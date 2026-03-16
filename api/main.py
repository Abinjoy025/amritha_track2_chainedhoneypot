#!/usr/bin/env python3
"""
api/main.py
────────────
Phase 5  – FastAPI Backend (Bridge Layer)

Provides:
  REST endpoints:
    GET  /api/attacks/latest          – last N attack records from mock/blockchain
    GET  /api/attacks/{id}            – single record
    GET  /api/stats                   – aggregated statistics
    POST /internal/attacker_detected  – watchdog notifies us of a new IP
    GET  /api/ipfs/{cid}              – IPFS gateway redirect

  WebSocket:
    WS   /ws/live                     – push new events to React dashboard

  Also mounts the React build at "/" (after `npm run build` in frontend/).

Environment variables (via .env):
  ABUSEIPDB_API_KEY, SHODAN_API_KEY, PINATA_JWT,
  WEB3_PROVIDER_URL, HONEYPORT_CONTRACT_ADDRESS, ETH_PRIVATE_KEY
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from typing import Any

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

# Add project root to path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.osint_enricher      import enrich as osint_enrich
from soar.soar_playbook       import run_playbook
from blockchain.blockchain_manager import BlockchainManager
from blockchain.ipfs_manager       import IPFSManager
from ai_module.predictor           import AttackPredictor

log = logging.getLogger("honeyport.api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [API] %(levelname)s %(message)s")

# ── Singletons ────────────────────────────────────────────────────────────────
blockchain = BlockchainManager()
ipfs       = IPFSManager()
predictor  = AttackPredictor()

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="Honeyport API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── WebSocket manager ─────────────────────────────────────────────────────────
class WSManager:
    def __init__(self):
        self._clients: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._clients.append(ws)
        log.info("WS client connected  total=%d", len(self._clients))

    def disconnect(self, ws: WebSocket):
        if ws in self._clients:
            self._clients.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self._clients:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


ws_manager = WSManager()


# ── Pydantic models ───────────────────────────────────────────────────────────
class AttackerDetectedPayload(BaseModel):
    attacker_ip: str
    trigger:     str
    timestamp:   str | None = None


# ── REST Endpoints ────────────────────────────────────────────────────────────

@app.get("/api/attacks/latest")
async def get_latest_attacks(n: int = 20):
    """Return the N most recent attack records."""
    records = blockchain.get_latest_records(n)
    return {"records": records, "count": len(records)}


@app.get("/api/attacks/{record_id}")
async def get_attack(record_id: int):
    """Return a single attack record by ID."""
    record = blockchain.get_record(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return record


@app.get("/api/stats")
async def get_stats():
    """Aggregated statistics for the dashboard header."""
    records = blockchain.get_latest_records(500)
    total   = len(records)
    by_type: dict[str, int] = {}
    for r in records:
        t = r.get("attack_type", "Unknown")
        by_type[t] = by_type.get(t, 0) + 1

    avg_score = (
        sum(r.get("osint_score", 0) for r in records) / total
        if total else 0
    )
    return {
        "total_attacks":    total,
        "by_attack_type":   by_type,
        "avg_osint_score":  round(avg_score, 1),
        "timestamp":        datetime.utcnow().isoformat(),
    }


@app.get("/api/ipfs/{cid}")
async def ipfs_redirect(cid: str):
    """Redirect to the public IPFS gateway for a given CID."""
    url = ipfs.get_gateway_url(cid)
    return RedirectResponse(url=url)


# ── Internal hook called by the watchdog ─────────────────────────────────────

@app.post("/internal/attacker_detected")
async def attacker_detected(payload: AttackerDetectedPayload):
    """
    Called by watchdog.py the moment an attacker is redirected to the honeypot.
    Pipeline:
      1. OSINT enrichment  (AbuseIPDB + Shodan)
      2. Broadcast live event to all WebSocket clients
    Full analysis (XGBoost + IPFS + blockchain) happens after session ends
    via /internal/session_complete.
    """
    ip = payload.attacker_ip

    # OSINT (run in thread to avoid blocking the event loop)
    osint = await asyncio.get_event_loop().run_in_executor(
        None, osint_enrich, ip
    )

    event = {
        "type":        "new_attacker",
        "ip":          ip,
        "trigger":     payload.trigger,
        "osint_score": osint.threat_score,
        "osint_label": osint.label,
        "country":     osint.country_code,
        "isp":         osint.isp,
        "shodan_tags": osint.shodan_tags,
        "open_ports":  osint.open_ports,
        "timestamp":   payload.timestamp or datetime.utcnow().isoformat(),
    }

    await ws_manager.broadcast(event)
    log.info("Notified %d WS clients of new attacker %s", len(ws_manager._clients), ip)
    return {"status": "ok", "osint": osint.to_dict()}


class SessionCompletePayload(BaseModel):
    attacker_ip: str
    session_id:  str
    features:    dict  = {}    # CIC-IDS feature vector from feature_extractor
    confidence:  float = 0.0


@app.post("/internal/session_complete")
async def session_complete(payload: SessionCompletePayload):
    """
    Called by the controller when a Cowrie session ends.
    Pipeline:
      1. XGBoost prediction + SHAP  (if features provided)
      2. IPFS upload of session bundle
      3. Blockchain record storage
      4. SOAR playbook  if confidence > 0.9 + critical attack type
      5. Broadcast final result to WS clients
    """
    ip         = payload.attacker_ip
    session_id = payload.session_id

    # 1. AI prediction
    prediction = {"attack_type": "Unknown", "confidence": 0.0, "is_attack": False, "shap": {}}
    if payload.features:
        prediction = await asyncio.get_event_loop().run_in_executor(
            None, predictor.predict, payload.features
        )

    # 2. IPFS upload
    cid = await asyncio.get_event_loop().run_in_executor(
        None, ipfs.upload_session, ip, session_id
    )

    # 3. OSINT
    osint = await asyncio.get_event_loop().run_in_executor(None, osint_enrich, ip)

    # 4. Blockchain
    bc_result = await asyncio.get_event_loop().run_in_executor(
        None,
        blockchain.store_attack_record,
        ip,
        osint.threat_score,
        prediction["attack_type"],
        cid,
    )

    # 5. SOAR – trigger if high confidence critical attack
    soar_result = None
    critical_types = {"BruteForce", "DDoS", "Bot", "Infiltration", "Heartbleed"}
    if (prediction["is_attack"]
            and prediction["confidence"] >= 0.90
            and prediction["attack_type"] in critical_types):
        soar_result = await asyncio.get_event_loop().run_in_executor(
            None,
            run_playbook,
            ip,
            prediction["attack_type"],
            prediction["confidence"],
        )

    # 6. Broadcast final event
    final_event = {
        "type":         "session_complete",
        "ip":           ip,
        "session_id":   session_id,
        "attack_type":  prediction["attack_type"],
        "confidence":   prediction["confidence"],
        "is_attack":    prediction["is_attack"],
        "shap":         prediction.get("shap", {}),
        "osint_score":  osint.threat_score,
        "osint_label":  osint.label,
        "ipfs_cid":     cid,
        "ipfs_url":     ipfs.get_gateway_url(cid),
        "tx_hash":      bc_result.get("tx_hash", bc_result.get("mock_id", "")),
        "soar_fired":   soar_result is not None,
        "timestamp":    datetime.utcnow().isoformat(),
    }
    await ws_manager.broadcast(final_event)

    return final_event


# ── WebSocket live feed ───────────────────────────────────────────────────────

@app.websocket("/ws/live")
async def live_feed(ws: WebSocket):
    """
    WebSocket endpoint.  React dashboard connects here to receive
    real-time attack events as JSON messages.
    """
    await ws_manager.connect(ws)
    try:
        while True:
            # Keep connection alive; server is push-only
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
        log.info("WS client disconnected  remaining=%d", len(ws_manager._clients))


# ── Serve React build (if it exists) ─────────────────────────────────────────
FRONTEND_BUILD = os.path.join(ROOT, "frontend", "honeyport-ui", "dist")
if os.path.isdir(FRONTEND_BUILD):
    app.mount("/", StaticFiles(directory=FRONTEND_BUILD, html=True), name="frontend")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )
