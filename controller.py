#!/usr/bin/env python3
"""
controller.py  (v2)
────────────────────
Honeyport Main Orchestration Controller

Runs the full Phase 2–4 pipeline:

  1. Tails honeypot_logs.json (written by app.py) → detects attack events
  2. On each attack event    →  fires OSINT enrichment (async HTTP to FastAPI)
  3. Parallel thread         →  pulls ZeekConnRecord objects from ZeekCapture,
                                 feeds them through CICFlowExtractor + XGBoost
                                 (continuous inference loop)
  4. Per attack event        →  XGBoost classification + SHAP,
                                 IPFS bundle upload,  blockchain record,
                                 SOAR playbook if critical
  5. Publishes all events    →  via POST to the FastAPI /internal/* endpoints
                                 (which then broadcast over WebSocket to React)

Run as:
  python3 controller.py

Requires the FastAPI backend (api/main.py) to be running separately.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
import threading
import requests
from datetime import datetime
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CTRL] %(levelname)s  %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join("logs", "controller.log"), mode="a"),
    ],
)
log = logging.getLogger("honeyport.controller")

API_BASE        = os.getenv("API_BASE_URL",      "http://127.0.0.1:8000")
HONEYPOT_LOG    = os.getenv("HONEYPOT_LOG",      "honeypot_logs.json")
ZEEK_LOG_DIR    = os.getenv("ZEEK_LOG_DIR",      "/logs/zeek")
SOAR_THRESHOLD  = float(os.getenv("SOAR_CONF_THRESHOLD", "0.90"))

os.makedirs("logs", exist_ok=True)

# ── Lazy imports (only if available) ─────────────────────────────────────────
try:
    from pipeline.traffic_capture   import ZeekCapture
    from pipeline.feature_extractor import CICFlowExtractor
    from ai_module.predictor         import AttackPredictor
    PIPELINE_AVAILABLE = True
except ImportError as e:
    log.warning("Pipeline import failed (%s) – running in OSINT-only mode.", e)
    PIPELINE_AVAILABLE = False


# ─── HTTP helpers ─────────────────────────────────────────────────────────────

def _post(path: str, payload: dict) -> dict:
    try:
        r = requests.post(f"{API_BASE}{path}", json=payload, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        log.warning("POST %s failed: %s", path, exc)
        return {}


# ─── Honeyport log tailer ─────────────────────────────────────────────────────

def _tail_honeypot_log(filepath: str):
    """Generator yielding parsed Honeyport JSON lines (from app.py) as they appear."""
    while not os.path.exists(filepath):
        log.info("Waiting for honeypot log at %s …", filepath)
        time.sleep(3)
    log.info("Tailing honeypot log: %s", filepath)
    with open(filepath, "r") as fh:
        fh.seek(0, 2)
        while True:
            line = fh.readline()
            if not line:
                try:
                    if os.stat(filepath).st_ino != os.fstat(fh.fileno()).st_ino:
                        fh = open(filepath, "r")
                except FileNotFoundError:
                    pass
                time.sleep(0.1)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                pass


# ─── Zeek inference loop ──────────────────────────────────────────────────────

class ZeekInferenceLoop(threading.Thread):
    """
    Background thread:  ZeekCapture → CICFlowExtractor → XGBoost → log/broadcast
    Runs continuously, independent of specific Cowrie sessions.
    """

    def __init__(self):
        super().__init__(daemon=True, name="ZeekInference")
        self.capture  = ZeekCapture(log_dir=ZEEK_LOG_DIR)
        self.extractor = CICFlowExtractor()
        self.predictor = AttackPredictor()
        # Per-IP: keep the latest features for when a session ends
        self._latest_features: dict[str, dict] = {}

    def run(self):
        self.capture.start()
        log.info("Zeek inference loop started.")
        while True:
            rec = self.capture.get_record(timeout=1.0)
            if rec is None:
                continue
            try:
                features   = self.extractor.extract(rec)
                prediction = self.predictor.predict(features)
                # Cache latest features per source IP
                self._latest_features[rec.src_ip] = features
                if prediction["is_attack"]:
                    log.info(
                        "Flow  %s→%s:%d  %s  conf=%.2f",
                        rec.src_ip, rec.dst_ip, rec.dst_port,
                        prediction["attack_type"], prediction["confidence"]
                    )
            except Exception as exc:
                log.debug("Inference error on flow: %s", exc)

    def get_features_for_ip(self, ip: str) -> dict:
        return self._latest_features.get(ip, {})


# ─── Controller ───────────────────────────────────────────────────────────────

class HoneypotController:

    def __init__(self):
        log.info("=" * 60)
        log.info("  Honeyport v2 Controller starting …")
        log.info("=" * 60)

        self._zeek_loop: ZeekInferenceLoop | None = None

        if PIPELINE_AVAILABLE:
            self._zeek_loop = ZeekInferenceLoop()
            self._zeek_loop.start()
            log.info("Zeek inference loop launched.")
        else:
            log.warning("Zeek/XGBoost pipeline not available – basic mode.")

    # ── Main loop ─────────────────────────────────────────────────────────

    def run(self):
        log.info("Watching honeypot log: %s", HONEYPOT_LOG)

        for entry in _tail_honeypot_log(HONEYPOT_LOG):
            # Our app.py writes one JSON object per attack attempt.
            # Each entry has: attacker_ip, timestamp, username_attempt, path, etc.
            ip = entry.get("attacker_ip", "")
            if not ip:
                continue

            # Generate a pseudo session-id from IP + timestamp for tracking
            session_id = hashlib.md5(
                f"{ip}{entry.get('timestamp','')}".encode()
            ).hexdigest()[:12]

            self._on_attack_event(entry, session_id)

    # ── Event handler ──────────────────────────────────────────────────────

    def _on_attack_event(self, entry: dict, session_id: str):
        ip = entry.get("attacker_ip", "")
        log.info(
            "ATTACK  ip=%s  path=%s  user=%r",
            ip, entry.get("path", ""), entry.get("username_attempt", "")
        )

        # 1. Immediately notify API for OSINT enrichment
        _post("/internal/attacker_detected", {
            "attacker_ip": ip,
            "trigger":     f"web_attack:{entry.get('path','/')}",
            "timestamp":   entry.get("timestamp", datetime.utcnow().isoformat()),
        })

        # 2. Get latest Zeek features for this IP (if available)
        features = {}
        if self._zeek_loop:
            features = self._zeek_loop.get_features_for_ip(ip)

        # 3. Trigger full pipeline: XGBoost + IPFS + Blockchain
        _post("/internal/session_complete", {
            "attacker_ip": ip,
            "session_id":  session_id,
            "features":    features,
            "confidence":  0.0,
        })


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        HoneypotController().run()
    except KeyboardInterrupt:
        log.info("Controller stopped by user.")
