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

def _post(path: str, payload: dict, timeout: int = 10) -> dict:
    try:
        r = requests.post(f"{API_BASE}{path}", json=payload, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        log.warning("POST %s failed: %s", path, exc)
        return {}


# ─── Heuristic CIC-IDS feature builder ────────────────────────────────────────

_SCANNER_UAS = {"sqlmap", "nikto", "nmap", "masscan", "dirbuster",
                "gobuster", "hydra", "zap", "burp", "metasploit"}

_SQLI_TOKENS  = {"union", "select", "insert", "drop", "sleep(", "' or ", "1=1",
                 "1%27", "or%20", "--", "%27"}
_XSS_TOKENS   = {"<script", "javascript:", "alert(", "onerror=", "onload="}
_PROBE_PATHS  = {"/admin", "/wp-admin", "/phpmyadmin", "/api/v1/auth",
                 "/.env", "/config", "/backup", "/shell", "/cgi-bin"}

def _features_from_http_entry(entry: dict) -> dict:
    """
    Build a minimal CIC-IDS 2017 style feature vector from the honeypot HTTP
    log entry so that XGBoost can classify the attack type.

    Profiles are approximated from published CIC-IDS 2017 statistics:
      - BruteForce  : repeated login attempts (POST /login)
      - PortScan    : path probing / scanner user-agents
      - DoS         : HTTP flood from same IP (high content-length)
      - Bot         : slow periodic check-in patterns
    """
    path       = (entry.get("path") or "/").lower()
    ua         = (entry.get("user_agent") or "").lower()
    method     = (entry.get("method") or "GET").upper()
    qs         = json.dumps(entry.get("query_params") or {}).lower()
    username   = (entry.get("username_attempt") or "").lower()
    cl         = int(entry.get("content_length") or 0)

    is_bruteforce = method == "POST" and "/login" in path
    is_scanner    = any(s in ua for s in _SCANNER_UAS)
    is_probe      = any(p in path for p in _PROBE_PATHS)
    is_sqli       = any(t in qs or t in path for t in _SQLI_TOKENS)
    is_xss        = any(t in qs or t in path for t in _XSS_TOKENS)

    # ── Base zeroed template (77 CIC-IDS features) ────────────────────────────
    f: dict = {k: 0.0 for k in [
        "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Fwd Packets Length Total", "Bwd Packets Length Total",
        "Fwd Packet Length Max", "Fwd Packet Length Min",
        "Fwd Packet Length Mean", "Fwd Packet Length Std",
        "Bwd Packet Length Max", "Bwd Packet Length Min",
        "Bwd Packet Length Mean", "Bwd Packet Length Std",
        "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
        "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
        "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total",
        "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
        "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
        "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
        "Packet Length Min", "Packet Length Max", "Packet Length Mean",
        "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
        "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
        "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio",
        "Avg Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
        "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
        "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
        "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
        "Subflow Bwd Bytes", "Init Fwd Win Bytes", "Init Bwd Win Bytes",
        "Fwd Act Data Packets", "Fwd Seg Size Min", "Active Mean", "Active Std",
        "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
    ]}
    f["Protocol"]      = 6.0   # TCP
    f["Fwd Seg Size Min"] = 20.0

    if is_bruteforce:
        # Repeated short TCP login sessions – CIC-IDS BruteForce signature
        f.update({
            "Flow Duration": 1_000_000.0, "Total Fwd Packets": 8.0,
            "Total Backward Packets": 6.0, "Fwd Packets Length Total": max(cl, 480.0),
            "Bwd Packets Length Total": 360.0, "Fwd Packet Length Mean": 60.0,
            "Fwd Packet Length Max": 120.0, "Fwd Packet Length Min": 40.0,
            "Bwd Packet Length Mean": 60.0, "Bwd Packet Length Max": 120.0,
            "Bwd Packet Length Min": 40.0, "Flow Bytes/s": 840.0,
            "Flow Packets/s": 14.0, "Fwd Packets/s": 8.0, "Bwd Packets/s": 6.0,
            "Flow IAT Mean": 71_428.0, "Flow IAT Std": 2_000.0,
            "Flow IAT Max": 150_000.0, "Flow IAT Min": 1_000.0,
            "Fwd IAT Total": 1_000_000.0, "Fwd IAT Mean": 125_000.0,
            "Bwd IAT Total": 1_000_000.0, "Bwd IAT Mean": 166_667.0,
            "FIN Flag Count": 1.0, "SYN Flag Count": 1.0,
            "ACK Flag Count": 1.0, "PSH Flag Count": 1.0,
            "Fwd Header Length": 320.0, "Bwd Header Length": 240.0,
            "Avg Packet Size": 60.0, "Avg Fwd Segment Size": 60.0,
            "Avg Bwd Segment Size": 60.0, "Down/Up Ratio": 0.75,
            "Subflow Fwd Packets": 8.0, "Subflow Fwd Bytes": 480.0,
            "Subflow Bwd Packets": 6.0, "Subflow Bwd Bytes": 360.0,
            "Init Fwd Win Bytes": 65535.0, "Init Bwd Win Bytes": 65535.0,
            "Fwd Act Data Packets": 6.0, "Active Mean": 1_000_000.0,
            "Active Max": 1_000_000.0, "Active Min": 1_000_000.0,
        })
    elif is_scanner or is_probe:
        # Port/path scan signature – sparse bidirectional flows
        f.update({
            "Flow Duration": 5_021_059.0, "Total Fwd Packets": 6.0,
            "Total Backward Packets": 5.0, "Fwd Packets Length Total": 703.0,
            "Bwd Packets Length Total": 1414.0, "Fwd Packet Length Max": 356.0,
            "Fwd Packet Length Mean": 117.17, "Fwd Packet Length Std": 181.54,
            "Bwd Packet Length Max": 1050.0, "Bwd Packet Length Mean": 282.8,
            "Bwd Packet Length Std": 456.92, "Flow Bytes/s": 421.62,
            "Flow Packets/s": 2.19, "Fwd Packets/s": 1.19, "Bwd Packets/s": 1.00,
            "Flow IAT Mean": 502_105.9, "Flow IAT Std": 1_568_379.1,
            "Flow IAT Max": 4_965_658.0, "Flow IAT Min": 19.0,
            "Fwd IAT Total": 55_401.0, "Fwd IAT Mean": 11_080.0,
            "Fwd IAT Std": 17_612.0, "Fwd IAT Max": 41_863.0, "Fwd IAT Min": 19.0,
            "Bwd IAT Total": 5_020_928.0, "Bwd IAT Mean": 1_255_232.0,
            "Bwd IAT Std": 2_499_939.5, "Bwd IAT Max": 5_005_133.0,
            "Bwd IAT Min": 1_053.0, "Fwd Header Length": 200.0,
            "Bwd Header Length": 168.0, "Packet Length Max": 1050.0,
            "Packet Length Mean": 176.42, "Packet Length Std": 317.47,
            "Packet Length Variance": 100_787.9, "PSH Flag Count": 1.0,
            "Avg Packet Size": 192.45, "Avg Fwd Segment Size": 117.17,
            "Avg Bwd Segment Size": 282.8, "Down/Up Ratio": 2.01,
            "Subflow Fwd Packets": 6.0, "Subflow Fwd Bytes": 703.0,
            "Subflow Bwd Packets": 5.0, "Subflow Bwd Bytes": 1414.0,
            "Init Fwd Win Bytes": 29_200.0, "Init Bwd Win Bytes": 243.0,
            "Fwd Act Data Packets": 2.0, "Fwd Seg Size Min": 32.0,
        })
    elif is_sqli or is_xss:
        # Injection attacks – treated similarly to infiltration
        f.update({
            "Flow Duration": 10_000_000.0, "Total Fwd Packets": 50.0,
            "Total Backward Packets": 45.0, "Fwd Packets Length Total": 10_000.0,
            "Bwd Packets Length Total": 9_000.0, "Fwd Packet Length Mean": 200.0,
            "Fwd Packet Length Max": 1_460.0, "Fwd Packet Length Min": 40.0,
            "Bwd Packet Length Mean": 200.0, "Bwd Packet Length Max": 1_460.0,
            "Flow Bytes/s": 1_900.0, "Flow Packets/s": 9.5,
            "Fwd Packets/s": 5.0, "Bwd Packets/s": 4.5,
            "Flow IAT Mean": 105_000.0, "Flow IAT Std": 80_000.0,
            "Flow IAT Max": 500_000.0, "Flow IAT Min": 2_000.0,
            "FIN Flag Count": 1.0, "SYN Flag Count": 1.0,
            "ACK Flag Count": 1.0, "PSH Flag Count": 20.0,
            "Fwd PSH Flags": 1.0, "Bwd PSH Flags": 1.0,
            "Fwd Header Length": 2_000.0, "Bwd Header Length": 1_800.0,
            "Avg Packet Size": 200.0, "Avg Fwd Segment Size": 200.0,
            "Init Fwd Win Bytes": 65535.0, "Init Bwd Win Bytes": 65535.0,
            "Fwd Act Data Packets": 40.0, "Active Mean": 10_000_000.0,
            "Active Max": 10_000_000.0, "Active Min": 10_000_000.0,
        })
    else:
        # Generic suspicious probe – BruteForce-lite
        f.update({
            "Flow Duration": 500_000.0, "Total Fwd Packets": 4.0,
            "Total Backward Packets": 2.0, "Fwd Packet Length Mean": 80.0,
            "Fwd Packet Length Max": 200.0, "Flow Bytes/s": 640.0,
            "Flow Packets/s": 12.0, "SYN Flag Count": 1.0, "ACK Flag Count": 1.0,
            "Init Fwd Win Bytes": 65535.0, "Init Bwd Win Bytes": 65535.0,
        })

    return f


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

        # Always fall back to HTTP heuristics when Zeek features are unavailable
        # (empty dict causes the API to skip the predictor entirely → "Unknown")
        if not features:
            features = _features_from_http_entry(entry)

        # 3. Trigger full pipeline: XGBoost + IPFS + Blockchain
        _post("/internal/session_complete", {
            "attacker_ip": ip,
            "session_id":  session_id,
            "features":    features,
            "confidence":  0.0,
        }, timeout=180)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        HoneypotController().run()
    except KeyboardInterrupt:
        log.info("Controller stopped by user.")
