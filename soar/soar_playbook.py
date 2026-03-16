#!/usr/bin/env python3
"""
soar/soar_playbook.py
──────────────────────
Phase 3  – Automated Security Orchestration, Automation & Response (SOAR)

Triggered when the XGBoost model classifies an event as high-severity
(confidence > 0.9).

Two automated actions:
  A. ADD the attacker's IP to the permanent blocklist on the Original Server
     (inserts an iptables DROP rule on the host).

  B. CYCLE the honeypot container:
       1. Kill the currently running honeyport_app container.
       2. Spin up a fresh replica from the same image.
     This ensures every new attacker starts in a clean environment.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from datetime import datetime

import docker

log = logging.getLogger(__name__)

BLOCKLIST_FILE      = os.getenv("BLOCKLIST_FILE",    "/data/blocklist.txt")
HONEYPOT_CONTAINER  = os.getenv("HONEYPOT_CONTAINER", "honeyport_app")
HONEYPOT_IMAGE      = os.getenv("HONEYPOT_IMAGE",     "docker_honeyport_app")  # built image name
HONEYPOT_NETWORK    = os.getenv("HONEYPOT_NETWORK",   "network_b")
HONEYPOT_IP         = os.getenv("HONEYPOT_IP",        "192.168.200.10")
HONEYPOT_LOG_DIR    = os.getenv("HONEYPOT_LOG_DIR",   "/logs/honeyport")
HONEYPOT_DL_DIR     = os.getenv("COWRIE_DL_DIR",      "/data/honeyport_dl")


# ─── Action A: Permanent blocklist ────────────────────────────────────────────

def block_ip_permanently(ip: str) -> bool:
    """
    Add an iptables DROP rule for the attacker's IP on the host
    and append it to the persisted blocklist file.
    """
    # iptables rule
    cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        log.info("ACTION A  iptables DROP added for %s", ip)
    except subprocess.CalledProcessError as exc:
        log.error("iptables failed: %s", exc.stderr.decode())
        return False

    # Persist to file so the watchdog re-applies on reboot
    os.makedirs(os.path.dirname(BLOCKLIST_FILE), exist_ok=True)
    with open(BLOCKLIST_FILE, "a") as f:
        f.write(f"{ip}\n")
    log.info("ACTION A  %s added to %s", ip, BLOCKLIST_FILE)
    return True


# ─── Action B: Recycle honeypot container ────────────────────────────────────

def recycle_honeypot() -> bool:
    """
    Kill the current Cowrie container and immediately start a fresh one.
    Uses the Docker Python SDK (docker package).
    """
    try:
        client = docker.from_env()
    except Exception as exc:
        log.error("Cannot connect to Docker daemon: %s", exc)
        return False

    # ── Step 1: Kill existing container ──────────────────────────────────────
    try:
        old = client.containers.get(HONEYPOT_CONTAINER)
        log.info("ACTION B  Stopping old honeypot container %s …", old.id[:12])
        old.stop(timeout=5)
        old.remove(force=True)
        log.info("ACTION B  Old container removed.")
    except docker.errors.NotFound:
        log.warning("ACTION B  Container %s not found — skipping removal.", HONEYPOT_CONTAINER)
    except Exception as exc:
        log.error("ACTION B  Failed to remove old container: %s", exc)

    time.sleep(1)   # brief pause so the network releases the fixed IP

    # ── Step 2: Start fresh replica ──────────────────────────────────────────
    try:
        new_container = client.containers.run(
            image          = HONEYPOT_IMAGE,
            name           = HONEYPOT_CONTAINER,
            detach         = True,
            restart_policy = {"Name": "unless-stopped"},
            network        = HONEYPOT_NETWORK,
            volumes        = {
                HONEYPOT_LOG_DIR: {"bind": "/logs", "mode": "rw"},
                HONEYPOT_DL_DIR:  {"bind": "/data/honeyport_dl", "mode": "rw"},
            },
            labels         = {"role": "honeypot"},
        )
        log.info("ACTION B  Fresh honeypot started: %s", new_container.id[:12])
        return True
    except Exception as exc:
        log.error("ACTION B  Could not start fresh honeypot: %s", exc)
        return False


# ─── Combined playbook trigger ────────────────────────────────────────────────

def run_playbook(ip: str, attack_type: str, confidence: float) -> dict:
    """
    Execute both SOAR actions and return a result summary.
    Called by the main controller when a critical event is detected.
    """
    log.warning(
        "🚨 SOAR PLAYBOOK  ip=%s  attack=%s  confidence=%.2f",
        ip, attack_type, confidence
    )
    result = {
        "timestamp":     datetime.utcnow().isoformat(),
        "ip":            ip,
        "attack_type":   attack_type,
        "confidence":    confidence,
        "action_a_ok":   False,   # blocked IP
        "action_b_ok":   False,   # recycled container
    }

    result["action_a_ok"] = block_ip_permanently(ip)
    result["action_b_ok"] = recycle_honeypot()

    log.info(
        "SOAR COMPLETE  block=%s  recycle=%s",
        result["action_a_ok"], result["action_b_ok"]
    )
    return result
