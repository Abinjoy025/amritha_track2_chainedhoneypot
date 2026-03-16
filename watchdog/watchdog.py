#!/usr/bin/env python3
"""
watchdog/watchdog.py
────────────────────
Phase 1 – "The Watchdog"

Continuously tails the Nginx access log on the Original Server (Network A).
Detects:
  • 3+ consecutive 401 / 403 responses from the same IP  → brute-force
  • SQL-injection patterns in the request URI           → web attack
  • Nmap/scanner User-Agents                             → recon

On trigger → silently re-routes the attacker's HTTP traffic via iptables NAT:
  iptables -t nat -A PREROUTING -s <ATTACKER_IP> -p tcp --dport 80
           -j DNAT --to-destination 192.168.200.10:5000

The attacker's HTTP packets now land inside our Honeyport Flask app (app.py)
on Network B at 192.168.200.10:5000.  app.py logs every attempt to
honeypot_logs.json which the controller.py tails to trigger IPFS + blockchain.

Dependencies: requests (pip install requests)
Must be run as root (iptables requires it).
"""

import os
import re
import sys
import json
import time
import subprocess
import logging
import signal
from collections import defaultdict
from datetime import datetime, timedelta

# ─── Config ───────────────────────────────────────────────────────────────────
NGINX_ACCESS_LOG   = os.getenv("NGINX_ACCESS_LOG",
                               "/logs/nginx/access.log")
HONEYPOT_IP        = os.getenv("HONEYPOT_IP",   "192.168.200.10")
HONEYPOT_PORT      = int(os.getenv("HONEYPOT_PORT", "5000"))   # our Flask app
BRUTE_THRESHOLD    = int(os.getenv("BRUTE_THRESHOLD", "3"))   # fails before redirect
WINDOW_SECONDS     = int(os.getenv("WINDOW_SECONDS",  "60"))  # sliding window
API_NOTIFY_URL     = os.getenv("API_NOTIFY_URL",
                               "http://127.0.0.1:8000/internal/attacker_detected")
BLOCKLIST_FILE     = os.getenv("BLOCKLIST_FILE", "/data/blocklist.txt")
WATCHDOG_LOG       = os.getenv("WATCHDOG_LOG",   "/logs/watchdog.log")

os.makedirs(os.path.dirname(WATCHDOG_LOG), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [WATCHDOG] %(levelname)s  %(message)s",
    handlers=[
        logging.FileHandler(WATCHDOG_LOG),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger(__name__)

# ─── Detection patterns ───────────────────────────────────────────────────────
# SQL injection strings in the URI
SQLI_PATTERN = re.compile(
    r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bDROP\b|'--|%27|%3B|script>)",
    re.IGNORECASE
)
SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|hydra|medusa)",
    re.IGNORECASE
)
# Nginx combined-log regex
NGINX_LINE = re.compile(
    r'(?P<ip>\S+) - \S+ \[.*?\] "(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) \d+ ".*?" "(?P<ua>[^"]*)"'
)

# ─── State ────────────────────────────────────────────────────────────────────
# ip → list of fail timestamps
fail_log: dict[str, list[datetime]] = defaultdict(list)
# already-redirected IPs (no duplicate iptables rules)
redirected: set[str] = set()


def load_existing_blocklist() -> None:
    """Pre-populate redirected set from persisted blocklist."""
    if os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE) as f:
            for line in f:
                ip = line.strip()
                if ip:
                    redirected.add(ip)
        log.info("Loaded %d blocked IPs from blocklist", len(redirected))


def add_iptables_rule(attacker_ip: str) -> None:
    """
    Insert DNAT rule so attacker's TCP→80 HTTP packets are silently forwarded
    to our Honeyport Flask app on Network B (192.168.200.10:5000).
    """
    cmd = [
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-s", attacker_ip, "-p", "tcp", "--dport", "80",
        "-j", "DNAT", "--to-destination",
        f"{HONEYPOT_IP}:{HONEYPOT_PORT}"
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        log.info("iptables DNAT added: %s → %s:%d",
                 attacker_ip, HONEYPOT_IP, HONEYPOT_PORT)
    except subprocess.CalledProcessError as e:
        log.error("iptables failed: %s", e.stderr.decode())


def append_blocklist(ip: str) -> None:
    os.makedirs(os.path.dirname(BLOCKLIST_FILE), exist_ok=True)
    with open(BLOCKLIST_FILE, "a") as f:
        f.write(ip + "\n")


def notify_api(ip: str, trigger: str) -> None:
    """POST to the FastAPI backend so it can start OSINT enrichment immediately."""
    try:
        import requests
        payload = {
            "attacker_ip": ip,
            "trigger":     trigger,
            "timestamp":   datetime.utcnow().isoformat(),
        }
        requests.post(API_NOTIFY_URL, json=payload, timeout=3)
    except Exception as exc:
        log.warning("API notify failed: %s", exc)


def redirect_attacker(ip: str, trigger: str) -> None:
    """Full pipeline: iptables + blocklist + API notify."""
    if ip in redirected:
        return
    redirected.add(ip)

    log.warning("🎯 ATTACKER DETECTED  ip=%s  trigger=%s", ip, trigger)
    add_iptables_rule(ip)
    append_blocklist(ip)
    notify_api(ip, trigger)


def analyse_line(line: str) -> None:
    """Parse one Nginx log line and check for attack indicators."""
    m = NGINX_LINE.match(line)
    if not m:
        return

    ip     = m.group("ip")
    path   = m.group("path")
    status = int(m.group("status"))
    ua     = m.group("ua")

    # 1. SQL-injection / XSS in URL
    if SQLI_PATTERN.search(path):
        redirect_attacker(ip, f"sqli_in_url:{path[:80]}")
        return

    # 2. Known scanner User-Agent
    if SCANNER_UA.search(ua):
        redirect_attacker(ip, f"scanner_ua:{ua[:60]}")
        return

    # 3. Repeated 401 / 403 → brute-force
    if status in (401, 403):
        now = datetime.utcnow()
        fail_log[ip].append(now)
        # Prune entries older than the sliding window
        cutoff = now - timedelta(seconds=WINDOW_SECONDS)
        fail_log[ip] = [t for t in fail_log[ip] if t > cutoff]

        if len(fail_log[ip]) >= BRUTE_THRESHOLD:
            redirect_attacker(ip, f"brute_force:{len(fail_log[ip])}_fails_in_{WINDOW_SECONDS}s")
            fail_log[ip] = []   # reset counter


def tail_log(filepath: str) -> None:
    """Continuously tail the log file, even across log rotations."""
    log.info("Tailing %s", filepath)
    while not os.path.exists(filepath):
        log.info("Waiting for log file to appear...")
        time.sleep(2)

    with open(filepath, "r") as fh:
        fh.seek(0, 2)          # jump to end
        while True:
            line = fh.readline()
            if not line:
                # Check for rotation (inode change)
                try:
                    if os.stat(filepath).st_ino != os.fstat(fh.fileno()).st_ino:
                        log.info("Log rotated, re-opening.")
                        fh = open(filepath, "r")
                except FileNotFoundError:
                    pass
                time.sleep(0.2)
                continue
            analyse_line(line.rstrip())


def handle_signal(signum, frame):
    log.info("Watchdog shutting down (signal %d)", signum)
    sys.exit(0)


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("ERROR: watchdog.py must run as root (iptables requires it).")

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT,  handle_signal)

    load_existing_blocklist()
    tail_log(NGINX_ACCESS_LOG)
