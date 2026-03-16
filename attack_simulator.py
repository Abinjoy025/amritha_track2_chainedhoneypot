#!/usr/bin/env python3
"""
attack_simulator.py
────────────────────
Two-phase attack simulation for the Honeyport project:

  Phase A – HTTP attacks against the live Flask honeypot (port 5000)
            Brute-force logins, scanner user-agents, path probes, SQLi payloads

  Phase B – XGBoost model evaluation using CIC-IDS 2017 traffic profiles
            Constructs realistic network-flow feature vectors for every attack
            class the model was trained on, then runs them through the loaded
            XGBoost classifier and prints detection results + SHAP explanation.
"""

import sys
import time
import json
import requests

HONEYPOT_URL = "http://localhost:5000"

# ─── ANSI colours ────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner(msg, colour=CYAN):
    width = 72
    print(f"\n{colour}{BOLD}{'─'*width}{RESET}")
    print(f"{colour}{BOLD}  {msg}{RESET}")
    print(f"{colour}{BOLD}{'─'*width}{RESET}")

def result_line(label, value, ok=True):
    icon  = f"{GREEN}✔{RESET}" if ok else f"{RED}✘{RESET}"
    print(f"  {icon}  {BOLD}{label:<28}{RESET} {value}")


# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE A  –  HTTP attack simulation
# ═══════════════════════════════════════════════════════════════════════════════

def phase_a():
    banner("PHASE A  –  Live HTTP Attacks → Flask Honeypot (port 5000)")

    # ── A1: Brute-force login attempts ─────────────────────────────────────
    print(f"\n{YELLOW}[A1] Brute-force login attempts{RESET}")
    credentials = [
        ("admin",  "admin"),
        ("admin",  "password"),
        ("root",   "toor"),
        ("admin",  "admin123"),
        ("user",   "password123"),
        ("admin",  "letmein"),
        ("test",   "test"),
        ("admin",  "' OR '1'='1"),          # SQLi inside login
    ]
    for username, password in credentials:
        try:
            r = requests.post(
                f"{HONEYPOT_URL}/login",
                data={"username": username, "password": password},
                timeout=5,
            )
            result_line(f"{username} / {password}", f"HTTP {r.status_code}")
        except requests.exceptions.ConnectionError:
            print(f"  {RED}[!] Honeypot unreachable at {HONEYPOT_URL}{RESET}")
            return
        time.sleep(0.1)

    # ── A2: Scanner user-agents ────────────────────────────────────────────
    print(f"\n{YELLOW}[A2] Scanner user-agent probes (/ endpoint){RESET}")
    scanners = [
        ("sqlmap/1.7",          "sqlmap automatic SQL injection"),
        ("Nikto/2.1.6",         "Nikto web-server vulnerability scanner"),
        ("Nmap Scripting Engine","Nmap NSE probe"),
        ("masscan/1.3.2",       "masscan port scanner"),
        ("dirbuster/1.0",       "DirBuster directory enumeration"),
        ("gobuster/3.5",        "GoBuster directory/DNS brute-forcer"),
        ("Hydra/9.4",           "Hydra login cracker"),
    ]
    for ua, description in scanners:
        try:
            r = requests.get(
                f"{HONEYPOT_URL}/",
                headers={"User-Agent": ua},
                timeout=5,
            )
            result_line(description, f"HTTP {r.status_code}")
        except Exception:
            pass
        time.sleep(0.05)

    # ── A3: High-value path probes ─────────────────────────────────────────
    print(f"\n{YELLOW}[A3] High-value honeypot endpoint probes{RESET}")
    paths = [
        ("/admin",        "Admin panel probe"),
        ("/wp-admin",     "WordPress admin probe"),
        ("/phpmyadmin",   "phpMyAdmin probe"),
        ("/api/v1/auth",  "API auth endpoint probe"),
    ]
    for path, description in paths:
        try:
            r = requests.get(f"{HONEYPOT_URL}{path}", timeout=5)
            result_line(description, f"HTTP {r.status_code} → {path}")
        except Exception:
            pass
        time.sleep(0.05)

    # ── A4: SQL injection / XSS payloads via query string ─────────────────
    print(f"\n{YELLOW}[A4] SQL injection & XSS payloads in query string{RESET}")
    payloads = [
        ("?id=1' UNION SELECT 1,2,3--",         "UNION-based SQLi"),
        ("?search=<script>alert(1)</script>",   "Reflected XSS"),
        ("?user=admin'--",                       "Comment-based SQLi"),
        ("?q=1%27%20OR%20%271%27%3D%271",       "URL-encoded SQLi"),
    ]
    for qs, description in payloads:
        try:
            r = requests.get(f"{HONEYPOT_URL}/{qs}", timeout=5)
            result_line(description, f"HTTP {r.status_code}")
        except Exception:
            pass
        time.sleep(0.05)

    # ── Show how many events were logged ──────────────────────────────────
    try:
        with open("logs/honeypot_logs.json") as fh:
            count = sum(1 for line in fh if line.strip())
        print(f"\n  {GREEN}Total events logged to honeypot_logs.json: {BOLD}{count}{RESET}")
    except FileNotFoundError:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE B  –  XGBoost model evaluation with CIC-IDS traffic profiles
# ═══════════════════════════════════════════════════════════════════════════════

# ── CIC-IDS 2017 representative feature profiles ──────────────────────────────
# Each dict maps every feature_name the model expects → a realistic float value.
# Values are based on published CIC-IDS 2017 dataset statistics.
# Protocol: 6=TCP, 17=UDP, 0=other

def _make_base():
    """Return a zeroed feature dict for all 77 features."""
    return {
        "Protocol": 6.0,
        "Flow Duration": 0.0,
        "Total Fwd Packets": 0.0,
        "Total Backward Packets": 0.0,
        "Fwd Packets Length Total": 0.0,
        "Bwd Packets Length Total": 0.0,
        "Fwd Packet Length Max": 0.0,
        "Fwd Packet Length Min": 0.0,
        "Fwd Packet Length Mean": 0.0,
        "Fwd Packet Length Std": 0.0,
        "Bwd Packet Length Max": 0.0,
        "Bwd Packet Length Min": 0.0,
        "Bwd Packet Length Mean": 0.0,
        "Bwd Packet Length Std": 0.0,
        "Flow Bytes/s": 0.0,
        "Flow Packets/s": 0.0,
        "Flow IAT Mean": 0.0,
        "Flow IAT Std": 0.0,
        "Flow IAT Max": 0.0,
        "Flow IAT Min": 0.0,
        "Fwd IAT Total": 0.0,
        "Fwd IAT Mean": 0.0,
        "Fwd IAT Std": 0.0,
        "Fwd IAT Max": 0.0,
        "Fwd IAT Min": 0.0,
        "Bwd IAT Total": 0.0,
        "Bwd IAT Mean": 0.0,
        "Bwd IAT Std": 0.0,
        "Bwd IAT Max": 0.0,
        "Bwd IAT Min": 0.0,
        "Fwd PSH Flags": 0.0,
        "Bwd PSH Flags": 0.0,
        "Fwd URG Flags": 0.0,
        "Bwd URG Flags": 0.0,
        "Fwd Header Length": 0.0,
        "Bwd Header Length": 0.0,
        "Fwd Packets/s": 0.0,
        "Bwd Packets/s": 0.0,
        "Packet Length Min": 0.0,
        "Packet Length Max": 0.0,
        "Packet Length Mean": 0.0,
        "Packet Length Std": 0.0,
        "Packet Length Variance": 0.0,
        "FIN Flag Count": 0.0,
        "SYN Flag Count": 0.0,
        "RST Flag Count": 0.0,
        "PSH Flag Count": 0.0,
        "ACK Flag Count": 0.0,
        "URG Flag Count": 0.0,
        "CWE Flag Count": 0.0,
        "ECE Flag Count": 0.0,
        "Down/Up Ratio": 0.0,
        "Avg Packet Size": 0.0,
        "Avg Fwd Segment Size": 0.0,
        "Avg Bwd Segment Size": 0.0,
        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,
        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,
        "Subflow Fwd Packets": 0.0,
        "Subflow Fwd Bytes": 0.0,
        "Subflow Bwd Packets": 0.0,
        "Subflow Bwd Bytes": 0.0,
        "Init Fwd Win Bytes": 0.0,
        "Init Bwd Win Bytes": 0.0,
        "Fwd Act Data Packets": 0.0,
        "Fwd Seg Size Min": 20.0,
        "Active Mean": 0.0,
        "Active Std": 0.0,
        "Active Max": 0.0,
        "Active Min": 0.0,
        "Idle Mean": 0.0,
        "Idle Std": 0.0,
        "Idle Max": 0.0,
        "Idle Min": 0.0,
    }

ATTACK_PROFILES = {

    # ── PortScan ─────────────────────────────────────────────────────────────
    # Real CIC-IDS 2017 PortScan values extracted from dataset (97% confidence).
    # Characteristic: moderate duration, small Init Bwd Win Bytes (243),
    # low Fwd Packet Length Mean, sparse bidirectional traffic.
    "PortScan": {
        **_make_base(),
        "Protocol": 6.0,
        "Flow Duration": 5_021_059.0,      # ~5 s
        "Total Fwd Packets": 6.0,
        "Total Backward Packets": 5.0,
        "Fwd Packets Length Total": 703.0,
        "Bwd Packets Length Total": 1414.0,
        "Fwd Packet Length Max": 356.0,
        "Fwd Packet Length Min": 0.0,
        "Fwd Packet Length Mean": 117.17,
        "Fwd Packet Length Std": 181.54,
        "Bwd Packet Length Max": 1050.0,
        "Bwd Packet Length Min": 0.0,
        "Bwd Packet Length Mean": 282.8,
        "Bwd Packet Length Std": 456.92,
        "Flow Bytes/s": 421.62,
        "Flow Packets/s": 2.19,
        "Fwd Packets/s": 1.19,
        "Bwd Packets/s": 1.00,
        "Flow IAT Mean": 502_105.9,
        "Flow IAT Std": 1_568_379.1,
        "Flow IAT Max": 4_965_658.0,
        "Flow IAT Min": 19.0,
        "Fwd IAT Total": 55_401.0,
        "Fwd IAT Mean": 11_080.0,
        "Fwd IAT Std": 17_612.0,
        "Fwd IAT Max": 41_863.0,
        "Fwd IAT Min": 19.0,
        "Bwd IAT Total": 5_020_928.0,
        "Bwd IAT Mean": 1_255_232.0,
        "Bwd IAT Std": 2_499_939.5,
        "Bwd IAT Max": 5_005_133.0,
        "Bwd IAT Min": 1_053.0,
        "Fwd Header Length": 200.0,
        "Bwd Header Length": 168.0,
        "Packet Length Min": 0.0,
        "Packet Length Max": 1050.0,
        "Packet Length Mean": 176.42,
        "Packet Length Std": 317.47,
        "Packet Length Variance": 100_787.9,
        "PSH Flag Count": 1.0,
        "Avg Packet Size": 192.45,
        "Avg Fwd Segment Size": 117.17,
        "Avg Bwd Segment Size": 282.8,
        "Down/Up Ratio": 2.01,
        "Subflow Fwd Packets": 6.0,
        "Subflow Fwd Bytes": 703.0,
        "Subflow Bwd Packets": 5.0,
        "Subflow Bwd Bytes": 1414.0,
        "Init Fwd Win Bytes": 29_200.0,
        "Init Bwd Win Bytes": 243.0,       # key discriminator vs BruteForce
        "Fwd Act Data Packets": 2.0,
        "Fwd Seg Size Min": 32.0,
    },

    # ── DDoS ─────────────────────────────────────────────────────────────────
    # CIC-IDS LOIT/Hulk DDoS: many SYNs, huge packet rate, minimal responses.
    "DDoS": {
        **_make_base(),
        "Protocol": 17.0,                  # UDP flood
        "Flow Duration": 60_000_000.0,     # 60 s
        "Total Fwd Packets": 100_000.0,
        "Total Backward Packets": 0.0,
        "Fwd Packets Length Total": 6_000_000.0,
        "Fwd Packet Length Mean": 60.0,
        "Fwd Packet Length Max": 64.0,
        "Fwd Packet Length Min": 56.0,
        "Flow Bytes/s": 100_000.0,
        "Flow Packets/s": 1_666.0,
        "Fwd Packets/s": 1_666.0,
        "Flow IAT Mean": 600.0,
        "Flow IAT Std": 50.0,
        "Flow IAT Max": 1_200.0,
        "Flow IAT Min": 10.0,
        "Fwd IAT Total": 60_000_000.0,
        "Fwd IAT Mean": 600.0,
        "SYN Flag Count": 100_000.0,
        "ACK Flag Count": 0.0,
        "Fwd Header Length": 2_800_000.0,
        "Avg Packet Size": 60.0,
        "Avg Fwd Segment Size": 60.0,
        "Subflow Fwd Packets": 100_000.0,
        "Subflow Fwd Bytes": 6_000_000.0,
        "Init Fwd Win Bytes": 8192.0,
        "Fwd Act Data Packets": 100_000.0,
        "Fwd Seg Size Min": 20.0,
        "Active Mean": 60_000_000.0,
        "Active Max": 60_000_000.0,
        "Active Min": 60_000_000.0,
    },

    # ── BruteForce (SSH/FTP-Patator) ─────────────────────────────────────────
    # CIC-IDS: repeated short TCP sessions to port 22/21, small packets, automation.
    "BruteForce": {
        **_make_base(),
        "Protocol": 6.0,
        "Flow Duration": 1_000_000.0,      # 1 s per attempt
        "Total Fwd Packets": 8.0,
        "Total Backward Packets": 6.0,
        "Fwd Packets Length Total": 480.0,
        "Bwd Packets Length Total": 360.0,
        "Fwd Packet Length Mean": 60.0,
        "Fwd Packet Length Max": 120.0,
        "Fwd Packet Length Min": 40.0,
        "Bwd Packet Length Mean": 60.0,
        "Bwd Packet Length Max": 120.0,
        "Bwd Packet Length Min": 40.0,
        "Flow Bytes/s": 840.0,
        "Flow Packets/s": 14.0,
        "Fwd Packets/s": 8.0,
        "Bwd Packets/s": 6.0,
        "Flow IAT Mean": 71_428.0,         # steady ~71 ms – automated
        "Flow IAT Std": 2_000.0,
        "Flow IAT Max": 150_000.0,
        "Flow IAT Min": 1_000.0,
        "Fwd IAT Total": 1_000_000.0,
        "Fwd IAT Mean": 125_000.0,
        "Bwd IAT Total": 1_000_000.0,
        "Bwd IAT Mean": 166_667.0,
        "FIN Flag Count": 1.0,
        "SYN Flag Count": 1.0,
        "ACK Flag Count": 1.0,
        "PSH Flag Count": 1.0,
        "Fwd Header Length": 320.0,
        "Bwd Header Length": 240.0,
        "Avg Packet Size": 60.0,
        "Avg Fwd Segment Size": 60.0,
        "Avg Bwd Segment Size": 60.0,
        "Down/Up Ratio": 0.75,
        "Subflow Fwd Packets": 8.0,
        "Subflow Fwd Bytes": 480.0,
        "Subflow Bwd Packets": 6.0,
        "Subflow Bwd Bytes": 360.0,
        "Init Fwd Win Bytes": 65535.0,
        "Init Bwd Win Bytes": 65535.0,
        "Fwd Act Data Packets": 6.0,
        "Fwd Seg Size Min": 20.0,
        "Active Mean": 1_000_000.0,
        "Active Max": 1_000_000.0,
        "Active Min": 1_000_000.0,
    },

    # ── DoS (Hulk / GoldenEye) ───────────────────────────────────────────────
    # CIC-IDS: HTTP flood, very high byte rate, long connections, many PSH/ACK.
    "DoS": {
        **_make_base(),
        "Protocol": 6.0,
        "Flow Duration": 120_000_000.0,    # 2 min
        "Total Fwd Packets": 5_000.0,
        "Total Backward Packets": 4_800.0,
        "Fwd Packets Length Total": 5_000_000.0,
        "Bwd Packets Length Total": 4_800_000.0,
        "Fwd Packet Length Mean": 1_000.0,
        "Fwd Packet Length Max": 1_460.0,
        "Fwd Packet Length Min": 40.0,
        "Bwd Packet Length Mean": 1_000.0,
        "Bwd Packet Length Max": 1_460.0,
        "Bwd Packet Length Min": 40.0,
        "Flow Bytes/s": 82_500.0,
        "Flow Packets/s": 82.0,
        "Fwd Packets/s": 41.7,
        "Bwd Packets/s": 40.0,
        "Flow IAT Mean": 12_195.0,
        "Flow IAT Std": 5_000.0,
        "Flow IAT Max": 50_000.0,
        "Flow IAT Min": 100.0,
        "Fwd IAT Total": 120_000_000.0,
        "Fwd IAT Mean": 24_000.0,
        "Bwd IAT Total": 120_000_000.0,
        "Bwd IAT Mean": 25_000.0,
        "FIN Flag Count": 0.0,
        "SYN Flag Count": 1.0,
        "PSH Flag Count": 4_800.0,
        "ACK Flag Count": 9_800.0,
        "Fwd PSH Flags": 1.0,
        "Bwd PSH Flags": 1.0,
        "Fwd Header Length": 200_000.0,
        "Bwd Header Length": 192_000.0,
        "Packet Length Mean": 1_000.0,
        "Packet Length Std": 300.0,
        "Packet Length Variance": 90_000.0,
        "Avg Packet Size": 1_000.0,
        "Avg Fwd Segment Size": 1_000.0,
        "Avg Bwd Segment Size": 1_000.0,
        "Down/Up Ratio": 0.96,
        "Subflow Fwd Packets": 5_000.0,
        "Subflow Fwd Bytes": 5_000_000.0,
        "Subflow Bwd Packets": 4_800.0,
        "Subflow Bwd Bytes": 4_800_000.0,
        "Init Fwd Win Bytes": 65535.0,
        "Init Bwd Win Bytes": 65535.0,
        "Fwd Act Data Packets": 4_800.0,
        "Fwd Seg Size Min": 20.0,
        "Active Mean": 120_000_000.0,
        "Active Max": 120_000_000.0,
        "Active Min": 120_000_000.0,
    },

    # ── Bot ───────────────────────────────────────────────────────────────────
    # CIC-IDS: Periodic low-bandwidth C2 check-ins, varied ports, steady IAT.
    "Bot": {
        **_make_base(),
        "Protocol": 6.0,
        "Flow Duration": 30_000_000.0,     # 30 s check-in interval
        "Total Fwd Packets": 4.0,
        "Total Backward Packets": 4.0,
        "Fwd Packets Length Total": 400.0,
        "Bwd Packets Length Total": 800.0,
        "Fwd Packet Length Mean": 100.0,
        "Fwd Packet Length Max": 200.0,
        "Fwd Packet Length Min": 80.0,
        "Bwd Packet Length Mean": 200.0,
        "Bwd Packet Length Max": 400.0,
        "Bwd Packet Length Min": 100.0,
        "Flow Bytes/s": 40.0,
        "Flow Packets/s": 0.27,
        "Fwd Packets/s": 0.13,
        "Bwd Packets/s": 0.13,
        "Flow IAT Mean": 3_750_000.0,      # 3.75 s – very slow, periodic
        "Flow IAT Std": 500_000.0,
        "Flow IAT Max": 8_000_000.0,
        "Flow IAT Min": 100_000.0,
        "Fwd IAT Total": 30_000_000.0,
        "Fwd IAT Mean": 7_500_000.0,
        "Bwd IAT Total": 30_000_000.0,
        "Bwd IAT Mean": 7_500_000.0,
        "FIN Flag Count": 1.0,
        "SYN Flag Count": 1.0,
        "ACK Flag Count": 1.0,
        "PSH Flag Count": 1.0,
        "Fwd PSH Flags": 1.0,
        "Fwd Header Length": 160.0,
        "Bwd Header Length": 160.0,
        "Packet Length Mean": 150.0,
        "Packet Length Std": 45.0,
        "Packet Length Variance": 2_025.0,
        "Avg Packet Size": 150.0,
        "Avg Fwd Segment Size": 100.0,
        "Avg Bwd Segment Size": 200.0,
        "Down/Up Ratio": 2.0,
        "Subflow Fwd Packets": 4.0,
        "Subflow Fwd Bytes": 400.0,
        "Subflow Bwd Packets": 4.0,
        "Subflow Bwd Bytes": 800.0,
        "Init Fwd Win Bytes": 8192.0,
        "Init Bwd Win Bytes": 8192.0,
        "Fwd Act Data Packets": 3.0,
        "Fwd Seg Size Min": 20.0,
        "Idle Mean": 25_000_000.0,
        "Idle Max": 28_000_000.0,
        "Idle Min": 20_000_000.0,
        "Active Mean": 5_000_000.0,
        "Active Max": 5_000_000.0,
        "Active Min": 5_000_000.0,
    },

    # ── Infiltration ─────────────────────────────────────────────────────────
    # CIC-IDS: Portscan + exploit – medium flows, mixed protocols.
    "Infiltration": {
        **_make_base(),
        "Protocol": 6.0,
        "Flow Duration": 10_000_000.0,
        "Total Fwd Packets": 50.0,
        "Total Backward Packets": 45.0,
        "Fwd Packets Length Total": 10_000.0,
        "Bwd Packets Length Total": 9_000.0,
        "Fwd Packet Length Mean": 200.0,
        "Fwd Packet Length Max": 1_460.0,
        "Fwd Packet Length Min": 40.0,
        "Bwd Packet Length Mean": 200.0,
        "Bwd Packet Length Max": 1_460.0,
        "Bwd Packet Length Min": 40.0,
        "Flow Bytes/s": 1_900.0,
        "Flow Packets/s": 9.5,
        "Fwd Packets/s": 5.0,
        "Bwd Packets/s": 4.5,
        "Flow IAT Mean": 105_000.0,
        "Flow IAT Std": 80_000.0,
        "Flow IAT Max": 500_000.0,
        "Flow IAT Min": 2_000.0,
        "Fwd IAT Total": 10_000_000.0,
        "Fwd IAT Mean": 200_000.0,
        "Bwd IAT Total": 10_000_000.0,
        "Bwd IAT Mean": 222_222.0,
        "FIN Flag Count": 1.0,
        "SYN Flag Count": 1.0,
        "ACK Flag Count": 1.0,
        "PSH Flag Count": 20.0,
        "Fwd PSH Flags": 1.0,
        "Bwd PSH Flags": 1.0,
        "Fwd Header Length": 2_000.0,
        "Bwd Header Length": 1_800.0,
        "Packet Length Mean": 200.0,
        "Packet Length Std": 60.0,
        "Packet Length Variance": 3_600.0,
        "Avg Packet Size": 200.0,
        "Avg Fwd Segment Size": 200.0,
        "Avg Bwd Segment Size": 200.0,
        "Down/Up Ratio": 0.9,
        "Subflow Fwd Packets": 50.0,
        "Subflow Fwd Bytes": 10_000.0,
        "Subflow Bwd Packets": 45.0,
        "Subflow Bwd Bytes": 9_000.0,
        "Init Fwd Win Bytes": 65535.0,
        "Init Bwd Win Bytes": 65535.0,
        "Fwd Act Data Packets": 40.0,
        "Fwd Seg Size Min": 20.0,
        "Active Mean": 10_000_000.0,
        "Active Max": 10_000_000.0,
        "Active Min": 10_000_000.0,
    },

    # ── Heartbleed ────────────────────────────────────────────────────────────
    # CIC-IDS: TLS heartbeat exploit – large bwd payload, small fwd request.
    "Heartbleed": {
        **_make_base(),
        "Protocol": 6.0,
        "Flow Duration": 500_000.0,        # 0.5 s
        "Total Fwd Packets": 3.0,
        "Total Backward Packets": 2.0,
        "Fwd Packets Length Total": 195.0,
        "Bwd Packets Length Total": 65_535.0,   # large heartbeat response
        "Fwd Packet Length Mean": 65.0,
        "Fwd Packet Length Max": 75.0,
        "Fwd Packet Length Min": 60.0,
        "Bwd Packet Length Mean": 32_768.0,
        "Bwd Packet Length Max": 65_535.0,
        "Bwd Packet Length Min": 1.0,
        "Flow Bytes/s": 131_460.0,
        "Flow Packets/s": 10.0,
        "Fwd Packets/s": 6.0,
        "Bwd Packets/s": 4.0,
        "Flow IAT Mean": 100_000.0,
        "Flow IAT Max": 300_000.0,
        "Flow IAT Min": 10_000.0,
        "Fwd IAT Total": 500_000.0,
        "Fwd IAT Mean": 250_000.0,
        "Bwd IAT Total": 500_000.0,
        "Bwd IAT Mean": 250_000.0,
        "FIN Flag Count": 1.0,
        "SYN Flag Count": 1.0,
        "ACK Flag Count": 1.0,
        "PSH Flag Count": 1.0,
        "Fwd PSH Flags": 1.0,
        "Bwd PSH Flags": 1.0,
        "Fwd Header Length": 120.0,
        "Bwd Header Length": 80.0,
        "Packet Length Mean": 13_146.0,
        "Packet Length Std": 25_000.0,
        "Packet Length Variance": 625_000_000.0,
        "Avg Packet Size": 13_146.0,
        "Avg Fwd Segment Size": 65.0,
        "Avg Bwd Segment Size": 32_768.0,
        "Down/Up Ratio": 336.0,
        "Subflow Fwd Packets": 3.0,
        "Subflow Fwd Bytes": 195.0,
        "Subflow Bwd Packets": 2.0,
        "Subflow Bwd Bytes": 65_535.0,
        "Init Fwd Win Bytes": 65535.0,
        "Init Bwd Win Bytes": 65535.0,
        "Fwd Act Data Packets": 2.0,
        "Fwd Seg Size Min": 20.0,
        "Active Mean": 500_000.0,
        "Active Max": 500_000.0,
        "Active Min": 500_000.0,
    },
}


def phase_b():
    banner("PHASE B  –  XGBoost Model Evaluation (CIC-IDS 2017 Traffic Profiles)")

    # Load predictor
    sys.path.insert(0, ".")
    from ai_module.predictor import AttackPredictor
    predictor = AttackPredictor()

    if predictor.model is None:
        print(f"  {RED}Model not loaded – cannot run Phase B.{RESET}")
        print("  Run: python3 ai_module/train_model.py --data data/cic-ids/")
        return

    print(f"\n  Model classes: {predictor.label_encoder.classes_.tolist()}\n")
    print(f"  {'Attack Profile':<16} {'Detected As':<16} {'Conf':>6}  "
          f"{'Is Attack':>10}  Top SHAP Feature")
    print(f"  {'─'*14:<16} {'─'*14:<16} {'─'*6:>6}  {'─'*9:>10}  {'─'*30}")

    all_results = []
    for expected_label, feature_vector in ATTACK_PROFILES.items():
        result = predictor.predict(feature_vector)

        detected   = result["attack_type"]
        confidence = result["confidence"]
        is_attack  = result["is_attack"]
        top_shap   = (result["shap"]["top_features"][0]["name"]
                      if result["shap"]["top_features"] else "N/A")

        correct = (detected == expected_label)
        colour  = GREEN if correct else YELLOW

        print(f"  {colour}{expected_label:<16}{RESET} "
              f"{colour}{detected:<16}{RESET} "
              f"{confidence:>6.1%}  "
              f"{'YES' if is_attack else 'NO':>10}  "
              f"{top_shap}")

        all_results.append({
            "expected":   expected_label,
            "detected":   detected,
            "confidence": confidence,
            "is_attack":  is_attack,
            "correct":    correct,
            "shap":       result["shap"],
        })

        time.sleep(0.05)

    # ── Summary ──────────────────────────────────────────────────────────────
    correct_count  = sum(1 for r in all_results if r["correct"])
    attack_flagged = sum(1 for r in all_results if r["is_attack"])
    total          = len(all_results)

    print(f"\n  {BOLD}Results Summary{RESET}")
    result_line("Correct classifications", f"{correct_count}/{total}",
                ok=(correct_count == total))
    result_line("Flagged as attack",       f"{attack_flagged}/{total}")
    result_line("Missed (classified Benign)",
                f"{total - attack_flagged}/{total}",
                ok=(total - attack_flagged == 0))

    # ── Detailed SHAP for each ────────────────────────────────────────────
    print(f"\n{CYAN}{BOLD}  SHAP Explanation (top-3 features per profile):{RESET}")
    for r in all_results:
        label_str = (f"{GREEN}{r['expected']}{RESET}"
                     if r["correct"] else
                     f"{YELLOW}{r['expected']} → {r['detected']}{RESET}")
        print(f"\n  {label_str}  (confidence {r['confidence']:.1%})")
        for feat in r["shap"]["top_features"]:
            direction = "+" if feat["shap_value"] >= 0 else ""
            print(f"    • {feat['name']:<35} SHAP {direction}{feat['shap_value']:+.4f}")
        if not r["shap"]["top_features"]:
            print("    (no SHAP data)")


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(f"\n{BOLD}{CYAN}Honeyport Attack Simulator{RESET}")
    print(f"{CYAN}Honeypot target : {HONEYPOT_URL}{RESET}")

    phase_a()
    phase_b()

    print(f"\n{GREEN}{BOLD}Simulation complete.{RESET}\n")
