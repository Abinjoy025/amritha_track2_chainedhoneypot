# Chained Honeypot — Secure Decentralized Deception System

A multi-phase cybersecurity research system combining **XGBoost multi-class attack detection**, **IPFS decentralized evidence storage**, **Ethereum blockchain immutability**, and a **React real-time dashboard** to create a tamper-proof honeypot platform.

---

## Features

- **Dynamic Honeypot**: Fake admin login portal that captures attacker credentials, payloads, and headers
- **XGBoost AI Detection**: Multi-class classifier trained on CIC-IDS 2017 — detects 9 attack categories with SHAP explanations
- **Behavioral Fingerprinting**: Per-IP attacker profiling with cross-session correlation
- **OSINT Enrichment**: IP geo, ASN, Tor exit detection, FireHOL/ipsum threat feeds, AbuseIPDB (optional)
- **SOAR Automation**: Automatic IP blocking and container recycling for high-confidence detections
- **IPFS Storage**: Decentralized forensic evidence via Pinata (with local fallback)
- **Blockchain Security**: Immutable attack records on Ethereum Sepolia via Solidity smart contract
- **React Dashboard**: Real-time WebSocket feed, SHAP panel, blockchain ledger (port 8000)
- **Flask Dashboard**: Lightweight monitoring UI with campaign and profile views (port 8080)

---

## Architecture

```
Attacker → Honeypot (Flask :5000)
               |
          honeypot_logs.json
               |
          Controller (v2)
          /    |    \    \
    Zeek   OSINT  SOAR  WebSocket
    Flow   Enrich  Block  Broadcast
     |
  XGBoost ─── SHAP
  (CIC-IDS 2017)
     |               |
  IPFS (Pinata) ← evidence JSON
     |
  Ethereum Sepolia ← IPFS CID + hash
     |
  React Dashboard (:8000) + Flask Dashboard (:8080)
```

---

## Prerequisites

| Item | Requirement |
|------|-------------|
| Python | 3.10 or newer |
| OS | Linux (Ubuntu 20.04+), macOS, Windows 10+ |
| RAM | 8 GB minimum (16 GB recommended for training) |
| Storage | 10 GB free (dataset + models) |
| Network | Internet for IPFS / blockchain; local-only mode also supported |

---

## Quick Start

### 1. Install

```bash
# Clone / download project
cd AMRITHA_TRACK2_CHAINEDHONEYPOT

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Train the AI Model

```bash
# Download CIC-IDS 2017 dataset (or place CSVs in data/cic-ids/)
python3 ai_module/dataset_downloader.py

# Train XGBoost on CIC-IDS 2017 (~15-25 min depending on hardware)
python3 ai_module/train_model.py --data data/cic-ids/
```

Expected output after training:
```
✅  Models saved to models/
   xgb_model.pkl
   scaler.pkl
   label_encoder.pkl
   feature_names.pkl
```

### 3. Configure Environment

Copy `.env.example` to `.env` and fill in credentials:

```bash
cp .env.example .env
```

Minimum required for offline / mock mode — no changes needed.
For full blockchain + IPFS, edit `.env` with:
- `PINATA_JWT` — Pinata JWT token (see ACCOUNT_SETUP.md)
- `WEB3_PROVIDER_URL` — Sepolia RPC from Infura or Alchemy
- `ETH_PRIVATE_KEY` — Wallet private key
- `HONEYPORT_CONTRACT_ADDRESS` — Deployed contract address

### 4. Run

**One-command launcher (all services):**
```bash
python3 start.py
```

**Or start services individually (4 terminals):**

```bash
# Terminal 1 — Honeypot trap
python3 app.py
# Access: http://localhost:5000

# Terminal 2 — Orchestration controller + AI pipeline
python3 controller.py

# Terminal 3 — FastAPI backend + WebSocket + React dashboard
cd api && uvicorn main:app --host 0.0.0.0 --port 8000 --reload
# React UI: http://localhost:8000

# Terminal 4 — Legacy Flask dashboard (optional)
python3 dashboard.py
# Access: http://localhost:8080
```

---

## Project Structure

```
AMRITHA_TRACK2_CHAINEDHONEYPOT/
│
├── app.py                      # Honeypot Flask server (port 5000)
├── controller.py               # Orchestration controller (v2)
├── dashboard.py                # Legacy Flask dashboard (port 8080)
├── start.py                    # One-command launcher
├── attack_simulator.py         # Attack simulation utility
│
├── ai_module/
│   ├── train_model.py          # XGBoost trainer on CIC-IDS 2017
│   ├── predictor.py            # XGBoost inference + SHAP explanations
│   ├── behavioral_fingerprint.py  # Per-IP attacker profile builder
│   ├── campaign_tracker.py     # Groups attacks into campaigns (SOC view)
│   ├── ip_intelligence.py      # IP enrichment / threat feeds (no key needed)
│   ├── online_learner.py       # Incremental Random Forest retraining
│   ├── packet_capture.py       # Packet capture utilities
│   └── dataset_downloader.py   # CIC-IDS / NSL-KDD dataset downloader
│
├── api/
│   ├── main.py                 # FastAPI backend + WebSocket live feed (port 8000)
│   └── Dockerfile
│
├── pipeline/
│   ├── feature_extractor.py    # Zeek conn.log → 78 CIC-IDS features
│   └── traffic_capture.py      # ZeekCapture connector
│
├── blockchain/
│   ├── blockchain_manager.py   # Ethereum / Sepolia (web3.py)
│   ├── ipfs_manager.py         # IPFS via Pinata JWT + local fallback
│   ├── AttackEvidenceStorage.sol  # Solidity smart contract
│   └── config.json.template
│
├── soar/
│   ├── osint_enricher.py       # AbuseIPDB + Shodan enrichment
│   └── soar_playbook.py        # Auto-block + container-recycle playbook
│
├── frontend/honeyport-ui/      # React dashboard (Vite + Tailwind + Recharts)
│   └── src/
│       ├── App.jsx             # Root + WebSocket client
│       └── components/
│           ├── LiveFeed.jsx    # Real-time attack event feed
│           ├── ShapPanel.jsx   # SHAP explainability bar chart
│           ├── Web3Ledger.jsx  # Blockchain records viewer
│           └── StatsBar.jsx    # Aggregate statistics header
│
├── templates/                  # Flask Jinja2 templates
│   ├── login.html              # Fake admin login trap
│   ├── dashboard.html          # Legacy Flask dashboard
│   └── portal.html             # Legitimate user portal decoy
│
├── docker/
│   ├── docker-compose.yml      # Multi-container setup (4 services)
│   └── zeek/local.zeek         # Zeek network monitor config
│
├── models/                     # Trained model artifacts
│   ├── xgb_model.pkl
│   ├── scaler.pkl
│   ├── label_encoder.pkl
│   └── feature_names.pkl
│
├── data/cic-ids/               # CIC-IDS 2017 CSVs (place here)
├── logs/                       # Honeypot + API logs
├── requirements.txt
├── setup.sh                    # Automated Linux/macOS setup
└── .env / .env.example         # Environment variables
```

---

## Attack Classes

The XGBoost model detects 9 canonical classes from CIC-IDS 2017 traffic features:

| Class | Source Labels | Notes |
|-------|--------------|-------|
| Benign | BENIGN | Normal traffic |
| DoS | DoS Hulk, GoldenEye, slowloris, Slowhttptest | Denial-of-Service variants |
| DDoS | DDoS | Distributed DoS |
| PortScan | PortScan | Network scanning |
| BruteForce | FTP-Patator, SSH-Patator | Credential stuffing |
| Bot | Bot | Botnet C2 traffic |
| WebAttack | Web Attack – BF/XSS/SQLi | Web application attacks |
| Infiltration | Infiltration | Lateral movement |
| Heartbleed | Heartbleed | SSL Heartbleed exploit (rare class) |

---

## Dashboards

| Dashboard | URL | Technology | Purpose |
|-----------|-----|-----------|---------|
| React UI | http://localhost:8000 | Vite + Tailwind + Recharts | Live feed, SHAP panel, blockchain ledger |
| Flask UI | http://localhost:8080 | Jinja2 | Campaigns, profiles, evidence browse |
| Honeypot | http://localhost:5000 | Flask | Fake login trap (attacker-facing) |

---

## Performance

| Metric | Value |
|--------|-------|
| XGBoost overall accuracy | ~97% on CIC-IDS 2017 test split |
| Detection latency | < 1 second per flow |
| IPFS upload (Pinata) | 2–5 seconds |
| Blockchain confirmation (Sepolia) | 10–30 seconds |
| SOAR trigger threshold | confidence >= 90% + high-risk class |

---

## Free Tier Resources

| Component | Service | Cost |
|-----------|---------|------|
| AI Model | XGBoost / scikit-learn | $0 |
| IPFS | Pinata free tier (1 GB) | $0 |
| Blockchain | Ethereum Sepolia testnet | $0 |
| RPC | Infura / Alchemy free tier | $0 |
| Dashboards | Local Flask + Vite dev server | $0 |

---

## Security Notes

- Deploy only in isolated / lab environments
- Honeypot opens ports intended to attract attackers — never expose on a production network without authorization
- Store private keys only in `.env` (which is `.gitignore`d)
- Use Sepolia testnet keys; never use real mainnet keys

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Module not found | `pip install -r requirements.txt` |
| XGBoost model missing | `python3 ai_module/train_model.py --data data/cic-ids/` |
| IPFS upload fails | System falls back to `data/ipfs_fallback/` automatically |
| Blockchain error | Check `.env` or system runs in mock mode automatically |
| Port in use | `lsof -i :5000` → `kill -9 <PID>` |
| Heartbleed low confidence | Retrain after adding more samples; model uses balanced weights |

---

## Team Roles

| Member | Responsibilities |
|--------|-----------------|
| AI & Honeypot Engineer | XGBoost training, CIC-IDS feature pipeline, attack classification, SHAP explainability |
| Blockchain & Storage Engineer | Pinata IPFS integration, Solidity smart contract, Sepolia deployment |
| Integration & Interface Engineer | Controller pipeline, FastAPI + WebSocket, React dashboard, behavioral fingerprinting |

---

## Links

- CIC-IDS 2017 Dataset: https://www.unb.ca/cic/datasets/ids-2017.html
- Pinata IPFS: https://pinata.cloud
- Ethereum Sepolia: https://sepolia.etherscan.io
- Infura RPC: https://infura.io
- Alchemy RPC: https://alchemy.com

---

**Disclaimer**: This is a honeypot system for research and educational purposes. Deploy responsibly and in accordance with applicable laws and regulations.

*Chained Honeypot — Secure Decentralized Deception System*
*Built with Python 3.10+ | XGBoost | Flask | FastAPI | React | Web3.py | IPFS | Ethereum*
