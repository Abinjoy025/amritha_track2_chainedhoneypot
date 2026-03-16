# CHAINED HONEYPOT — COMPLETE SETUP GUIDE

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Environment Setup](#2-environment-setup)
3. [Install Dependencies](#3-install-dependencies)
4. [Dataset and Model Training](#4-dataset-and-model-training)
5. [Environment Variables (.env)](#5-environment-variables-env)
6. [Blockchain Configuration](#6-blockchain-configuration)
7. [React Dashboard Build](#7-react-dashboard-build)
8. [Running the System](#8-running-the-system)
9. [Testing the System](#9-testing-the-system)
10. [Docker Deployment](#10-docker-deployment)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. System Requirements

### Hardware
- Processor: Intel i5 / AMD Ryzen 5 or better
- RAM: 8 GB minimum (16 GB recommended for model training)
- Storage: 10 GB free (dataset ~4 GB + models ~200 MB + logs)
- Network: Internet connection for IPFS / blockchain; local-only mode works offline

### Software

| Tool | Version |
|------|---------|
| Python | 3.10 or newer |
| pip | Latest (`pip install --upgrade pip`) |
| Node.js | 18+ (only for React dashboard build) |
| npm | 9+ (bundled with Node.js) |
| Git | Any recent version |
| Docker + Compose | Optional (for full network simulation) |

OS: Linux Ubuntu 20.04+, macOS 12+, or Windows 10+ (WSL2 recommended on Windows)

---

## 2. Environment Setup

```bash
# Navigate to project root
cd AMRITHA_TRACK2_CHAINEDHONEYPOT

# Create Python virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate          # Linux / macOS
# venv\Scripts\activate           # Windows CMD
# venv\Scripts\Activate.ps1       # Windows PowerShell
```

---

## 3. Install Dependencies

```bash
# Upgrade pip
pip install --upgrade pip

# Install all Python dependencies
pip install -r requirements.txt
```

Key packages installed:

| Package | Purpose |
|---------|---------|
| xgboost >= 2.0.3 | Primary attack classifier |
| shap >= 0.45.0 | SHAP explainability for AI decisions |
| scikit-learn >= 1.4.0 | Preprocessing, metrics, online learner |
| pandas, numpy | Data processing |
| flask >= 3.0.0 | Honeypot server + legacy dashboard |
| fastapi, uvicorn | REST API + WebSocket real-time feed |
| web3 >= 6.15.0 | Ethereum Sepolia blockchain interaction |
| requests | IP intelligence + HTTP calls |
| inotify-simple | Real-time log file monitoring (Linux) |
| docker | SOAR container management |

---

## 4. Dataset and Model Training

### Step 4a: Download CIC-IDS 2017 Dataset

```bash
python3 ai_module/dataset_downloader.py
```

This downloads CIC-IDS 2017 CSV files to `data/cic-ids/`.

Alternatively, download manually from:
https://www.unb.ca/cic/datasets/ids-2017.html

Place the CSV files in `data/cic-ids/` (subdirectories are fine; the trainer scans recursively).

### Step 4b: Train XGBoost Model

```bash
python3 ai_module/train_model.py --data data/cic-ids/
```

Training configuration:
- 600 estimators, max depth 10, learning rate 0.08
- Balanced sample weights (critical for rare classes like Heartbleed and Infiltration)
- 80/20 stratified train/test split

Expected output:
```
📂 Found N CSV file(s)
📊 Total rows: 2,830,743
📊 Class distribution:
   Benign                 2,273,097
   BruteForce                13,835
   Bot                        1,966
   DDoS                     128,027
   DoS                      252,661
   Heartbleed                    11
   Infiltration                  36
   PortScan                 158,930
   WebAttack                  2,180
🌲  Training XGBoost (classes=9) …
...
✅  Models saved to models/
```

Saved artifacts:
```
models/
├── xgb_model.pkl         ← Trained XGBoost classifier
├── scaler.pkl            ← StandardScaler
├── label_encoder.pkl     ← Class index ↔ name mapping
└── feature_names.pkl     ← 78 CIC-IDS feature names in order
```

---

## 5. Environment Variables (.env)

```bash
cp .env.example .env
```

Edit `.env`:

```ini
# Flask
FLASK_SECRET=change-me-to-random-string

# OSINT (optional — system works without these)
ABUSEIPDB_API_KEY=your_abuseipdb_key
SHODAN_API_KEY=your_shodan_key

# IPFS (Pinata JWT — see ACCOUNT_SETUP.md)
PINATA_JWT=your_pinata_jwt_token_here

# Ethereum / Sepolia
WEB3_PROVIDER_URL=https://sepolia.infura.io/v3/YOUR_INFURA_PROJECT_ID
HONEYPORT_CONTRACT_ADDRESS=0xYourDeployedContractAddress
ETH_PRIVATE_KEY=0xYourPrivateKeyHere

# React frontend (for Vite build)
VITE_CONTRACT_ADDRESS=0xYourDeployedContractAddress
VITE_RPC_URL=https://rpc.sepolia.org
VITE_WS_URL=ws://localhost:8000/ws/live

# SOAR
SOAR_CONF_THRESHOLD=0.90
```

The system runs in **mock mode** if blockchain credentials are absent — evidence is saved locally.

---

## 6. Blockchain Configuration

### Option A: Full Blockchain (Sepolia Testnet)

See [ACCOUNT_SETUP.md](ACCOUNT_SETUP.md) for step-by-step account creation.

Summary:
1. Get a free Infura or Alchemy Sepolia RPC URL
2. Create an Ethereum wallet (MetaMask or programmatic)
3. Get free Sepolia test ETH from a faucet
4. Get free Pinata JWT for IPFS uploads
5. Fill in all values in `.env`

### Option B: Mock Mode (No Setup Needed)

No blockchain or IPFS credentials required. The system will:
- Save evidence JSON to `data/ipfs_fallback/`
- Log blockchain records to `evidence_summary_new.json`
- Skip on-chain transactions silently

This mode is sufficient for local testing and demos.

### Option C: Local Ganache Blockchain

```bash
npm install -g ganache
ganache
```

Use the provided test account private key and `http://127.0.0.1:8545` as `WEB3_PROVIDER_URL`.

---

## 7. React Dashboard Build

The React dashboard is in `frontend/honeyport-ui/` and is served by the FastAPI backend on port 8000.

```bash
cd frontend/honeyport-ui

# Install Node.js dependencies
npm install

# Development server (hot reload, connects to localhost:8000 WebSocket)
npm run dev
# Access: http://localhost:5173

# Production build (served by FastAPI)
npm run build
# Outputs to frontend/honeyport-ui/dist/
```

If Node.js is not available, the FastAPI backend at `http://localhost:8000` still serves the REST API and WebSocket — you can use the legacy Flask dashboard at `http://localhost:8080` instead.

---

## 8. Running the System

### Option 1: One-Command Launch

```bash
source venv/bin/activate
python3 start.py
```

Starts: honeypot (5000) + controller + FastAPI backend (8000) + Flask dashboard (8080)

### Option 2: Manual (4 Terminals)

**Terminal 1 — Honeypot**
```bash
source venv/bin/activate
python3 app.py
# Trap: http://localhost:5000
```

**Terminal 2 — Controller + AI Pipeline**
```bash
source venv/bin/activate
python3 controller.py
```

**Terminal 3 — FastAPI Backend + React Dashboard**
```bash
source venv/bin/activate
cd api
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
# React dashboard: http://localhost:8000
# WebSocket: ws://localhost:8000/ws/live
```

**Terminal 4 — Legacy Flask Dashboard (optional)**
```bash
source venv/bin/activate
python3 dashboard.py
# http://localhost:8080
```

### Access Points Summary

| Service | URL | Description |
|---------|-----|-------------|
| Honeypot | http://localhost:5000 | Attacker-facing fake login |
| React Dashboard | http://localhost:8000 | Live feed, SHAP, blockchain ledger |
| Flask Dashboard | http://localhost:8080 | Campaigns, profiles, evidence |
| FastAPI Docs | http://localhost:8000/docs | Auto-generated API documentation |

---

## 9. Testing the System

### Simulate an Attack

1. Open http://localhost:5000
2. Enter any credentials (e.g., username: `admin`, password: `password123`)
3. Click Login — you will see "Invalid credentials" (honeypot is working)

### Watch the Controller

You should see in the controller terminal:
```
NEW ATTEMPT DETECTED
IP: 127.0.0.1  User: admin
Attack type : BruteForce
Confidence  : 93.47%
SHAP        : Flow Bytes/s (+1.42), SYN Flag Count (+0.88)
IPFS CID    : QmXxxx...
Blockchain  : tx 0xabc...
```

### Verify on Dashboard

- Open http://localhost:8000 — check the live feed card appears
- Click the SHAP panel — verify confidence percentage and top features
- Open the Web3 Ledger tab — verify blockchain record

### Run Attack Simulator

```bash
python3 attack_simulator.py
```

Sends multiple simulated attack events to test the full pipeline.

---

## 10. Docker Deployment

For full network simulation with Zeek traffic capture:

```bash
cd docker
docker-compose up -d
```

Services started:
- `nginx_original` (192.168.100.10:8080) — legitimate server decoy
- `honeyport_app` (192.168.200.10:5000) — honeypot (internal, reached via iptables DNAT)
- `zeek_monitor` — network packet capture in host mode
- `api_backend` — FastAPI backend (port 8000)

Check logs:
```bash
docker-compose logs -f honeyport_app
docker-compose logs -f api_backend
```

---

## 11. Troubleshooting

### "ModuleNotFoundError"
```bash
pip install -r requirements.txt
```

### XGBoost model not found
```bash
python3 ai_module/train_model.py --data data/cic-ids/
```

### "No CSV files found in data/cic-ids/"
```bash
python3 ai_module/dataset_downloader.py
# Or manually place CIC-IDS 2017 CSVs in data/cic-ids/
```

### Port already in use
```bash
lsof -i :5000          # find PID
kill -9 <PID>
```

### IPFS upload fails
Normal — the system automatically falls back to `data/ipfs_fallback/`. To enable real IPFS:
- Add `PINATA_JWT` to `.env` (see ACCOUNT_SETUP.md)

### Blockchain connection error
Normal — system runs in mock mode. To enable:
- Add `WEB3_PROVIDER_URL`, `ETH_PRIVATE_KEY`, `HONEYPORT_CONTRACT_ADDRESS` to `.env`

### Heartbleed / Bot low confidence after training
The model uses `compute_sample_weight('balanced', y_train)` to up-weight rare classes. To further improve:
- Augment `data/cic-ids/` with more Heartbleed samples if available
- Lower `SOAR_CONF_THRESHOLD` in `.env` for these specific classes if needed

### React dashboard not loading at port 8000
```bash
cd frontend/honeyport-ui
npm install
npm run build
# Then restart the FastAPI server
```

---

**Remember:** Only deploy honeypots ethically and legally in environments you own or have authorization to test.
