# Running Chained Honeypot Locally

This guide covers every step to get the full system running on your local machine — from first clone to live dashboard.

---

## Prerequisites

- Python 3.10+
- Node.js 18+ and npm 9+ (for the React dashboard)
- A terminal with the project directory open

```bash
cd AMRITHA_TRACK2_CHAINEDHONEYPOT
```

---

## Step 1 — Create and Activate Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows
```

You should see `(venv)` in your prompt.

---

## Step 2 — Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Step 3 — Train the AI Model (First Run Only)

The pre-trained `.pkl` files in `models/` were generated from CIC-IDS 2017. If they are present, skip to Step 4.

If `models/xgb_model.pkl` is missing:

```bash
# Download the dataset (takes a few minutes)
python3 ai_module/dataset_downloader.py

# Train XGBoost on CIC-IDS 2017 (~15–25 min on mid-range hardware)
python3 ai_module/train_model.py --data data/cic-ids/
```

Expected files after training:
```
models/
├── xgb_model.pkl
├── scaler.pkl
├── label_encoder.pkl
└── feature_names.pkl
```

---

## Step 4 — Configure Environment

```bash
cp .env.example .env
```

For a local test without blockchain or IPFS, the default `.env.example` values work as-is. The system automatically falls back to mock mode.

For full functionality (IPFS + blockchain), fill in:
```ini
PINATA_JWT=your_pinata_jwt
WEB3_PROVIDER_URL=https://sepolia.infura.io/v3/YOUR_ID
ETH_PRIVATE_KEY=0xYourPrivateKey
HONEYPORT_CONTRACT_ADDRESS=0xYourContractAddress
```

See [ACCOUNT_SETUP.md](ACCOUNT_SETUP.md) for how to get these free credentials.

---

## Step 5 — Start All Services

### Option A: One Command

```bash
python3 start.py
```

This launches all services (honeypot, controller, API backend, Flask dashboard) in subprocesses.

### Option B: Four Separate Terminals (Recommended for Development)

Open four terminal windows, all with the virtualenv activated.

**Terminal 1 — Honeypot Trap**
```bash
source venv/bin/activate
python3 app.py
```

**Terminal 2 — Orchestration Controller**
```bash
source venv/bin/activate
python3 controller.py
```

**Terminal 3 — FastAPI Backend + React Dashboard**
```bash
source venv/bin/activate
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 4 — Legacy Flask Dashboard (optional)**
```bash
source venv/bin/activate
python3 dashboard.py
```

---

## Step 6 — Build the React Dashboard (First Run Only)

The React dashboard needs to be built before `uvicorn` can serve it.

```bash
cd frontend/honeyport-ui
npm install
npm run build           # outputs to frontend/honeyport-ui/dist/
cd ../..
```

For live development with hot reload:
```bash
cd frontend/honeyport-ui
npm run dev             # runs on http://localhost:5173
```

---

## Where Are the Dashboards?

### React Dashboard (Primary)

**URL:** http://localhost:8000

Served by the FastAPI backend. Requires:
- `uvicorn api.main:app` running on port 8000
- React build completed (`npm run build`)

Features:
- **Live Feed** — real-time attack events via WebSocket (`ws://localhost:8000/ws/live`)
- **SHAP Panel** — AI explanation: predicted class, confidence %, top-3 feature contributions
- **Web3 Ledger** — blockchain records from Sepolia; links to Pinata IPFS gateway and Sepolia Etherscan
- **Stats Bar** — total attacks, severity breakdown, SOAR-triggered count

### Legacy Flask Dashboard

**URL:** http://localhost:8080

Served by `dashboard.py`. Works without Node.js.

Features:
- Total attempt and attack counts
- Campaign grouping (correlated attack groups)
- Behavioral attacker profiles
- Evidence browser with IPFS link verification

### FastAPI Auto Docs

**URL:** http://localhost:8000/docs

Interactive Swagger UI listing all REST endpoints:
- `GET /api/attacks/latest` — recent attack events
- `GET /api/evidence` — IPFS + blockchain evidence records
- `GET /api/campaigns` — grouped attack campaigns
- `POST /internal/attacker_detected` — internal OSINT trigger
- `POST /internal/session_complete` — full AI → IPFS → blockchain pipeline

### Honeypot (Attacker-Facing)

**URL:** http://localhost:5000

This is the fake admin login portal. Every login attempt (except the one legitimate user) is treated as an attacker and logged forensically.

> Do not log in with real credentials here.

---

## Testing the Full Pipeline

1. Open http://localhost:5000
2. Enter `admin` / `password123` and click Login
3. Watch Terminal 2 (controller) for:
   ```
   NEW ATTEMPT DETECTED
   Attack type : BruteForce
   Confidence  : 93.47%
   IPFS CID    : Qm...
   ```
4. Open http://localhost:8000 — the new event should appear in the Live Feed within 1–2 seconds
5. Click the event — the SHAP panel shows the confidence and top features
6. Open the Web3 Ledger tab (if blockchain is configured) — the record appears

### Run the Attack Simulator

To quickly generate multiple test events:

```bash
python3 attack_simulator.py
```

---

## Port Reference

| Port | Service | URL |
|------|---------|-----|
| 5000 | Honeypot (Flask) | http://localhost:5000 |
| 8000 | FastAPI + React Dashboard | http://localhost:8000 |
| 8080 | Legacy Flask Dashboard | http://localhost:8080 |
| 5173 | React dev server (npm run dev) | http://localhost:5173 |

---

## Stopping All Services

If using `start.py`:
```bash
Ctrl+C
```

If running manually, press `Ctrl+C` in each terminal.

To kill a stuck port:
```bash
lsof -i :5000          # find PID
kill -9 <PID>
```

---

## Common Issues on First Run

| Problem | Cause | Fix |
|---------|-------|-----|
| `ModuleNotFoundError` | Dependencies not installed | `pip install -r requirements.txt` |
| `xgb_model.pkl not found` | Model not trained yet | `python3 ai_module/train_model.py` |
| React UI shows blank page | Build not done | `cd frontend/honeyport-ui && npm run build` |
| Port 8000 in use | Something else running | `lsof -i :8000` → kill |
| IPFS upload fails silently | No Pinata JWT | Normal — falls back to `data/ipfs_fallback/` |
| Blockchain tx error | No `.env` credentials | Normal — runs in mock mode |
| `inotify` error on macOS/Windows | inotify is Linux-only | The controller falls back to polling mode |

---

## Quick Reference Card

```
# One-time setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 ai_module/train_model.py --data data/cic-ids/
cd frontend/honeyport-ui && npm install && npm run build && cd ../..
cp .env.example .env

# Every run
source venv/bin/activate
python3 start.py

# Dashboards
http://localhost:8000   ← React dashboard (primary)
http://localhost:8080   ← Flask dashboard (alternative)
http://localhost:5000   ← Honeypot trap
```
