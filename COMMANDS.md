# Chained Honeypot — Run Commands

## 1. Setup (First Time Only)

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 2. Train XGBoost Model on CIC-IDS Dataset

### Step 1 — Download CIC-IDS 2017 Dataset

Requires Kaggle credentials in `~/.kaggle/kaggle.json`
(or environment variables `KAGGLE_USERNAME` and `KAGGLE_KEY`)

```bash
python3 ai_module/dataset_downloader.py
```

Downloads `dhoogla/cicids2017` from Kaggle and saves to:
```
data/cic-ids/cicids2017_combined.csv
```

### Step 2 — Train XGBoost

```bash
python3 ai_module/train_model.py --data data/cic-ids/
```

Optional flags:
```bash
python3 ai_module/train_model.py --data data/cic-ids/ --model-dir models/
```

Output after training:
```
models/
├── xgb_model.pkl
├── scaler.pkl
├── label_encoder.pkl
└── feature_names.pkl
```

---

## 3. Run the Honeypot

```bash
source venv/bin/activate
python3 app.py
```

Honeypot trap accessible at: `http://localhost:5000`

---

## 4. Run the Dashboard

### FastAPI Backend + React Dashboard (Primary)

```bash
source venv/bin/activate
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

Dashboard at: `http://localhost:8000`
API docs at: `http://localhost:8000/docs`

### Build React UI (First Time Only)

```bash
cd frontend/honeyport-ui
npm install
npm run build
cd ../..
```

### Legacy Flask Dashboard (Alternative)

```bash
source venv/bin/activate
python3 dashboard.py
```

Dashboard at: `http://localhost:8080`

---

## 5. Run the Controller

```bash
source venv/bin/activate
python3 controller.py
```

Monitors honeypot logs and triggers the AI → IPFS → Blockchain pipeline.

---

## 6. Run All Services at Once

```bash
source venv/bin/activate
python3 start.py
```

Starts honeypot and controller together in subprocesses. Press `Ctrl+C` to stop.

---

## Port Reference

| Port | Service |
|------|---------|
| 5000 | Honeypot trap (Flask) |
| 8000 | FastAPI + React dashboard |
| 8080 | Legacy Flask dashboard |
| 5173 | React dev server (`npm run dev`) |

---

## Test the Pipeline

```bash
# Simulate attacks to generate test events
python3 attack_simulator.py
```

Then check `http://localhost:8000` for live events in the dashboard.
