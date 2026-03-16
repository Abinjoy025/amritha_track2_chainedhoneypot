# 🚀 CHAINED HONEYPOT - COMPLETE SETUP GUIDE

## 📋 Table of Contents
1. [System Requirements](#system-requirements)
2. [Installation Steps](#installation-steps)
3. [Blockchain Configuration](#blockchain-configuration)
4. [Running the System](#running-the-system)
5. [Testing the System](#testing-the-system)
6. [Troubleshooting](#troubleshooting)

---

## 🖥️ System Requirements

### Hardware
- **Processor**: Intel i5+ or AMD equivalent
- **RAM**: Minimum 8GB (16GB recommended)
- **Storage**: 5GB free space
- **Network**: Active internet connection

### Software
- **OS**: Linux (Ubuntu 20.04+), Windows 10+, or macOS
- **Python**: 3.14.2 or compatible (3.8-3.11 also work)
- **pip**: Latest version
- **Git**: For cloning repository

---

## 📦 Installation Steps

### Step 1: Prepare Environment

```bash
# Navigate to project directory
cd /home/master_tech/honeyport

# (Optional but Recommended) Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 2: Install Dependencies

```bash
# Upgrade pip first
pip install --upgrade pip

# Install all required packages
pip install -r requirements.txt
```

**What gets installed:**
- `flask` - Web framework for honeypot and dashboard
- `scikit-learn` - Machine learning library for AI model
- `pandas`, `numpy` - Data processing
- `web3` - Ethereum blockchain interaction
- `requests` - IPFS and HTTP communication
- `watchdog` - File monitoring for real-time processing

### Step 3: Download Dataset & Train AI Model

```bash
# Download NSL-KDD dataset
cd ai_module
python3 dataset_downloader.py

# Train Random Forest model (takes 3-5 minutes)
python3 train_model.py

# Return to main directory
cd ..
```

**Expected Output:**
```
📥 Downloading NSL-KDD Dataset...
✅ Downloaded train dataset
✅ Downloaded test dataset
🌲 Training Random Forest Classifier...
✅ Training Accuracy: 0.9834
✅ Validation Accuracy: 0.9512
💾 Saving model...
✅ Model saved successfully!
```

### Step 4: Verify Installation

```bash
# Check if model was created
ls -la models/

# You should see:
# - random_forest_model.pkl
# - scaler.pkl
# - label_encoders.pkl
# - feature_names.pkl
```

---

## ⛓️ Blockchain Configuration

### Option 1: Free Tier (Sepolia Testnet) - Recommended

#### A. Get Free RPC Endpoint

**Using Infura (Recommended):**
1. Go to https://infura.io
2. Sign up for free account
3. Create new project → Select "Web3 API"
4. Copy your Sepolia endpoint URL:
   ```
   https://sepolia.infura.io/v3/YOUR_PROJECT_ID
   ```

**Alternative - Using Alchemy:**
1. Go to https://alchemy.com
2. Sign up for free account
3. Create app → Select "Ethereum" → "Sepolia"
4. Copy your HTTPS endpoint

#### B. Create Wallet

**Option 1: Use MetaMask**
1. Install MetaMask browser extension
2. Create new wallet
3. Switch network to "Sepolia Test Network"
4. Export private key (Settings → Security & Privacy → Reveal Private Key)

**Option 2: Generate Programmatically**
```bash
python3 -c "from eth_account import Account; acc = Account.create(); print(f'Address: {acc.address}\nPrivate Key: {acc.key.hex()}')"
```

**⚠️ IMPORTANT:** Save your private key securely! Never share it or commit to Git!

#### C. Get Test ETH

1. Copy your wallet address
2. Visit https://sepoliafaucet.com
3. Paste address and request test ETH
4. Wait 1-2 minutes for confirmation

**Alternative Faucets:**
- https://faucet.sepolia.dev
- https://sepolia-faucet.pk910.de

#### D. Configure System

Create `blockchain/config.json`:

```json
{
  "network": "sepolia",
  "rpc_url": "https://sepolia.infura.io/v3/YOUR_PROJECT_ID",
  "contract_address": "",
  "private_key": "YOUR_PRIVATE_KEY_HERE"
}
```

**Security Note:** Add `blockchain/config.json` to `.gitignore`!

### Option 2: Local Development (Ganache)

```bash
# Install Ganache globally
npm install -g ganache

# Start Ganache
ganache

# Use provided test accounts (private keys shown in console)
```

Configure for local:
```json
{
  "network": "local",
  "rpc_url": "http://127.0.0.1:8545",
  "private_key": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
}
```

### Option 3: Mock Mode (No Blockchain)

**No configuration needed!** System automatically runs in mock mode if no blockchain is configured. Evidence is saved locally for testing.

---

## 🚀 Running the System

### Quick Start (All Services)

```bash
# Run everything with one command
python3 start.py
```

This starts:
- ✅ Honeypot server (port 5000)
- ✅ Controller (monitors and processes attacks)
- ✅ Dashboard (port 8080)

### Manual Start (Individual Services)

**Terminal 1 - Honeypot:**
```bash
python3 app.py
```
Access at: http://localhost:5000

**Terminal 2 - Controller:**
```bash
python3 controller.py --mode monitor
```

**Terminal 3 - Dashboard:**
```bash
python3 dashboard.py
```
Access at: http://localhost:8080

---

## 🧪 Testing the System

### Step 1: Simulate an Attack

1. Open browser to `http://localhost:5000`
2. Try logging in with fake credentials:
   - Username: `admin`
   - Password: `password123`
3. Click "Login"
4. You'll see "Invalid credentials" (this is the honeypot working!)

### Step 2: Watch the Controller

In the controller terminal, you should see:

```
🔍 NEW ATTEMPT DETECTED
═══════════════════════════════════════
⏰ Time: 2026-02-10 14:32:15
🌐 IP: 127.0.0.1
👤 Username: admin
🔑 Password: ***********

🤖 STEP 1: AI ANALYSIS
─────────────────────────────────────────
🚨 ATTACK DETECTED!
   Severity: HIGH
   Confidence: 89.34%

📤 STEP 2: IPFS STORAGE
─────────────────────────────────────────
✅ Uploaded to IPFS!
   CID: QmX9dE3...
   Size: 437 bytes

⛓️  STEP 3: BLOCKCHAIN STORAGE
─────────────────────────────────────────
✅ Evidence stored on blockchain!

✅ ATTACK EVIDENCE SECURED!
═══════════════════════════════════════
```

### Step 3: View Dashboard

1. Open `http://localhost:8080` in browser
2. You should see:
   - Total attempts: 1
   - Attacks detected: 1
   - Evidence with IPFS link and blockchain TX

### Step 4: Verify Evidence

Click on the IPFS link in the dashboard to view the raw evidence stored on IPFS.

---

## 🔧 Troubleshooting

### Problem: "Module not found" errors

**Solution:**
```bash
pip install -r requirements.txt
```

### Problem: AI model not loading

**Solution:**
```bash
cd ai_module
python3 train_model.py
cd ..
```

### Problem: IPFS upload fails

**Status:** This is normal! System uses fallback local storage.

**To use real IPFS:**
1. Check internet connection
2. Try different IPFS gateways (code will try multiple automatically)
3. Or install local IPFS daemon

### Problem: Blockchain connection error

**Status:** System runs in mock mode automatically.

**To connect to real blockchain:**
1. Verify `blockchain/config.json` exists and is valid
2. Check RPC URL is correct
3. Ensure you have test ETH in wallet
4. Try restarting controller

### Problem: Port already in use

**Solution:**
```bash
# Find and kill process using port 5000
lsof -i :5000  # Get PID
kill -9 <PID>

# Or change port in app.py:
# app.run(host='0.0.0.0', port=5001)  # Use different port
```

### Problem: Dataset download fails

**Solution:**
```bash
# Manual download
wget https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt -O data/NSL-KDD_train.csv
wget https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt -O data/NSL-KDD_test.csv
```

---

## 📊 System Architecture

```
┌─────────────┐
│  Attacker   │
└──────┬──────┘
       │ Attempts Login
       ▼
┌─────────────────┐
│  Honeypot       │ ← Flask Server (Port 5000)
│  (app.py)       │
└────────┬────────┘
         │ Logs Attack
         ▼
┌──────────────────┐
│  honeypot_logs   │ ← JSON File
│  .json           │
└────────┬─────────┘
         │ Monitors
         ▼
┌──────────────────┐
│  Controller      │ ← Integration Logic
│  (controller.py) │
└────────┬─────────┘
         │
    ┌────┴─────┬──────────┬─────────┐
    ▼          ▼          ▼         ▼
┌────────┐ ┌────────┐ ┌────────┐ ┌──────────┐
│   AI   │ │  IPFS  │ │Blockchain│ │Dashboard │
│Predictor│ │Manager │ │ Manager │ │  (8080) │
└────────┘ └────────┘ └────────┘ └──────────┘
```

---

## 🎯 Next Steps

1. **Customize Honeypot**: Edit `templates/login.html` to look like your target system
2. **Expose to Network**: Change `host='0.0.0.0'` to accept external connections
3. **Add More Traps**: Create additional fake services (SSH, FTP, etc.)
4. **Tune AI Model**: Experiment with different ML algorithms
5. **Deploy Smart Contract**: Use Remix IDE to deploy to testnet
6. **Share Intelligence**: Export attack data for threat intelligence platforms

---

## 📞 Support

For issues or questions:
1. Check [README.md](README.md) for general info
2. Review this setup guide
3. Check error logs in console output
4. Verify all dependencies are installed

---

## 🎓 Educational Use

This system is perfect for:
- Cybersecurity courses and research
- Blockchain application demonstrations
- Machine learning in security
- Full-stack development projects
- Academic papers and presentations

---

**🔒 Remember:** Always use honeypots ethically and legally. Ensure you have permission before deploying on any network.

**✅ Setup Complete!** You now have a fully functional Chained Honeypot system!
