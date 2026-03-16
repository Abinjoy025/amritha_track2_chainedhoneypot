# FREE ACCOUNT CREATION GUIDE
## Blockchain (Sepolia) + IPFS (Pinata) Setup

All external services used by the Chained Honeypot system are available on **100% free tiers**. No credit card is required for basic functionality.

---

## Overview

| Service | Purpose | Free Tier |
|---------|---------|-----------|
| Infura or Alchemy | Sepolia RPC endpoint | 100k–300M req/month |
| MetaMask or eth-account | Ethereum wallet | Free |
| Sepolia faucet | Test ETH | 0.5 ETH/day |
| Pinata | IPFS file pinning | 1 GB storage |

---

## 1. IPFS Storage — Pinata (Recommended)

Pinata provides an easy JWT-based API for pinning files to IPFS. The system uses `PINATA_JWT` from `.env`.

### Create a Free Account

1. Go to https://pinata.cloud
2. Click **Start for Free**
3. Sign up with email (no credit card needed)
4. Verify your email

### Get Your JWT Token

1. Log in to the Pinata dashboard
2. Click your avatar → **API Keys**
3. Click **+ New Key**
4. Enable **pinFileToIPFS** and **pinJSONToIPFS** permissions
5. Name it: `honeypot`
6. Click **Create** — copy the **JWT** token shown (you won't see it again)

### Add to .env

```ini
PINATA_JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.your_token_here
```

### Free Tier Limits

| Limit | Value |
|-------|-------|
| Storage | 1 GB |
| Bandwidth | 50 GB/month |
| Files | Unlimited |
| Cost | $0 |

If you exceed 1 GB, evidence falls back automatically to `data/ipfs_fallback/` locally.

> **Note:** Infura's IPFS service has been deprecated. Use Pinata (recommended), web3.storage, or another pinning service that accepts JWT authentication.

---

## 2. Ethereum RPC — Infura or Alchemy

### Option A: Infura (Recommended)

Free tier: 100,000 requests/day

1. Go to https://infura.io
2. Click **Get Started for Free**
3. Sign up with email — no credit card
4. Dashboard → **Create New Project** → select **Web3 API**
5. Name it: `honeypot`
6. Under **API Keys**, copy the **Sepolia** endpoint:
   ```
   https://sepolia.infura.io/v3/YOUR_PROJECT_ID
   ```

### Option B: Alchemy

Free tier: 300M compute units/month

1. Go to https://alchemy.com
2. Click **Get started free**
3. Dashboard → **+ Create App**
   - Chain: Ethereum
   - Network: Sepolia
   - Name: `honeypot`
4. Click **View Key** → copy the HTTPS endpoint

### Add to .env

```ini
WEB3_PROVIDER_URL=https://sepolia.infura.io/v3/YOUR_PROJECT_ID
```

---

## 3. Ethereum Wallet

You need a wallet to sign transactions that store attack records on Sepolia.

### Option A: MetaMask (Browser Extension)

1. Install: https://metamask.io/download
2. Open MetaMask → **Create a new wallet**
3. Set a password and **write down your 12-word seed phrase on paper**
4. Switch network → enable **Show test networks** → select **Sepolia**
5. Get your private key: Account icon → Account details → **Show private key** → enter password

### Option B: Generate Programmatically (No Browser)

```bash
source venv/bin/activate

python3 -c "
from eth_account import Account
import secrets

key = secrets.token_hex(32)
acc = Account.from_key(key)
print('=' * 60)
print('Address    :', acc.address)
print('Private Key: 0x' + key)
print('=' * 60)
print('SAVE THIS PRIVATE KEY - never share it!')
"
```

### Add to .env

```ini
ETH_PRIVATE_KEY=0xYourPrivateKeyHere
```

> **Security:** The private key is only for Sepolia testnet. It has no real monetary value. Never use a real mainnet key here.

---

## 4. Free Sepolia Test ETH

Transactions on Sepolia require test ETH (no real value). You need approximately 0.01 ETH for hundreds of transactions.

### Faucets (Try Any)

| Faucet | URL | Requires |
|--------|-----|---------|
| Alchemy Faucet | https://sepoliafaucet.com | Alchemy account |
| Infura Faucet | https://www.infura.io/faucet/sepolia | Infura account |
| Google Cloud Faucet | https://cloud.google.com/application/web3/faucet/ethereum/sepolia | Google account |
| POW Faucet (no account) | https://sepolia-faucet.pk910.de | None (browser mining) |

Each faucet gives ~0.5 ETH/day. One transaction costs ~0.001 test ETH, so 0.5 ETH covers 500+ blockchain records.

### Verify Balance

After requesting:
```bash
# Check on Etherscan
https://sepolia.etherscan.io/address/YOUR_WALLET_ADDRESS
```

Or in MetaMask: switch to Sepolia and check the balance.

---

## 5. Deploy the Smart Contract (Optional)

The smart contract `blockchain/AttackEvidenceStorage.sol` must be deployed once. After deployment, save its address to `.env`.

### Using Remix IDE (Free, Browser-Based)

1. Go to https://remix.ethereum.org
2. Upload `blockchain/AttackEvidenceStorage.sol` (or paste its contents)
3. Compile with Solidity ^0.8.20
4. In the **Deploy** tab:
   - Environment: **Injected Provider - MetaMask** (make sure MetaMask is on Sepolia)
   - Click **Deploy** and confirm the transaction in MetaMask
5. Copy the deployed contract address from the **Deployed Contracts** section

### Add to .env

```ini
HONEYPORT_CONTRACT_ADDRESS=0xYourDeployedContractAddress
VITE_CONTRACT_ADDRESS=0xYourDeployedContractAddress
```

### Verify Deployment

```bash
python3 blockchain/blockchain_manager.py
```

Expected:
```
Connected to Ethereum sepolia
Latest block: 7XXXXXX
Contract found at 0xYour...
```

---

## 6. Complete .env Configuration

After completing steps 1–5, your `.env` should look like:

```ini
FLASK_SECRET=some-random-string-here

# IPFS
PINATA_JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Ethereum
WEB3_PROVIDER_URL=https://sepolia.infura.io/v3/abc123def456
HONEYPORT_CONTRACT_ADDRESS=0xDeployedContractAddress
ETH_PRIVATE_KEY=0xYourPrivateKey

# React (for Vite)
VITE_CONTRACT_ADDRESS=0xDeployedContractAddress
VITE_RPC_URL=https://rpc.sepolia.org
VITE_WS_URL=ws://localhost:8000/ws/live

# SOAR
SOAR_CONF_THRESHOLD=0.90
```

---

## 7. Quick Verification

```bash
source venv/bin/activate

# Test IPFS (Pinata)
python3 blockchain/ipfs_manager.py

# Test blockchain connection
python3 blockchain/blockchain_manager.py
```

Expected IPFS output:
```
Pinata JWT found — using Pinata API
Uploading test evidence...
CID: QmXxxxxxxxxxxxxxxx
Access: https://gateway.pinata.cloud/ipfs/QmXxxxxxxxxxxxxxxx
```

Expected blockchain output:
```
Connected to Ethereum sepolia
Latest block: 7XXXXXX
```

---

## Free Tier Summary

| Service | Account | Free Limit | Cost |
|---------|---------|-----------|------|
| Pinata | Required | 1 GB storage, 50 GB bandwidth | $0 |
| Infura | Required | 100,000 req/day | $0 |
| Ethereum Sepolia | No account | Unlimited test transactions | $0 |
| MetaMask/wallet | Optional | N/A | $0 |
| **Total** | | | **$0.00** |

---

## Security Checklist

- `blockchain/config.json` is in `.gitignore` — never commit it
- `.env` is in `.gitignore` — never commit it
- Private key is for Sepolia testnet only — no real value
- Never reuse a testnet private key on Ethereum mainnet
- Store your Pinata JWT securely — it grants write access to your IPFS storage

---

**Setup complete.** You can now run the full Chained Honeypot system with decentralized IPFS evidence and Ethereum blockchain immutability.
