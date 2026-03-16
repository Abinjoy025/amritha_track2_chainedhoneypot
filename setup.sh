#!/bin/bash

# Chained Honeypot System - Setup Script
# Automated installation and configuration

echo "🍯 Chained Honeypot System - Setup"
echo "===================================="
echo ""

# Check Python version
echo "🐍 Checking Python version..."
python3 --version

# Create virtual environment (optional but recommended)
echo ""
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo ""
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo ""
echo "📥 Installing Python dependencies..."
pip install -r requirements.txt

# Create necessary directories
echo ""
echo "📁 Creating directories..."
mkdir -p data models logs blockchain/contracts

# Download and prepare dataset
echo ""
echo "📊 Downloading NSL-KDD dataset..."
cd ai_module
python3 dataset_downloader.py
cd ..

# Train the AI model
echo ""
echo "🤖 Training AI model (this may take a few minutes)..."
cd ai_module
python3 train_model.py
cd ..

# Setup complete
echo ""
echo "✅ Setup complete!"
echo ""
echo "📋 Next Steps:"
echo "─────────────────────────────────────────────────"
echo ""
echo "1️⃣  Configure Blockchain (Optional):"
echo "   - Create a free account at https://infura.io or https://alchemy.com"
echo "   - Get Sepolia testnet RPC URL"
echo "   - Get test ETH from https://sepoliafaucet.com"
echo "   - Add config to blockchain/config.json:"
echo "     {"
echo "       \"rpc_url\": \"https://sepolia.infura.io/v3/YOUR_PROJECT_ID\","
echo "       \"private_key\": \"YOUR_PRIVATE_KEY\""
echo "     }"
echo ""
echo "2️⃣  Start the Honeypot:"
echo "   python3 app.py"
echo "   (Access at http://localhost:5000)"
echo ""
echo "3️⃣  Start the Controller (in a new terminal):"
echo "   python3 controller.py --mode monitor"
echo ""
echo "4️⃣  Start the Dashboard (optional, in a new terminal):"
echo "   python3 dashboard.py"
echo "   (Access at http://localhost:8080)"
echo ""
echo "─────────────────────────────────────────────────"
echo "🎉 Happy Honeypotting!"
