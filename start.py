#!/usr/bin/env python3
"""
Quick Start Script - Run the entire Chained Honeypot system
This script starts all components in the correct order
"""

import subprocess
import sys
import time
import os

def print_banner():
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║                                                            ║
    ║        🍯 CHAINED HONEYPOT SYSTEM - QUICK START 🍯        ║
    ║                                                            ║
    ║     Secure Decentralized Deception System                 ║
    ║     AI + IPFS + Blockchain = Tamper-Proof Security        ║
    ║                                                            ║
    ╚════════════════════════════════════════════════════════════╝
    """)

def check_dependencies():
    """Check if required packages are installed"""
    print("🔍 Checking dependencies...")
    
    try:
        import flask
        import sklearn
        import pandas
        import web3
        print("✅ All dependencies installed!")
        return True
    except ImportError as e:
        print(f"❌ Missing dependencies: {e}")
        print("\n📥 Please run: pip install -r requirements.txt")
        return False

def check_model():
    """Check if AI model is trained"""
    print("\n🤖 Checking AI model...")
    
    if os.path.exists('models/random_forest_model.pkl'):
        print("✅ AI model found!")
        return True
    else:
        print("⚠️  AI model not found. Training now...")
        print("   This will take a few minutes...")
        
        # Download dataset
        subprocess.run([sys.executable, 'ai_module/dataset_downloader.py'])
        
        # Train model
        subprocess.run([sys.executable, 'ai_module/train_model.py'])
        
        return os.path.exists('models/random_forest_model.pkl')

def start_honeypot():
    """Start the honeypot server"""
    print("\n🍯 Starting Honeypot Server...")
    print("   Access at: http://localhost:5000")
    print("   Press Ctrl+C to stop all services\n")
    
    return subprocess.Popen(
        [sys.executable, 'app.py'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

def start_controller():
    """Start the controller"""
    print("🎮 Starting Controller...")
    
    return subprocess.Popen(
        [sys.executable, 'controller.py'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

def main():
    print_banner()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check/train AI model
    if not check_model():
        print("❌ Failed to prepare AI model")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("🚀 STARTING ALL SERVICES")
    print("="*60)
    
    processes = []
    
    try:
        # Start honeypot
        honeypot = start_honeypot()
        processes.append(honeypot)
        time.sleep(2)
        
        # Start controller
        controller = start_controller()
        processes.append(controller)
        time.sleep(1)
        
        print("="*60)
        print("✅ ALL SERVICES RUNNING!")
        print("="*60)
        print("\n📋 Access Points:")
        print("   🍯 Honeypot:  http://localhost:5000")
        print("   🔌 API:       http://localhost:8000")
        print("\n💡 Tips:")
        print("   • Try logging into the honeypot with fake credentials")
        print("   • Check the FastAPI backend for real-time attack data")
        print("   • All evidence is automatically stored on IPFS + Blockchain")
        print("\n⚠️  Press Ctrl+C to stop all services")
        print("="*60 + "\n")
        
        # Keep running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n🛑 Stopping all services...")
        
        for process in processes:
            process.terminate()
            process.wait()
        
        print("✅ All services stopped")
        print("👋 Goodbye!")

if __name__ == '__main__':
    main()
