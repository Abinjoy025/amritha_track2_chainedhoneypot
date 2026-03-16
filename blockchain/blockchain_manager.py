#!/usr/bin/env python3
"""
Blockchain Manager for Ethereum Integration
Handles smart contract deployment and interaction
Uses Sepolia Testnet (Free) via Infura or Alchemy
"""

from web3 import Web3
import json
import os
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

class BlockchainManager:
    def __init__(self, network='sepolia'):
        """
        Initialize Blockchain Manager
        
        Networks:
        - 'sepolia': Ethereum Sepolia Testnet (Recommended for testing)
        - 'local': Local Ganache instance
        """
        self.network = network
        self.w3 = None
        self.contract = None
        self.account = None
        
        # Contract ABI (simplified for Python interaction)
        self.contract_abi = [
            {
                "inputs": [
                    {"internalType": "string", "name": "_ipfsCID", "type": "string"},
                    {"internalType": "bytes32", "name": "_dataHash", "type": "bytes32"},
                    {"internalType": "string", "name": "_severity", "type": "string"}
                ],
                "name": "storeEvidence",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "uint256", "name": "_evidenceId", "type": "uint256"}],
                "name": "getEvidence",
                "outputs": [
                    {"internalType": "string", "name": "ipfsCID", "type": "string"},
                    {"internalType": "bytes32", "name": "dataHash", "type": "bytes32"},
                    {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
                    {"internalType": "address", "name": "reporter", "type": "address"},
                    {"internalType": "string", "name": "severity", "type": "string"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "evidenceCount",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]
        
        self._setup_connection()
    
    def _setup_connection(self):
        """Setup Web3 connection"""
        try:
            if self.network == 'local':
                # Local Ganache
                self.w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
                print("🔗 Connecting to local Ganache...")
            else:
                # Load RPC URL from .env
                rpc_url = os.getenv('WEB3_RPC_URL', '')
                private_key = os.getenv('WALLET_PRIVATE_KEY', '')
                contract_address = os.getenv('CONTRACT_ADDRESS', '')

                if not rpc_url or rpc_url.startswith('your_'):
                    print("⚠️  WEB3_RPC_URL not set in .env — using mock mode")
                    print("   → Get a free RPC at https://infura.io or https://alchemy.com")
                    print("   → Add WEB3_RPC_URL to your .env file")
                    self._use_mock_mode()
                    return

                self.w3 = Web3(Web3.HTTPProvider(rpc_url))

                if not self.w3.is_connected():
                    print("❌ Could not connect to RPC. Check WEB3_RPC_URL in .env")
                    self._use_mock_mode()
                    return

                print(f"✅ Connected to Ethereum {self.network}")
                print(f"   Latest block: {self.w3.eth.block_number}")

                # Load wallet
                if private_key and not private_key.startswith('your_'):
                    if not private_key.startswith('0x'):
                        private_key = '0x' + private_key
                    self.account = self.w3.eth.account.from_key(private_key)
                    print(f"✅ Wallet loaded: {self.account.address}")
                else:
                    print("⚠️  WALLET_PRIVATE_KEY not set in .env — read-only mode")

                # Load contract
                if contract_address and not contract_address.startswith('your_') and contract_address != '':
                    self.load_contract(contract_address)
                else:
                    print("⚠️  CONTRACT_ADDRESS not set in .env — transactions will be skipped")
                    self._use_mock_mode()
                    return
            
            if self.w3 and self.w3.is_connected():
                print(f"✅ Connected to local Ganache")
                print(f"   Latest block: {self.w3.eth.block_number}")
            else:
                print("❌ Failed to connect to Ganache")
                self._use_mock_mode()
                
        except Exception as e:
            print(f"❌ Blockchain connection error: {e}")
            self._use_mock_mode()
    
    def _use_mock_mode(self):
        """Use mock mode for testing without actual blockchain"""
        print("🎭 Running in MOCK MODE (no actual blockchain transactions)")
        self.mock_mode = True
        self.mock_evidence = {}
        self.mock_count = 0
    
    def load_contract(self, contract_address):
        """Load existing deployed contract"""
        if hasattr(self, 'mock_mode') and self.mock_mode:
            print("🎭 Mock mode: Contract loaded")
            return True
        
        try:
            self.contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(contract_address),
                abi=self.contract_abi
            )
            print(f"✅ Contract loaded at {contract_address}")
            return True
        except Exception as e:
            print(f"❌ Error loading contract: {e}")
            return False
    
    def store_evidence(self, ipfs_cid, data_hash, severity):
        """
        Store evidence on blockchain
        
        Args:
            ipfs_cid: IPFS Content Identifier
            data_hash: SHA256 hash of the data
            severity: Attack severity (LOW, MEDIUM, HIGH)
        """
        if hasattr(self, 'mock_mode') and self.mock_mode:
            return self._mock_store_evidence(ipfs_cid, data_hash, severity)
        
        try:
            # Convert hash string to bytes32
            hash_bytes = bytes.fromhex(data_hash) if isinstance(data_hash, str) else data_hash
            
            # Build transaction
            tx = self.contract.functions.storeEvidence(
                ipfs_cid,
                hash_bytes,
                severity
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 200000,
                'gasPrice': self.w3.eth.gas_price
            })
            
            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            # Wait for receipt
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            print(f"✅ Evidence stored on blockchain!")
            print(f"   Transaction: {tx_hash.hex()}")
            print(f"   Block: {receipt['blockNumber']}")
            
            return {
                'success': True,
                'tx_hash': tx_hash.hex(),
                'block': receipt['blockNumber']
            }
            
        except Exception as e:
            print(f"❌ Error storing evidence: {e}")
            return {'success': False, 'error': str(e)}
    
    def _mock_store_evidence(self, ipfs_cid, data_hash, severity):
        """Mock version for testing without blockchain"""
        self.mock_count += 1
        evidence_id = self.mock_count
        
        self.mock_evidence[evidence_id] = {
            'ipfs_cid': ipfs_cid,
            'data_hash': data_hash,
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            'block': 'MOCK_BLOCK'
        }
        
        # Save to local file for persistence
        _base = os.path.dirname(os.path.abspath(__file__))
        mock_file = os.path.join(_base, '..', 'data', 'blockchain_mock.json')
        os.makedirs(os.path.dirname(mock_file), exist_ok=True)
        
        with open(mock_file, 'w') as f:
            json.dump(self.mock_evidence, f, indent=2)
        
        print(f"🎭 Mock evidence stored (ID: {evidence_id})")
        print(f"   IPFS CID: {ipfs_cid}")
        print(f"   Hash: {data_hash[:16]}...")
        print(f"   Severity: {severity}")
        
        return {
            'success': True,
            'evidence_id': evidence_id,
            'tx_hash': f'MOCK_TX_{evidence_id}',
            'block': 'MOCK_BLOCK'
        }
    
    def verify_evidence(self, evidence_id, data_hash):
        """Verify evidence hasn't been tampered with"""
        if hasattr(self, 'mock_mode') and self.mock_mode:
            if evidence_id in self.mock_evidence:
                is_valid = self.mock_evidence[evidence_id]['data_hash'] == data_hash
                print(f"🔍 Mock verification: {'✅ VALID' if is_valid else '❌ INVALID'}")
                return is_valid
            return False
        
        try:
            result = self.contract.functions.verifyEvidence(
                evidence_id,
                bytes.fromhex(data_hash)
            ).call()
            
            print(f"🔍 Evidence verification: {'✅ VALID' if result else '❌ INVALID'}")
            return result
        except Exception as e:
            print(f"❌ Error verifying evidence: {e}")
            return False

def setup_instructions():
    """Print setup instructions for users"""
    print("\n" + "="*60)
    print("🔐 BLOCKCHAIN SETUP INSTRUCTIONS (FREE TIER)")
    print("="*60)
    print("\n📋 Option 1: Ethereum Sepolia Testnet (Recommended)")
    print("   Prerequisites:")
    print("   1. Get free RPC endpoint:")
    print("      - Infura: https://infura.io (Sign up, create project)")
    print("      - Alchemy: https://alchemy.com (Sign up, create app)")
    print("   2. Get test ETH:")
    print("      - Sepolia Faucet: https://sepoliafaucet.com")
    print("      - Or: https://faucet.sepolia.dev")
    print("   3. Create a wallet:")
    print("      - MetaMask: https://metamask.io")
    print("      - Or generate with: python -c 'from eth_account import Account; acc = Account.create(); print(f\"Address: {acc.address}\\nPrivate Key: {acc.key.hex()}\")'")
    print("\n📋 Option 2: Local Ganache (For Development)")
    print("   1. Install: npm install -g ganache")
    print("   2. Run: ganache")
    print("   3. Use provided test accounts")
    print("\n💡 Save your configuration in blockchain/config.json:")
    print('   {')
    print('     "rpc_url": "https://sepolia.infura.io/v3/YOUR_PROJECT_ID",')
    print('     "contract_address": "0x...",')
    print('     "private_key": "YOUR_PRIVATE_KEY"')
    print('   }')
    print("="*60 + "\n")

if __name__ == '__main__':
    setup_instructions()
    
    # Test blockchain connection
    print("🧪 Testing blockchain connection...\n")
    manager = BlockchainManager()
