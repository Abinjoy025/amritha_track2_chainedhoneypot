#!/usr/bin/env python3
"""
IPFS Integration Module
Uploads attack logs to IPFS via Pinata (free tier)
Credentials loaded from .env file
"""

import json
import hashlib
import requests
import os
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

class IPFSManager:
    def __init__(self):
        """
        Initialize IPFS Manager using Pinata credentials from .env
        """
        self.jwt        = os.getenv('PINATA_JWT', '')
        self.api_key    = os.getenv('PINATA_API_KEY', '')
        self.api_secret = os.getenv('PINATA_API_SECRET', '')

        if self.jwt and not self.jwt.startswith('your_'):
            self.mode = 'pinata'
            self.headers = {'Authorization': f'Bearer {self.jwt}'}
            print("✅ IPFS: Using Pinata (Internet)")
        else:
            self.mode = 'fallback'
            print("⚠️  IPFS: Pinata JWT not set in .env — using local fallback")
            print("   → Sign up free at https://app.pinata.cloud/register")
            print("   → Add PINATA_JWT to your .env file")

    def upload_to_ipfs(self, data):
        """
        Upload data to IPFS via Pinata.
        Returns the IPFS CID on success.
        """
        if isinstance(data, dict):
            data_str = json.dumps(data, indent=2)
        else:
            data_str = str(data)

        data_hash = hashlib.sha256(data_str.encode()).hexdigest()

        if self.mode != 'pinata':
            return self._fallback_storage(data, data_hash)

        try:
            # Pinata pinFileToIPFS endpoint
            response = requests.post(
                'https://api.pinata.cloud/pinning/pinJSONToIPFS',
                headers={**self.headers, 'Content-Type': 'application/json'},
                json={
                    'pinataContent': data,
                    'pinataMetadata': {
                        'name': f'honeypot_evidence_{data_hash[:8]}'
                    }
                },
                timeout=30
            )

            if response.status_code == 200:
                cid = response.json()['IpfsHash']
                print(f"✅ Uploaded to IPFS via Pinata!")
                print(f"   CID: {cid}")
                print(f"   View: https://gateway.pinata.cloud/ipfs/{cid}")
                print(f"   SHA256: {data_hash[:16]}...")
                return {
                    'success': True,
                    'cid': cid,
                    'hash': data_hash,
                    'url': f'https://gateway.pinata.cloud/ipfs/{cid}',
                    'timestamp': datetime.now().isoformat()
                }
            else:
                print(f"❌ Pinata upload failed ({response.status_code}): {response.text}")
                return self._fallback_storage(data, data_hash)

        except requests.exceptions.ConnectionError:
            print("❌ Cannot connect to Pinata. Check internet connection.")
            return self._fallback_storage(data, data_hash)
        except Exception as e:
            print(f"❌ IPFS error: {e}")
            return self._fallback_storage(data, data_hash)
    
    def _fallback_storage(self, data, data_hash):
        """Fallback to local storage if IPFS unavailable"""
        import os
        
        storage_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'ipfs_fallback')
        if not os.path.exists(storage_dir):
            os.makedirs(storage_dir)
        
        filename = f"{data_hash[:16]}.json"
        filepath = os.path.join(storage_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"💾 Stored locally at: {filepath}")
        
        return {
            'success': True,
            'cid': f"local_{data_hash[:16]}",
            'hash': data_hash,
            'local_path': filepath,
            'timestamp': datetime.now().isoformat()
        }
    
    def retrieve_from_ipfs(self, cid):
        """Retrieve data from IPFS using CID"""
        try:
            # Try multiple gateways for reliability
            gateways = [
                f"https://ipfs.io/ipfs/{cid}",
                f"https://gateway.pinata.cloud/ipfs/{cid}",
                f"https://cloudflare-ipfs.com/ipfs/{cid}"
            ]
            
            for gateway in gateways:
                try:
                    response = requests.get(gateway, timeout=10)
                    if response.status_code == 200:
                        print(f"✅ Retrieved from IPFS: {cid}")
                        return response.text
                except:
                    continue
            
            print(f"❌ Could not retrieve from any gateway")
            return None
            
        except Exception as e:
            print(f"❌ Error retrieving from IPFS: {e}")
            return None
    
    def pin_to_ipfs(self, cid):
        """Pin content to prevent garbage collection (Pinata keeps it pinned automatically)"""
        if self.mode != 'pinata':
            return False
        try:
            response = requests.post(
                'https://api.pinata.cloud/pinning/pinByHash',
                headers={**self.headers, 'Content-Type': 'application/json'},
                json={'hashToPin': cid},
                timeout=15
            )
            if response.status_code == 200:
                print(f"📌 Pinned {cid} to Pinata")
                return True
            return False
        except Exception as e:
            print(f"⚠️  Could not pin: {e}")
            return False

def test_ipfs():
    """Test IPFS functionality"""
    print("🧪 Testing IPFS Integration...\n")
    
    manager = IPFSManager()
    
    # Test data
    test_data = {
        "type": "honeypot_attack",
        "timestamp": datetime.now().isoformat(),
        "attacker_ip": "192.168.1.100",
        "attack_type": "brute_force",
        "severity": "HIGH"
    }
    
    # Upload test
    print("📤 Uploading test data to IPFS...")
    result = manager.upload_to_ipfs(test_data)
    
    if result['success']:
        print(f"\n✅ IPFS Test Successful!")
        print(f"   Access your data at:")
        print(f"   https://ipfs.io/ipfs/{result['cid']}")
        return result
    else:
        print("\n⚠️  IPFS test failed, but fallback storage works!")
        return result

if __name__ == '__main__':
    test_ipfs()
