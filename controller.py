#!/usr/bin/env python3
"""
Main Integration Controller - The Brain of the Chained Honeypot
Connects: Honeypot -> AI Analysis -> IPFS Storage -> Blockchain Verification
"""

import json
import time
import os
import sys
import hashlib
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv

load_dotenv()

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_module.predictor import AttackPredictor
from ai_module.packet_capture import PacketCapture
from ai_module.ip_intelligence import IPIntelligence, fingerprint_payload
from ai_module.behavioral_fingerprint import BehavioralFingerprinter
from ai_module.campaign_tracker import CampaignTracker
from ai_module.online_learner import OnlineLearner
from blockchain.ipfs_manager import IPFSManager
from blockchain.blockchain_manager import BlockchainManager

class HoneypotMonitor(FileSystemEventHandler):
    """Monitors honeypot log file for new attacks"""
    
    def __init__(self, controller):
        self.controller = controller
        self.last_position = 0
        
        # Get initial file size
        if os.path.exists(controller.log_file):
            self.last_position = os.path.getsize(controller.log_file)
    
    def on_modified(self, event):
        """Called when log file is modified"""
        if event.src_path.endswith('honeypot_logs.json'):
            self.controller.process_new_logs()

class ChainedHoneypotController:
    """Main controller that orchestrates all components"""
    
    def __init__(self):
        self.log_file = 'honeypot_logs.json'
        self.last_processed_line = 0
        
        print("🚀 Initializing Chained Honeypot System...")
        print("="*60)
        
        # Initialize components
        self.ai_predictor = None
        self.ipfs_manager = None
        self.blockchain_manager = None
        self.packet_capture = None
        self.ip_intelligence = None
        self.behavioral_fp = None
        self.campaign_tracker = None
        self.online_learner = None
        
        self._initialize_components()
        
        # Statistics
        self.stats = {
            'total_attempts': 0,
            'attacks_detected': 0,
            'evidence_stored': 0,
            'start_time': datetime.now()
        }
        
        print("="*60)
        print("✅ System initialized and ready!")
        print()
    
    def _initialize_components(self):
        """Initialize all system components"""
        
        # 1. AI Module
        print("\n1️⃣  Initializing AI Module...")
        try:
            self.ai_predictor = AttackPredictor(model_dir='models')
            if not self.ai_predictor.model:
                print("   ⚠️  AI model not trained yet - will use basic detection")
        except Exception as e:
            print(f"   ⚠️  AI module error: {e}")
            print("   ⚠️  Will use basic heuristic detection")
        
        # 2. Packet Capture
        print("\n2️⃣  Initializing Packet Capture...")
        try:
            honeypot_port = int(os.getenv('HONEYPOT_PORT', 5000))
            self.packet_capture = PacketCapture(honeypot_port=honeypot_port)
            self.packet_capture.start()
            print(f"   ✅ Packet capture active on port {honeypot_port} (requires root)")
        except PermissionError:
            print("   ⚠️  Packet capture needs root — run with sudo for REAL mode")
        except Exception as e:
            print(f"   ⚠️  Packet capture unavailable: {e}")

        # 3. IPFS Module
        print("\n3️⃣  Initializing IPFS Module...")
        try:
            self.ipfs_manager = IPFSManager()
        except Exception as e:
            print(f"   ⚠️  IPFS module error: {e}")
        
        # 4. Blockchain Module
        print("\n4️⃣  Initializing Blockchain Module...")
        try:
            self.blockchain_manager = BlockchainManager(network='sepolia')
        except Exception as e:
            print(f"   ⚠️  Blockchain module error: {e}")

        # 5. IP Intelligence
        print("\n5️⃣  Initializing IP Intelligence...")
        try:
            self.ip_intelligence = IPIntelligence()
            keys = []
            if os.getenv('ABUSEIPDB_API_KEY'): keys.append('AbuseIPDB')
            if os.getenv('VIRUSTOTAL_API_KEY'): keys.append('VirusTotal')
            built_in = 'ip-api + Tor + FireHOL/ipsum/ET feeds'
            print(f"   ✅ IP Intel active. Built-in: {built_in}"
                  f"{('. Extra: ' + ', '.join(keys)) if keys else ''}")
        except Exception as e:
            print(f"   ⚠️  IP Intel error: {e}")

        # 6. Behavioral Fingerprinting
        print("\n6️⃣  Initializing Behavioral Fingerprinter...")
        try:
            self.behavioral_fp = BehavioralFingerprinter()
            print("   ✅ Behavioral fingerprinter ready")
        except Exception as e:
            print(f"   ⚠️  Behavioral fingerprinter error: {e}")

        # 7. Campaign Tracker
        print("\n7️⃣  Initializing Campaign Tracker...")
        try:
            self.campaign_tracker = CampaignTracker()
            print(f"   ✅ Campaign tracker ready ({len(self.campaign_tracker.campaigns)} existing campaigns)")
        except Exception as e:
            print(f"   ⚠️  Campaign tracker error: {e}")

        # 8. Online Learner
        print("\n8️⃣  Initializing Online Learner...")
        try:
            self.online_learner = OnlineLearner(model_dir='models')
            print("   ✅ Online learner ready (auto-retrains every 20 confirmed attacks)")
        except Exception as e:
            print(f"   ⚠️  Online learner error: {e}")
    
    def process_new_logs(self):
        """Process new entries in the honeypot log file"""
        if not os.path.exists(self.log_file):
            return
        
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
                
                # Process only new lines
                new_lines = lines[self.last_processed_line:]
                
                for line in new_lines:
                    if line.strip():
                        try:
                            log_entry = json.loads(line.strip())
                            self.process_attack(log_entry)
                        except json.JSONDecodeError:
                            continue
                
                self.last_processed_line = len(lines)
                
        except Exception as e:
            print(f"❌ Error processing logs: {e}")
    
    def process_attack(self, log_entry):
        """
        Main processing pipeline:
        1. Analyze with AI
        2. Upload to IPFS
        3. Store hash on Blockchain
        """
        self.stats['total_attempts'] += 1
        
        print(f"\n{'='*60}")
        print(f"🔍 NEW ATTEMPT DETECTED")
        print(f"{'='*60}")
        ip = log_entry.get('attacker_ip', 'unknown')
        print(f"⏰ Time:     {log_entry.get('timestamp')}")
        print(f"🌐 IP:       {ip}")
        print(f"👤 Username: {log_entry.get('username_attempt')}")
        print(f"🔑 Password: {'*' * len(log_entry.get('password_attempt', ''))}")
        print(f"🖥️  UA:       {(log_entry.get('user_agent', '') or '')[:80]}")

        # ── IP Intelligence ────────────────────────────────────────────────────
        ip_intel = {}
        if self.ip_intelligence:
            print(f"\n{'─'*60}")
            print("🔍 IP INTELLIGENCE")
            print(f"{'─'*60}")
            try:
                ip_intel = self.ip_intelligence.enrich(ip)
                print(f"   Class:     {ip_intel.get('attacker_class')}")
                print(f"   ASN/Org:   {ip_intel.get('org', 'Unknown')}")
                print(f"   Country:   {ip_intel.get('country', 'Unknown')} / {ip_intel.get('city', '')}")
                print(f"   Risk:      {ip_intel.get('risk_score', 0)}/100")
                print(f"   Abuse:     {ip_intel.get('abuse_confidence', 0)}%  "
                      f"({ip_intel.get('total_reports', 0)} reports)")
                print(f"   Tor:       {'YES ⚠️' if ip_intel.get('is_tor') else 'No'}")
                print(f"   VPN/DC:    {'YES' if ip_intel.get('is_vpn_or_dc') else 'No'}")
                if ip_intel.get('threat_feeds'):
                    print(f"   Feeds:     {', '.join(ip_intel['threat_feeds'])}")
                if ip_intel.get('known_attack_types'):
                    print(f"   Hist:      {', '.join(ip_intel['known_attack_types'][:3])}")
            except Exception as e:
                print(f"   ⚠️ IP intel error: {e}")

        # ── Payload Fingerprinting ─────────────────────────────────────────────
        raw_payload = log_entry.get('raw_payload', '') or ''
        payload_fp = fingerprint_payload(raw_payload)
        if payload_fp:
            print(f"\n   🧬 Payload SHA256: {payload_fp.get('sha256', '')[:16]}...")
            if payload_fp.get('malware_families'):
                print(f"   🦠 Families:  {', '.join(payload_fp['malware_families'])}")
            if payload_fp.get('mitre_techniques'):
                print(f"   🎯 MITRE ATT&CK: {'; '.join(payload_fp['mitre_techniques'][:3])}")

        # ── Behavioral Fingerprinting ──────────────────────────────────────────
        behavior = {}
        if self.behavioral_fp:
            try:
                behavior = self.behavioral_fp.record(log_entry)
                print(f"\n   🔎 Behavior:     {behavior.get('timing_pattern')}")
                print(f"   🎭 Cred strategy:{behavior.get('credential_strategy')}")
                print(f"   🏷️  Tags:         {', '.join(behavior.get('behavior_tags', []))}")
                print(f"   🆔 Fingerprint:  {behavior.get('fingerprint_hash')}")
                related = self.behavioral_fp.find_related_ips(ip)
                if related:
                    print(f"   🔗 Same actor (other IPs): "
                          f"{[r['ip'] for r in related[:5]]}")
            except Exception as e:
                print(f"   ⚠️ Behavioral fp error: {e}")
        
        # Step 1: AI Analysis
        print(f"\n{'─'*60}")
        print("🤖 STEP 1: AI ANALYSIS")
        print(f"{'─'*60}")
        
        is_attack = True
        severity = "MEDIUM"
        confidence = 0.75
        
        if self.ai_predictor and self.ai_predictor.model:
            # Grab real packet features if capture is running
            pkt_features = None
            if self.packet_capture:
                pkt_features = self.packet_capture.get_features(
                    log_entry.get('attacker_ip'))

            result = self.ai_predictor.analyze_honeypot_log(
                log_entry, packet_features=pkt_features)
            if result:
                is_attack    = result['is_attack']
                severity     = result['severity']
                confidence   = result['confidence']
                feature_mode = result.get('feature_mode', 'UNKNOWN')
                attack_label = result.get('attack_label', '')
                print(f"   Feature mode:  {feature_mode}")
                if attack_label:
                    print(f"   Attack type:   {attack_label}")
        else:
            # Basic heuristic detection
            feature_mode = 'RULES_ONLY'
            attack_label = ''
            severity = self._basic_threat_assessment(log_entry)
        
        # ── Campaign Attribution ────────────────────────────────────────────
        campaign = {}
        if self.campaign_tracker and is_attack:
            try:
                campaign = self.campaign_tracker.attribute(
                    ip=ip,
                    behavior=behavior,
                    attack_label=attack_label,
                    payload_fingerprint=payload_fp,
                    ip_intel=ip_intel
                )
                print(f"\n   📁 Campaign: {campaign.get('name')} "
                      f"({len(campaign.get('ips', []))} IPs, "
                      f"{campaign.get('total_attempts', 0)} total attempts)")
            except Exception as e:
                print(f"   ⚠️ Campaign tracker error: {e}")

        if is_attack:
            print(f"🚨 ATTACK DETECTED!")
            print(f"   Severity:   {severity}")
            print(f"   Confidence: {confidence:.2%}")
            self.stats['attacks_detected'] += 1

            # ── Online Learning ────────────────────────────────────────────────
            if self.online_learner:
                try:
                    pkt_feat = (self.packet_capture.get_features(ip)
                                if self.packet_capture else None)
                    self.online_learner.add_sample(
                        log_entry=log_entry,
                        attack_label=attack_label,
                        is_attack=True,
                        packet_features=pkt_feat
                    )
                except Exception as e:
                    print(f"   ⚠️ Online learner error: {e}")

            # Step 2: Upload to IPFS
            print(f"\n{'─'*60}")
            print("📤 STEP 2: IPFS STORAGE")
            print(f"{'─'*60}")

            evidence_data = {
                'log_entry': log_entry,
                'analysis': {
                    'is_attack': is_attack,
                    'severity': severity,
                    'confidence': confidence,
                    'feature_mode': feature_mode,
                    'attack_label': attack_label,
                    'analyzed_at': datetime.now().isoformat()
                },
                'ip_intelligence': ip_intel,
                'payload_fingerprint': payload_fp,
                'behavior': behavior,
                'campaign': {'id': campaign.get('campaign_id'), 'name': campaign.get('name')},
            }
            
            ipfs_result = self.ipfs_manager.upload_to_ipfs(evidence_data)
            
            if ipfs_result['success']:
                # Step 3: Store on Blockchain
                print(f"\n{'─'*60}")
                print("⛓️  STEP 3: BLOCKCHAIN STORAGE")
                print(f"{'─'*60}")
                
                blockchain_result = self.blockchain_manager.store_evidence(
                    ipfs_cid=ipfs_result['cid'],
                    data_hash=ipfs_result['hash'],
                    severity=severity
                )
                
                if blockchain_result['success']:
                    self.stats['evidence_stored'] += 1
                    print(f"\n{'='*60}")
                    print(f"✅ ATTACK EVIDENCE SECURED!")
                    print(f"{'='*60}")
                    print(f"📦 IPFS CID: {ipfs_result['cid']}")
                    print(f"🔗 Blockchain TX: {blockchain_result.get('tx_hash', 'N/A')}")
                    print(f"🔒 Evidence ID: {blockchain_result.get('evidence_id', 'N/A')}")
                    
                    # Save summary
                    self._save_evidence_summary(
                        log_entry, ipfs_result, blockchain_result,
                        severity, ip_intel, behavior, payload_fp, campaign, attack_label)
        else:
            print(f"✅ Benign activity (Confidence: {confidence:.2%})")
    
    def _basic_threat_assessment(self, log_entry):
        """Basic heuristic threat assessment when AI is not available"""
        username = log_entry.get('username_attempt', '').lower()
        password = log_entry.get('password_attempt', '')
        
        # Check for common attack patterns
        high_risk_usernames = ['admin', 'root', 'administrator', 'sa', 'postgres']
        medium_risk_usernames = ['user', 'test', 'guest', 'webadmin']
        common_passwords = ['password', '123456', 'admin', 'root', '12345678', 'qwerty']
        
        if username in high_risk_usernames and password.lower() in common_passwords:
            return "HIGH"
        elif username in medium_risk_usernames:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _save_evidence_summary(self, log_entry, ipfs_result, blockchain_result,
                               severity, ip_intel=None, behavior=None,
                               payload_fp=None, campaign=None, attack_label=''):
        """Save a summary of all evidence for easy reference"""
        summary_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'evidence_summary.json')

        summary = {
            'timestamp':      datetime.now().isoformat(),
            'attacker_ip':    log_entry.get('attacker_ip'),
            'username':       log_entry.get('username_attempt', ''),
            'severity':       severity,
            'attack_label':   attack_label,
            'ipfs_cid':       ipfs_result['cid'],
            'ipfs_hash':      ipfs_result['hash'],
            'blockchain_tx':  blockchain_result.get('tx_hash'),
            'evidence_id':    blockchain_result.get('evidence_id'),
            # IP intelligence
            'attacker_class': (ip_intel or {}).get('attacker_class', ''),
            'country':        (ip_intel or {}).get('country', ''),
            'org':            (ip_intel or {}).get('org', ''),
            'risk_score':     (ip_intel or {}).get('risk_score', 0),
            'is_tor':         (ip_intel or {}).get('is_tor', False),
            'is_vpn_or_dc':   (ip_intel or {}).get('is_vpn_or_dc', False),
            'threat_feeds':   (ip_intel or {}).get('threat_feeds', []),
            # Behavior
            'timing_pattern':      (behavior or {}).get('timing_pattern', ''),
            'credential_strategy': (behavior or {}).get('credential_strategy', ''),
            'behavior_tags':       (behavior or {}).get('behavior_tags', []),
            'fingerprint_hash':    (behavior or {}).get('fingerprint_hash', ''),
            # Payload
            'payload_sha256':    (payload_fp or {}).get('sha256', ''),
            'mitre_techniques':  (payload_fp or {}).get('mitre_techniques', []),
            'malware_families':  (payload_fp or {}).get('malware_families', []),
            # Campaign
            'campaign_id':   (campaign or {}).get('campaign_id', ''),
            'campaign_name': (campaign or {}).get('name', ''),
            'campaign_ips':  (campaign or {}).get('ips', []),
        }
        
        # Append to summary file (use fallback name if root-owned)
        try:
            if os.path.exists(summary_file) and not os.access(summary_file, os.W_OK):
                summary_file = summary_file.replace('.json', '_new.json')
            with open(summary_file, 'a') as f:
                json.dump(summary, f)
                f.write('\n')
        except Exception as e:
            print(f"   ⚠️  Could not write evidence summary: {e}")
    
    def print_statistics(self):
        """Print system statistics"""
        uptime = datetime.now() - self.stats['start_time']
        
        print(f"\n{'='*60}")
        print("📊 SYSTEM STATISTICS")
        print(f"{'='*60}")
        print(f"⏱️  Uptime: {uptime}")
        print(f"📈 Total Attempts: {self.stats['total_attempts']}")
        print(f"🚨 Attacks Detected: {self.stats['attacks_detected']}")
        print(f"🔒 Evidence Stored: {self.stats['evidence_stored']}")
        
        if self.stats['total_attempts'] > 0:
            detection_rate = (self.stats['attacks_detected'] / self.stats['total_attempts']) * 100
            print(f"📊 Detection Rate: {detection_rate:.1f}%")
        
        print(f"{'='*60}\n")
    
    def run_monitor(self):
        """Run continuous monitoring"""
        print("👀 Starting continuous monitoring...")
        print("   Watching for new honeypot logs...")
        print("   Press Ctrl+C to stop\n")
        
        # First process any existing logs
        self.process_new_logs()
        
        # Setup file watcher
        event_handler = HoneypotMonitor(self)
        observer = Observer()
        observer.schedule(event_handler, path='.', recursive=False)
        observer.start()
        
        try:
            while True:
                time.sleep(10)
                self.print_statistics()
        except KeyboardInterrupt:
            print("\n\n🛑 Stopping monitor...")
            observer.stop()
            if self.packet_capture:
                self.packet_capture.stop()
        
        observer.join()
        self.print_statistics()
        print("👋 Monitor stopped.")
    
    def run_batch_analysis(self):
        """Run one-time analysis of all existing logs"""
        print("🔄 Running batch analysis of existing logs...\n")
        self.process_new_logs()
        self.print_statistics()

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Chained Honeypot Controller')
    parser.add_argument('--mode', choices=['monitor', 'batch'], default='monitor',
                        help='Run mode: monitor (continuous) or batch (one-time)')
    
    args = parser.parse_args()
    
    controller = ChainedHoneypotController()
    
    if args.mode == 'monitor':
        controller.run_monitor()
    else:
        controller.run_batch_analysis()

if __name__ == '__main__':
    main()
