#!/usr/bin/env python3
"""
Chained Honeypot Dashboard - Web-based monitoring interface
Simple Flask dashboard to view attacks and verify evidence
"""

from flask import Flask, render_template, jsonify
import json
import os
from datetime import datetime
import sys
from dotenv import load_dotenv
from collections import defaultdict

load_dotenv()

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blockchain.blockchain_manager import BlockchainManager
from blockchain.ipfs_manager import IPFSManager

app = Flask(__name__)

def load_evidence_summary():
    """Load evidence summary"""
    if not os.path.exists('evidence_summary.json'):
        return []
    
    evidence = []
    with open('evidence_summary.json', 'r') as f:
        for line in f:
            try:
                evidence.append(json.loads(line.strip()))
            except:
                continue
    
    return sorted(evidence, key=lambda x: x.get('timestamp', ''), reverse=True)

def load_honeypot_logs():
    """Load recent honeypot logs"""
    if not os.path.exists('honeypot_logs.json'):
        return []
    logs = []
    with open('honeypot_logs.json', 'r') as f:
        for line in f:
            try:
                logs.append(json.loads(line.strip()))
            except:
                continue
    return sorted(logs, key=lambda x: x.get('timestamp', ''), reverse=True)[:50]


def load_campaigns():
    """Load campaign tracker data"""
    cfile = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         'data', 'campaigns.json')
    try:
        if os.path.exists(cfile):
            with open(cfile, 'r') as f:
                data = json.load(f)
                campaigns = list(data.get('campaigns', {}).values())
                return sorted(campaigns, key=lambda c: c.get('last_seen', ''), reverse=True)
    except Exception:
        pass
    return []


def load_behavioral_profiles():
    """Load behavioral fingerprint profiles"""
    pfile = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         'data', 'behavioral_profiles.json')
    try:
        if os.path.exists(pfile):
            with open(pfile, 'r') as f:
                data = json.load(f)
                profiles = list(data.get('profiles', {}).values())
                return sorted(profiles, key=lambda p: p.get('attempt_count', 0), reverse=True)
    except Exception:
        pass
    return []


@app.route('/')
def dashboard():
    """Main dashboard"""
    evidence  = load_evidence_summary()
    logs      = load_honeypot_logs()
    campaigns = load_campaigns()
    profiles  = load_behavioral_profiles()

    # ── Aggregate new stats ──────────────────────────────────────────────────
    tor_count = len([e for e in evidence if e.get('is_tor')])
    vpn_count = len([e for e in evidence if e.get('is_vpn_or_dc')])

    # top attacker classes
    class_counts: dict = defaultdict(int)
    for e in evidence:
        cls = e.get('attacker_class', 'Unknown')
        if cls:
            class_counts[cls] += 1
    top_classes = sorted(class_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    # top MITRE techniques
    mitre_counts: dict = defaultdict(int)
    for e in evidence:
        for t in (e.get('mitre_techniques') or []):
            mitre_counts[t] += 1
    top_mitre = sorted(mitre_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    stats = {
        'total_attempts':  len(logs),
        'total_attacks':   len(evidence),
        'high_severity':   len([e for e in evidence if e.get('severity') == 'HIGH']),
        'medium_severity': len([e for e in evidence if e.get('severity') == 'MEDIUM']),
        'low_severity':    len([e for e in evidence if e.get('severity') == 'LOW']),
        'tor_attacks':     tor_count,
        'vpn_attacks':     vpn_count,
        'campaigns':       len(campaigns),
    }

    return render_template('dashboard.html',
                           evidence=evidence, logs=logs, stats=stats,
                           campaigns=campaigns, profiles=profiles,
                           top_classes=top_classes, top_mitre=top_mitre)

@app.route('/api/evidence')
def api_evidence():
    """API endpoint for evidence data"""
    return jsonify(load_evidence_summary())

@app.route('/api/logs')
def api_logs():
    """API endpoint for honeypot logs"""
    return jsonify(load_honeypot_logs())

@app.route('/api/campaigns')
def api_campaigns():
    """API endpoint for campaign data"""
    return jsonify(load_campaigns())

@app.route('/api/profiles')
def api_profiles():
    """API endpoint for behavioral profiles"""
    return jsonify(load_behavioral_profiles())

@app.route('/api/verify/<evidence_id>')
def api_verify(evidence_id):
    """Verify evidence on blockchain"""
    try:
        evidence = load_evidence_summary()
        target = next((e for e in evidence if str(e.get('evidence_id')) == evidence_id), None)
        
        if not target:
            return jsonify({'error': 'Evidence not found'}), 404
        
        # Verify with blockchain
        blockchain = BlockchainManager()
        is_valid = blockchain.verify_evidence(
            int(evidence_id),
            target['ipfs_hash']
        )
        
        return jsonify({
            'evidence_id': evidence_id,
            'is_valid': is_valid,
            'verified_at': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🎨 Starting Chained Honeypot Dashboard...")
    port = int(os.getenv('DASHBOARD_PORT', 8080))
    print(f"📍 Access at: http://localhost:{port}")
    print()
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
