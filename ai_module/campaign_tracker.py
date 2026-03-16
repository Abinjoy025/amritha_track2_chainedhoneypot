#!/usr/bin/env python3
"""
Campaign Tracker
================
Group attacks into campaigns based on:
  - Same behavioral fingerprint (same attacker through VPN rotation)
  - Same payload/command patterns
  - Same tool signatures
  - MITRE ATT&CK TTP clustering

Follows modern SOC methodology: track campaigns, not individuals.
Persists campaign data to data/campaigns.json.
"""

import os
import json
import hashlib
from datetime import datetime
from collections import defaultdict

_CAMPAIGNS_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..', 'data', 'campaigns.json'
)


class CampaignTracker:

    def __init__(self):
        self.campaigns: dict = {}       # campaign_id -> campaign dict
        self.ip_to_campaign: dict = {}  # ip -> campaign_id
        self._load()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self):
        try:
            if os.path.exists(_CAMPAIGNS_FILE):
                with open(_CAMPAIGNS_FILE, 'r') as f:
                    data = json.load(f)
                    self.campaigns      = data.get('campaigns', {})
                    self.ip_to_campaign = data.get('ip_to_campaign', {})
        except Exception:
            self.campaigns = {}
            self.ip_to_campaign = {}

    def _save(self):
        try:
            os.makedirs(os.path.dirname(_CAMPAIGNS_FILE), exist_ok=True)
            with open(_CAMPAIGNS_FILE, 'w') as f:
                json.dump({
                    'campaigns': self.campaigns,
                    'ip_to_campaign': self.ip_to_campaign,
                    'updated': datetime.utcnow().isoformat(),
                }, f, indent=2)
        except Exception:
            pass

    # ── Main API ──────────────────────────────────────────────────────────────

    def attribute(self, ip: str, behavior: dict, attack_label: str,
                  payload_fingerprint: dict, ip_intel: dict) -> dict:
        """
        Attribute an attack event to a campaign.
        Returns the campaign dict.
        """
        fingerprint_hash = behavior.get('fingerprint_hash', '')
        behavior_tags    = behavior.get('behavior_tags', [])
        mitre_techniques = payload_fingerprint.get('mitre_techniques', [])
        malware_families = payload_fingerprint.get('malware_families', [])

        # Find existing campaign by fingerprint or IP
        campaign_id = self._find_campaign(ip, fingerprint_hash, mitre_techniques, malware_families)

        if campaign_id is None:
            campaign_id = self._new_campaign(ip, fingerprint_hash, attack_label,
                                              behavior_tags, mitre_techniques,
                                              malware_families, ip_intel)
        else:
            self._update_campaign(campaign_id, ip, attack_label,
                                  behavior_tags, mitre_techniques,
                                  malware_families, ip_intel)

        self.ip_to_campaign[ip] = campaign_id
        self._save()

        return self.campaigns[campaign_id]

    def get_campaign_for_ip(self, ip: str) -> dict:
        cid = self.ip_to_campaign.get(ip)
        if cid:
            return self.campaigns.get(cid, {})
        return {}

    def list_campaigns(self) -> list:
        return sorted(self.campaigns.values(),
                      key=lambda c: c.get('last_seen', ''), reverse=True)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _find_campaign(self, ip: str, fingerprint_hash: str,
                       mitre: list, families: list) -> str | None:
        # 1. Direct IP membership
        if ip in self.ip_to_campaign:
            return self.ip_to_campaign[ip]

        # 2. Matching fingerprint hash
        if fingerprint_hash:
            for cid, c in self.campaigns.items():
                if fingerprint_hash in c.get('fingerprint_hashes', []):
                    return cid

        # 3. Same malware family
        if families:
            for cid, c in self.campaigns.items():
                existing = set(c.get('malware_families', []))
                if existing & set(families):
                    return cid

        # 4. Mostly overlapping MITRE TTPs
        if len(mitre) >= 2:
            for cid, c in self.campaigns.items():
                existing = set(c.get('mitre_techniques', []))
                if len(existing & set(mitre)) >= 2:
                    return cid

        return None

    def _new_campaign(self, ip, fingerprint_hash, attack_label,
                       behavior_tags, mitre, families, ip_intel) -> str:
        """Create a new campaign and return its ID."""
        now = datetime.utcnow().isoformat()
        # Campaign ID: short hash of first IP + timestamp
        cid = hashlib.sha256(f'{ip}{now}'.encode()).hexdigest()[:12]

        attacker_class = ip_intel.get('attacker_class', 'Unknown')
        country        = ip_intel.get('country', 'Unknown')

        self.campaigns[cid] = {
            'campaign_id': cid,
            'name': f'Campaign-{cid[:6]}',
            'first_seen': now,
            'last_seen': now,
            'ips': [ip],
            'fingerprint_hashes': [fingerprint_hash] if fingerprint_hash else [],
            'attack_types': [attack_label] if attack_label else [],
            'behavior_tags': behavior_tags,
            'mitre_techniques': mitre,
            'malware_families': families,
            'attacker_classes': [attacker_class],
            'countries': [country],
            'total_attempts': 1,
            'severity_peak': 'LOW',
        }
        return cid

    def _update_campaign(self, cid, ip, attack_label,
                          behavior_tags, mitre, families, ip_intel):
        """Update an existing campaign with new event data."""
        c = self.campaigns[cid]
        now = datetime.utcnow().isoformat()

        c['last_seen'] = now
        c['total_attempts'] = c.get('total_attempts', 0) + 1

        if ip not in c['ips']:
            c['ips'].append(ip)
        if attack_label and attack_label not in c['attack_types']:
            c['attack_types'].append(attack_label)
        for t in behavior_tags:
            if t not in c['behavior_tags']:
                c['behavior_tags'].append(t)
        for t in mitre:
            if t not in c['mitre_techniques']:
                c['mitre_techniques'].append(t)
        for f in families:
            if f not in c['malware_families']:
                c['malware_families'].append(f)

        attacker_class = ip_intel.get('attacker_class', 'Unknown')
        country        = ip_intel.get('country', 'Unknown')
        if attacker_class not in c['attacker_classes']:
            c['attacker_classes'].append(attacker_class)
        if country not in c['countries']:
            c['countries'].append(country)
