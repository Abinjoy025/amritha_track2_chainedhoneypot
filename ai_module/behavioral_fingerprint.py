#!/usr/bin/env python3
"""
Behavioral Fingerprinting Module
=================================
VPN hides location — but NOT behavior.
Track and fingerprint attacker behavior across sessions:
  - Attack timing patterns (burst / slow / scheduled)
  - Credential patterns (wordlist, keyboard-walk, targeted)
  - User-Agent fingerprint
  - Payload structure similarity
  - Repeated command sequences → link multiple IPs to same actor

Persists state to data/behavioral_profiles.json so patterns survive restarts.
"""

import os
import json
import hashlib
import statistics
from datetime import datetime, timedelta
from collections import defaultdict
from difflib import SequenceMatcher


_PROFILES_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..', 'data', 'behavioral_profiles.json'
)


class BehavioralFingerprinter:
    """
    Maintains per-IP behavioral profiles and detects patterns.
    """

    def __init__(self):
        self.profiles: dict = {}       # ip -> profile dict
        self.sessions: dict = {}       # ip -> list of event timestamps
        self._load()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self):
        try:
            if os.path.exists(_PROFILES_FILE):
                with open(_PROFILES_FILE, 'r') as f:
                    data = json.load(f)
                    self.profiles = data.get('profiles', {})
        except Exception:
            self.profiles = {}

    def _save(self):
        try:
            os.makedirs(os.path.dirname(_PROFILES_FILE), exist_ok=True)
            with open(_PROFILES_FILE, 'w') as f:
                json.dump({'profiles': self.profiles,
                           'updated': datetime.utcnow().isoformat()}, f, indent=2)
        except Exception:
            pass

    # ── Main API ──────────────────────────────────────────────────────────────

    def record(self, log_entry: dict) -> dict:
        """
        Record a new event from a log entry and return behavioral analysis.
        """
        ip        = log_entry.get('attacker_ip', 'unknown')
        ts_str    = log_entry.get('timestamp', datetime.utcnow().isoformat())
        username  = log_entry.get('username_attempt', '')
        password  = log_entry.get('password_attempt', '')
        user_agent = log_entry.get('user_agent', '')
        payload   = log_entry.get('raw_payload', '') or ''
        headers   = log_entry.get('request_headers', {}) or {}

        # Parse timestamp
        try:
            ts = datetime.fromisoformat(ts_str)
        except Exception:
            ts = datetime.utcnow()

        # Initialize profile
        if ip not in self.profiles:
            self.profiles[ip] = {
                'ip': ip,
                'first_seen': ts.isoformat(),
                'last_seen': ts.isoformat(),
                'attempt_count': 0,
                'usernames_tried': [],
                'passwords_tried': [],
                'user_agents': [],
                'payloads': [],
                'timestamps': [],
                'timing_pattern': 'Unknown',
                'credential_strategy': 'Unknown',
                'behavior_tags': [],
                'fingerprint_hash': '',
            }

        p = self.profiles[ip]
        p['attempt_count'] += 1
        p['last_seen'] = ts.isoformat()
        p['timestamps'].append(ts.isoformat())

        # Store unique values (cap at last 100)
        if username and username not in p['usernames_tried']:
            p['usernames_tried'].append(username)
        if password and password not in p['passwords_tried']:
            p['passwords_tried'].append(password)
        if user_agent and user_agent not in p['user_agents']:
            p['user_agents'].append(user_agent)
        if payload and payload not in p['payloads']:
            p['payloads'].append(payload[:500])   # truncate long payloads

        # Cap lists
        for k in ('usernames_tried', 'passwords_tried', 'user_agents', 'payloads', 'timestamps'):
            p[k] = p[k][-100:]

        # Analyze patterns
        p['timing_pattern']       = self._timing_pattern(p['timestamps'])
        p['credential_strategy']  = self._credential_strategy(p)
        p['behavior_tags']        = self._behavior_tags(p)
        p['fingerprint_hash']     = self._fingerprint_hash(p)

        self._save()

        return {
            'ip': ip,
            'attempt_count': p['attempt_count'],
            'timing_pattern': p['timing_pattern'],
            'credential_strategy': p['credential_strategy'],
            'behavior_tags': p['behavior_tags'],
            'fingerprint_hash': p['fingerprint_hash'],
            'user_agents_seen': list(set(p['user_agents'])),
            'unique_usernames': len(p['usernames_tried']),
            'unique_passwords': len(p['passwords_tried']),
        }

    def get_profile(self, ip: str) -> dict:
        return self.profiles.get(ip, {})

    # ── Analysis Methods ──────────────────────────────────────────────────────

    def _timing_pattern(self, timestamps: list) -> str:
        """Classify timing pattern from list of ISO timestamp strings."""
        if len(timestamps) < 2:
            return 'Single Attempt'

        try:
            times = sorted([datetime.fromisoformat(t) for t in timestamps])
            gaps  = [(times[i+1] - times[i]).total_seconds()
                     for i in range(len(times)-1)]
            avg_gap = statistics.mean(gaps)
            stdev   = statistics.stdev(gaps) if len(gaps) > 1 else 0

            if avg_gap < 1:
                return '⚡ Machine Speed (< 1s) — Automated'
            elif avg_gap < 5:
                return '🤖 Rapid Burst (< 5s) — Automated'
            elif stdev < avg_gap * 0.15:
                return '⏱️  Regular Interval — Scripted/Scheduled'
            elif avg_gap > 300:
                return '🐢 Slow / Low-and-Slow (> 5 min)'
            else:
                return '🔁 Moderate Rate — Manual or Slow Script'
        except Exception:
            return 'Unknown'

    def _credential_strategy(self, p: dict) -> str:
        """Identify credential attack strategy."""
        usernames = p['usernames_tried']
        passwords = p['passwords_tried']

        if len(usernames) == 1 and len(passwords) > 3:
            return '🔑 Password Spray (single user)'
        elif len(usernames) > 5 and len(passwords) > 5:
            return '📚 Credential Stuffing (wordlist)'
        elif len(usernames) > 1 and len(passwords) == 1:
            return '🎯 Username Enumeration'
        elif len(usernames) == 1 and len(passwords) == 1:
            return '🎯 Targeted (specific credentials)'
        elif len(passwords) > 0:
            top_pass = passwords[0] if passwords else ''
            if _is_keyboard_walk(top_pass):
                return '⌨️  Keyboard-Walk Passwords'
        return '📋 Mixed Credential Attack'

    def _behavior_tags(self, p: dict) -> list:
        """Assign behavior tags based on profile data."""
        tags = []
        if p['attempt_count'] >= 50:
            tags.append('HIGH_VOLUME')
        if p['attempt_count'] >= 5:
            tags.append('REPEAT_ATTACKER')
        if any('../' in pw for pw in p['passwords_tried']):
            tags.append('PATH_TRAVERSAL')
        if any('select' in pw.lower() or 'union' in pw.lower()
               for pw in p['passwords_tried']):
            tags.append('SQL_INJECTION')
        if any(len(pw) > 200 for pw in p['passwords_tried']):
            tags.append('BUFFER_OVERFLOW_ATTEMPT')
        if any('nc -e' in pw or '/bin/sh' in pw for pw in p['passwords_tried']):
            tags.append('REVERSE_SHELL')
        if any(pw.lower() in p['passwords_tried']
               for pw in ['password','123456','admin','root']):
            tags.append('DEFAULT_CREDENTIALS')
        if len(p['user_agents']) > 3:
            tags.append('ROTATING_USER_AGENT')
        ua_lower = ' '.join(p['user_agents']).lower()
        if 'python' in ua_lower or 'curl' in ua_lower or 'wget' in ua_lower:
            tags.append('AUTOMATED_TOOL')
        if 'sqlmap' in ua_lower:
            tags.append('SQLMAP')
        if 'nikto' in ua_lower:
            tags.append('NIKTO_SCANNER')
        if 'hydra' in ua_lower or 'medusa' in ua_lower:
            tags.append('CREDENTIAL_BRUTEFORCE_TOOL')
        return list(set(tags))

    def _fingerprint_hash(self, p: dict) -> str:
        """
        Create a behavioral fingerprint hash:
        same hash across different IPs → same attacker/campaign.
        Based on: UA pattern + username set + password pattern.
        """
        components = []

        # Top 3 usernames (sorted for stability)
        components.append('|'.join(sorted(p['usernames_tried'][:3])))

        # Password "shape" (length classes, not actual passwords)
        pw_shapes = sorted(set(_password_shape(pw) for pw in p['passwords_tried'][:5]))
        components.append('|'.join(pw_shapes))

        # Sanitized user-agent (remove version noise)
        for ua in p['user_agents'][:1]:
            components.append(_sanitize_ua(ua))

        combined = '::'.join(components)
        return hashlib.sha256(combined.encode()).hexdigest()[:16]

    # ── Cross-IP correlation ──────────────────────────────────────────────────

    def find_related_ips(self, ip: str) -> list:
        """
        Find other IPs with the same behavioral fingerprint.
        Returns list of (ip, fingerprint_hash) tuples.
        """
        target_hash = self.profiles.get(ip, {}).get('fingerprint_hash', '')
        if not target_hash:
            return []

        related = []
        for other_ip, profile in self.profiles.items():
            if other_ip != ip and profile.get('fingerprint_hash') == target_hash:
                related.append({
                    'ip': other_ip,
                    'fingerprint_hash': target_hash,
                    'attempts': profile['attempt_count'],
                    'first_seen': profile['first_seen'],
                })
        return related

    def payload_similarity(self, payload_a: str, payload_b: str) -> float:
        """Return 0.0-1.0 similarity between two payloads."""
        if not payload_a or not payload_b:
            return 0.0
        return SequenceMatcher(None, payload_a, payload_b).ratio()


# ── Utility helpers ────────────────────────────────────────────────────────────

def _is_keyboard_walk(s: str) -> bool:
    walks = ['qwerty', 'qwertz', 'azerty', '1234', 'asdf', 'zxcv']
    return any(w in s.lower() for w in walks)


def _password_shape(pw: str) -> str:
    """Convert password to a shape string: A=uppercase, a=lower, 1=digit, @=special"""
    shape = ''
    for c in pw[:20]:
        if c.isupper():    shape += 'A'
        elif c.islower():  shape += 'a'
        elif c.isdigit():  shape += '1'
        else:              shape += '@'
    return shape


def _sanitize_ua(ua: str) -> str:
    """Remove version numbers to get a stable UA class."""
    import re
    return re.sub(r'[\d.]+', 'V', ua.split('(')[0].strip())
