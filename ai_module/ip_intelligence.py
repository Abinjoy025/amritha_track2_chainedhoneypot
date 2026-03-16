#!/usr/bin/env python3
"""
IP Intelligence Module  —  ZERO API KEYS REQUIRED
==================================================
Works completely out of the box using:

  1. ip-api.com       → FREE, no key, geo + ASN + org + ISP (45 req/min)
  2. ipwho.is         → FREE fallback geo lookup
  3. Tor exit list    → live from check.torproject.org
  4. FireHOL Level-1  → ~25k known-bad IPs, downloaded & cached locally
  5. ipsum feed       → aggregated threat intel list (500+ sources)
  6. Local VPN/DC ASN keyword matching

Optional (if keys are set in .env they add extra data, but nothing breaks without them):
  ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY

Threat feeds are cached in data/threat_feeds/ and auto-refresh every 24 hours.
"""

import os
import json
import time
import gzip
import hashlib
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

_BASE      = os.path.dirname(os.path.abspath(__file__))
_FEED_DIR  = os.path.join(_BASE, '..', 'data', 'threat_feeds')
os.makedirs(_FEED_DIR, exist_ok=True)

# ── Known VPN / DC / Hosting ASN keywords ─────────────────────────────────────
DC_ASN_KEYWORDS = [
    'amazon', 'aws', 'digitalocean', 'linode', 'akamai', 'cloudflare',
    'ovh', 'hetzner', 'vultr', 'microsoft azure', 'google cloud',
    'ibm cloud', 'alibaba', 'tencent', 'choopa', 'heficed', 'hostinger',
    'contabo', 'scaleway', 'leaseweb', 'quadranet', 'vpn', 'nordvpn',
    'expressvpn', 'surfshark', 'mullvad', 'protonvpn', 'cyberghost',
    'tor project', 'm247', 'privax', 'witopia', 'datacamp', 'tzulo',
    'serverius', 'packethub', 'pegtechinc', 'nexeon', 'incapsula',
    'fastly', 'imperva', 'psychz', 'hostwinds', 'sharktech',
]

# ── Payload → malware family signatures ───────────────────────────────────────
KNOWN_BOTNET_STRINGS = {
    'wget hxxp':       'Botnet dropper wget',
    'curl -s -o':      'Botnet dropper curl',
    'chmod +x':        'Script execution payload',
    '/bin/sh':         'Shell spawn',
    'nc -e':           'Netcat reverse shell',
    '/etc/shadow':     'Password file exfil',
    'bot.sh':          'Bot script dropper',
    'masscan':         'Mass scanner',
    'mirai':           'Mirai botnet variant',
    'xmrig':           'Cryptominer (XMRig)',
    'kinsing':         'Kinsing malware',
    'stratum+tcp':     'Cryptomining pool',
    'base64 -d':       'Obfuscated payload',
    '/dev/null 2>&1':  'Background exec',
}

# ── Threat feed sources (free, no key) ────────────────────────────────────────
THREAT_FEEDS = {
    'firehol_level1': {
        'url':   'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
        'desc':  'FireHOL Level 1 — definitely bad IPs',
        'file':  'firehol_level1.txt',
        'ttl':   86400,   # refresh daily
    },
    'ipsum': {
        'url':   'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
        'desc':  'ipsum — aggregated from 500+ threat intel sources',
        'file':  'ipsum.txt',
        'ttl':   86400,
    },
    'emerging_blocklist': {
        'url':   'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
        'desc':  'Emerging Threats block list',
        'file':  'emerging_block.txt',
        'ttl':   43200,   # 12 hours
    },
}


# ══════════════════════════════════════════════════════════════════════════════
class ThreatFeedManager:
    """
    Downloads and caches FREE threat intelligence feeds locally.
    No API keys required. Auto-refreshes based on each feed's TTL.
    """

    # in-memory IP set (populated at first use)
    _bad_ips:   set  = set()
    _ip_scores: dict = {}    # ip -> score (from ipsum: number of sources)
    _loaded_at: float = 0.0
    _RELOAD_INTERVAL = 3600  # reload memory every hour (re-read from disk)

    def __init__(self):
        self._ensure_feeds()

    def is_known_bad(self, ip: str) -> tuple[bool, int, list]:
        """
        Returns (is_bad, score, feed_names).
        score = number of threat intel sources that list this IP (from ipsum).
        """
        self._maybe_reload()
        score = self._ip_scores.get(ip, 0)
        is_bad = ip in self._bad_ips
        feeds = []
        if is_bad:
            feeds.append('ipsum/FireHOL/ET')
        return is_bad, score, feeds

    # ── Feed download ──────────────────────────────────────────────────────────

    def _ensure_feeds(self):
        """Download any feed that is missing or stale."""
        for name, cfg in THREAT_FEEDS.items():
            fpath = os.path.join(_FEED_DIR, cfg['file'])
            needs_update = (
                not os.path.exists(fpath) or
                time.time() - os.path.getmtime(fpath) > cfg['ttl']
            )
            if needs_update:
                self._download_feed(name, cfg, fpath)

    def _download_feed(self, name: str, cfg: dict, fpath: str):
        try:
            print(f"   📥 Downloading threat feed: {name} ({cfg['desc']})...")
            resp = requests.get(cfg['url'], timeout=15)
            if resp.status_code == 200:
                with open(fpath, 'w') as f:
                    f.write(resp.text)
                print(f"   ✅ {name}: saved ({len(resp.text.splitlines())} lines)")
            else:
                print(f"   ⚠️  {name}: HTTP {resp.status_code}")
        except Exception as e:
            print(f"   ⚠️  {name}: download failed — {e}")

    # ── In-memory reload ───────────────────────────────────────────────────────

    def _maybe_reload(self):
        if time.time() - ThreatFeedManager._loaded_at < self._RELOAD_INTERVAL:
            return
        self._reload_memory()

    def _reload_memory(self):
        bad: set  = set()
        scores: dict = {}

        # ipsum: lines are "IP\tscore" (score = # of sources that list it)
        ipsum_path = os.path.join(_FEED_DIR, 'ipsum.txt')
        if os.path.exists(ipsum_path):
            with open(ipsum_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split()
                    if len(parts) >= 1:
                        ip = parts[0]
                        score = int(parts[1]) if len(parts) >= 2 else 1
                        bad.add(ip)
                        scores[ip] = score

        # firehol_level1: IP or CIDR, plain text
        fhl_path = os.path.join(_FEED_DIR, 'firehol_level1.txt')
        if os.path.exists(fhl_path):
            with open(fhl_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '/' not in line:
                        bad.add(line)

        # emerging threats: same format
        et_path = os.path.join(_FEED_DIR, 'emerging_block.txt')
        if os.path.exists(et_path):
            with open(et_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        bad.add(line.split()[0])

        ThreatFeedManager._bad_ips   = bad
        ThreatFeedManager._ip_scores = scores
        ThreatFeedManager._loaded_at = time.time()
        if bad:
            print(f"   🗂️  Threat feeds loaded: {len(bad):,} known-bad IPs in memory")

    def force_refresh(self):
        """Re-download all feeds and reload."""
        for name, cfg in THREAT_FEEDS.items():
            fpath = os.path.join(_FEED_DIR, cfg['file'])
            self._download_feed(name, cfg, fpath)
        self._reload_memory()

    def status(self) -> dict:
        """Return feed status summary."""
        result = {}
        for name, cfg in THREAT_FEEDS.items():
            fpath = os.path.join(_FEED_DIR, cfg['file'])
            if os.path.exists(fpath):
                age_h = (time.time() - os.path.getmtime(fpath)) / 3600
                result[name] = {'age_hours': round(age_h, 1),
                                'lines': sum(1 for _ in open(fpath))}
            else:
                result[name] = {'age_hours': None, 'lines': 0}
        result['ips_in_memory'] = len(ThreatFeedManager._bad_ips)
        return result


# ══════════════════════════════════════════════════════════════════════════════
class IPIntelligence:
    """
    Full infrastructure intelligence on any IP — no API keys required.

    Data sources (all free, no signup):
      • ip-api.com    → geo, ASN, org, ISP, hosting flag
      • ipwho.is      → fallback geo
      • Tor exit list → torproject.org
      • Local threat feeds (FireHOL + ipsum + Emerging Threats)

    Optional enrichment if .env keys are present:
      • AbuseIPDB  (ABUSEIPDB_API_KEY)
      • VirusTotal (VIRUSTOTAL_API_KEY)
    """

    _cache: dict  = {}
    _CACHE_TTL    = 3600

    _tor_exits:     set   = set()
    _tor_fetched_at: float = 0.0

    _feed_manager: ThreatFeedManager = None

    def __init__(self):
        self.abuseipdb_key  = os.getenv('ABUSEIPDB_API_KEY', '')
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY', '')

        # Lazy-init threat feed manager (downloads feeds on first use)
        if IPIntelligence._feed_manager is None:
            IPIntelligence._feed_manager = ThreatFeedManager()

    # ── Public API ─────────────────────────────────────────────────────────────

    def enrich(self, ip: str) -> dict:
        if self._is_private(ip):
            return self._private_result(ip)

        cached = self._cache.get(ip)
        if cached:
            result, expires = cached
            if time.time() < expires:
                return result

        profile = {
            'ip':               ip,
            'enriched_at':      datetime.utcnow().isoformat() + 'Z',
            'is_tor':           False,
            'is_vpn_or_dc':     False,
            'is_hosting':       False,
            'attacker_class':   'Unknown',
            'risk_score':       0,
            'abuse_confidence': 0,
            'total_reports':    0,
            'threat_score':     0,      # number of intel sources listing this IP
            'country':          'Unknown',
            'country_code':     '',
            'city':             'Unknown',
            'region':           '',
            'asn':              'Unknown',
            'org':              'Unknown',
            'isp':              'Unknown',
            'vt_malicious':     0,
            'vt_detections':    0,
            'known_attack_types': [],
            'last_seen_attack': None,
            'threat_feeds':     [],
        }

        self._enrich_tor(profile)
        self._enrich_geo_free(profile, ip)          # ip-api.com  (no key)
        self._enrich_threat_feeds(profile, ip)      # local feeds (no key)
        self._enrich_abuseipdb(profile, ip)         # optional
        self._enrich_virustotal(profile, ip)        # optional
        self._classify_attacker(profile)

        self._cache[ip] = (profile, time.time() + self._CACHE_TTL)
        return profile

    # ── Tor ───────────────────────────────────────────────────────────────────

    def _enrich_tor(self, profile: dict):
        if time.time() - IPIntelligence._tor_fetched_at > 3600:
            try:
                resp = requests.get(
                    'https://check.torproject.org/torbulkexitlist', timeout=5)
                if resp.status_code == 200:
                    IPIntelligence._tor_exits = set(resp.text.strip().split('\n'))
                    IPIntelligence._tor_fetched_at = time.time()
            except Exception:
                pass
        if profile['ip'] in IPIntelligence._tor_exits:
            profile['is_tor'] = True
            profile['threat_feeds'].append('Tor Exit List')

    # ── ip-api.com  (FREE, no key, 45 req/min) ───────────────────────────────

    def _enrich_geo_free(self, profile: dict, ip: str):
        """
        ip-api.com returns: country, countryCode, region, city, isp, org, as,
        hosting flag (true if VPN/DC/bot).
        Completely free, no API key.
        """
        try:
            fields = 'status,country,countryCode,region,city,isp,org,as,hosting,proxy,mobile'
            resp = requests.get(
                f'http://ip-api.com/json/{ip}',
                params={'fields': fields},
                timeout=5)
            if resp.status_code == 200:
                d = resp.json()
                if d.get('status') == 'success':
                    profile['country']      = d.get('country', 'Unknown')
                    profile['country_code'] = d.get('countryCode', '')
                    profile['region']       = d.get('region', '')
                    profile['city']         = d.get('city', 'Unknown')
                    profile['isp']          = d.get('isp', 'Unknown')
                    profile['org']          = d.get('org', d.get('isp', 'Unknown'))
                    profile['asn']          = d.get('as', 'Unknown')
                    profile['is_hosting']   = bool(d.get('hosting', False))
                    if d.get('proxy'):
                        profile['is_vpn_or_dc'] = True
                        if 'Proxy/VPN' not in profile['threat_feeds']:
                            profile['threat_feeds'].append('ip-api Proxy Detection')
                    if d.get('hosting'):
                        profile['is_vpn_or_dc'] = True
        except Exception:
            # Fallback: ipwho.is (also free, no key)
            self._enrich_geo_fallback(profile, ip)

    def _enrich_geo_fallback(self, profile: dict, ip: str):
        """ipwho.is fallback — free, no key."""
        try:
            resp = requests.get(f'https://ipwho.is/{ip}', timeout=5)
            if resp.status_code == 200:
                d = resp.json()
                if d.get('success'):
                    profile['country']      = d.get('country', 'Unknown')
                    profile['country_code'] = d.get('country_code', '')
                    profile['city']         = d.get('city', 'Unknown')
                    profile['region']       = d.get('region', '')
                    conn = d.get('connection', {})
                    profile['isp']  = conn.get('isp', 'Unknown')
                    profile['org']  = conn.get('org', conn.get('isp', 'Unknown'))
                    profile['asn']  = f"AS{conn.get('asn', '')}"
        except Exception:
            pass

    # ── Local threat feeds (no key) ───────────────────────────────────────────

    def _enrich_threat_feeds(self, profile: dict, ip: str):
        if self._feed_manager is None:
            return
        is_bad, score, feeds = self._feed_manager.is_known_bad(ip)
        if is_bad:
            profile['threat_feeds'].extend(feeds)
            profile['threat_score']     = score
            profile['abuse_confidence'] = min(score * 10, 100)  # rough estimate
            profile['total_reports']    = score

    # ── AbuseIPDB (optional) ──────────────────────────────────────────────────

    def _enrich_abuseipdb(self, profile: dict, ip: str):
        key = self.abuseipdb_key
        if not key or key == 'your_abuseipdb_key_here':
            return
        try:
            resp = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers={'Key': key, 'Accept': 'application/json'},
                params={'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': True},
                timeout=8)
            if resp.status_code == 200:
                d = resp.json().get('data', {})
                profile['abuse_confidence'] = max(
                    profile['abuse_confidence'],
                    d.get('abuseConfidenceScore', 0))
                profile['total_reports'] = max(
                    profile['total_reports'],
                    d.get('totalReports', 0))
                profile['isp']              = d.get('isp', profile['isp'])
                profile['last_seen_attack'] = d.get('lastReportedAt')
                if d.get('abuseConfidenceScore', 0) > 0:
                    if 'AbuseIPDB' not in profile['threat_feeds']:
                        profile['threat_feeds'].append('AbuseIPDB')
                cats = {
                    3:'Fraud', 4:'DDoS', 5:'FTP Brute-Force', 6:'Ping of Death',
                    7:'Phishing', 9:'Open Proxy', 10:'Web Spam', 11:'Email Spam',
                    14:'Port Scan', 15:'Hacking', 18:'Brute-Force', 19:'Bad Web Bot',
                    20:'Exploited Host', 21:'Web App Attack', 22:'SSH', 23:'IoT',
                }
                for r in d.get('reports', [])[:10]:
                    for c in r.get('categories', []):
                        if c in cats and cats[c] not in profile['known_attack_types']:
                            profile['known_attack_types'].append(cats[c])
        except Exception:
            pass

    # ── VirusTotal (optional) ─────────────────────────────────────────────────

    def _enrich_virustotal(self, profile: dict, ip: str):
        key = self.virustotal_key
        if not key or key == 'your_virustotal_api_key_here':
            return
        try:
            resp = requests.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                headers={'x-apikey': key}, timeout=8)
            if resp.status_code == 200:
                stats = (resp.json()
                         .get('data', {})
                         .get('attributes', {})
                         .get('last_analysis_stats', {}))
                profile['vt_malicious']  = stats.get('malicious', 0)
                profile['vt_detections'] = stats.get('malicious', 0) + stats.get('suspicious', 0)
                if profile['vt_malicious'] > 0:
                    if 'VirusTotal' not in profile['threat_feeds']:
                        profile['threat_feeds'].append('VirusTotal')
        except Exception:
            pass

    # ── Attacker classification ───────────────────────────────────────────────

    def _classify_attacker(self, profile: dict):
        org_lower = (profile.get('org', '') + ' ' +
                     profile.get('isp', '') + ' ' +
                     profile.get('asn', '')).lower()

        for kw in DC_ASN_KEYWORDS:
            if kw in org_lower:
                profile['is_vpn_or_dc'] = True
                break

        abuse   = profile['abuse_confidence']
        score   = profile['threat_score']
        is_tor  = profile['is_tor']
        is_dc   = profile['is_vpn_or_dc']
        is_host = profile['is_hosting']
        feeds   = profile['threat_feeds']

        # Risk score (0-100)
        risk = 0
        risk += min(abuse, 50)
        risk += min(score * 5, 30)
        risk += 15 if is_tor  else 0
        risk += 5  if is_dc   else 0
        risk += 5  if is_host else 0
        risk += 10 if len(feeds) >= 2 else (5 if feeds else 0)
        profile['risk_score'] = min(risk, 100)

        if is_tor:
            profile['attacker_class'] = '🧅 Tor User (Anonymous)'
        elif score >= 10:
            profile['attacker_class'] = '☠️  Known Malicious (10+ intel sources)'
        elif score >= 3:
            profile['attacker_class'] = '⚠️  Repeat Offender (3+ intel sources)'
        elif is_dc and abuse > 30:
            profile['attacker_class'] = '🤖 Botnet / Automated (VPS)'
        elif is_dc or is_host:
            profile['attacker_class'] = '☁️  Cloud/VPS/Hosting Actor'
        elif feeds:
            profile['attacker_class'] = '🔍 Known Scanner / Listed Threat'
        else:
            profile['attacker_class'] = '👤 Unknown / Script Kiddie'

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _is_private(ip: str) -> bool:
        import ipaddress
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    @staticmethod
    def _private_result(ip: str) -> dict:
        return {
            'ip': ip, 'enriched_at': datetime.utcnow().isoformat() + 'Z',
            'is_tor': False, 'is_vpn_or_dc': False, 'is_hosting': False,
            'attacker_class': '🏠 Internal / Private IP', 'risk_score': 0,
            'abuse_confidence': 0, 'total_reports': 0, 'threat_score': 0,
            'country': 'Local', 'country_code': '', 'city': 'Local',
            'region': '', 'asn': 'Private', 'org': 'Private Network',
            'isp': 'Private Network', 'vt_malicious': 0, 'vt_detections': 0,
            'known_attack_types': [], 'last_seen_attack': None, 'threat_feeds': [],
        }


# ══════════════════════════════════════════════════════════════════════════════
def fingerprint_payload(payload: str) -> dict:
    """
    Fingerprint a raw payload:
      - SHA256 hash
      - Malware family detection (signature matching)
      - MITRE ATT&CK technique auto-mapping
    """
    if not payload:
        return {}

    sha256  = hashlib.sha256(payload.encode()).hexdigest()
    families = []
    for sig, family in KNOWN_BOTNET_STRINGS.items():
        if sig.lower() in payload.lower():
            families.append(family)

    mitre = []
    p = payload.lower()
    if 'wget' in p or 'curl' in p:
        mitre.append('T1105 – Ingress Tool Transfer')
    if 'chmod' in p:
        mitre.append('T1222 – File Permission Modification')
    if 'nc -e' in p or '/bin/sh' in p:
        mitre.append('T1059 – Command and Scripting Interpreter')
    if '/etc/shadow' in p or '/etc/passwd' in p:
        mitre.append('T1003 – OS Credential Dumping')
    if 'base64' in p:
        mitre.append('T1027 – Obfuscated Files or Information')
    if 'xmrig' in p or 'stratum' in p:
        mitre.append('T1496 – Resource Hijacking (Cryptominer)')
    if '../' in payload or '%2e%2e' in p:
        mitre.append('T1055 – Path Traversal')
    if "or '1'='1" in p or 'union select' in p:
        mitre.append('T1190 – Exploit Public-Facing Application (SQLi)')
    if 'powershell' in p or 'cmd.exe' in p:
        mitre.append('T1059.001 – PowerShell / Windows CMD')

    return {
        'sha256':           sha256,
        'length':           len(payload),
        'malware_families': families,
        'mitre_techniques': mitre,
    }
