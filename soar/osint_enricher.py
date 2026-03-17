#!/usr/bin/env python3
"""
soar/osint_enricher.py
───────────────────────
Phase 3  – OSINT Enrichment

The moment an IP is routed to the honeypot, this module fires requests to:
  • AbuseIPDB  – threat score, reports count, usage type
  • Shodan     – open ports, tags (e.g. "Mirai", "scanner")

Returns a merged OsintResult dataclass with a unified threat_score (0‒100).
Falls back gracefully when API keys are absent or rate-limits are hit.
"""

from __future__ import annotations

import ipaddress
import os
import time
import logging
from dataclasses import dataclass, field
from typing import Optional

import requests

log = logging.getLogger(__name__)

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
SHODAN_KEY    = os.getenv("SHODAN_API_KEY", "")

CACHE: dict[str, "OsintResult"] = {}        # simple in-process TTL cache
CACHE_TTL = 3600                             # seconds


@dataclass
class OsintResult:
    ip:            str
    threat_score:  int   = 0          # 0–100  (AbuseIPDB confidence)
    country_code:  str   = ""
    isp:           str   = ""
    usage_type:    str   = ""         # e.g. "Data Center/Web Hosting/Transit"
    abuse_reports: int   = 0
    shodan_tags:   list  = field(default_factory=list)   # ["mirai", "scanner"]
    open_ports:    list  = field(default_factory=list)   # [22, 80, 443]
    hostnames:     list  = field(default_factory=list)
    is_tor:        bool  = False
    is_vpn:        bool  = False
    label:         str   = ""         # human-readable summary
    timestamp:     float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "ip":            self.ip,
            "threat_score":  self.threat_score,
            "country_code":  self.country_code,
            "isp":           self.isp,
            "usage_type":    self.usage_type,
            "abuse_reports": self.abuse_reports,
            "shodan_tags":   self.shodan_tags,
            "open_ports":    self.open_ports,
            "hostnames":     self.hostnames,
            "is_tor":        self.is_tor,
            "is_vpn":        self.is_vpn,
            "label":         self.label,
        }


def _query_abuseipdb(ip: str) -> dict:
    """Return AbuseIPDB check response JSON or empty dict."""
    if not ABUSEIPDB_KEY:
        return {}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json().get("data", {})
    except Exception as exc:
        log.warning("AbuseIPDB query failed for %s: %s", ip, exc)
        return {}


def _query_shodan(ip: str) -> dict:
    """Return Shodan host info dict or empty dict."""
    if not SHODAN_KEY:
        return {}
    try:
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_KEY},
            timeout=8,
        )
        if resp.status_code == 404:
            return {}
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        log.warning("Shodan query failed for %s: %s", ip, exc)
        return {}


def enrich(ip: str) -> OsintResult:
    """
    Full OSINT lookup for an IP.  Results are cached for CACHE_TTL seconds.
    """
    # Skip external API calls for private/loopback/reserved IPs — they have
    # no AbuseIPDB or Shodan records and the calls would just hang/timeout.
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_unspecified:
            result = OsintResult(ip=ip, label="Reserved/Private")
            CACHE[ip] = result
            return result
    except ValueError:
        pass  # invalid IP string, let it proceed and fail gracefully

    if ip in CACHE and (time.time() - CACHE[ip].timestamp) < CACHE_TTL:
        return CACHE[ip]

    result = OsintResult(ip=ip)

    # ── AbuseIPDB ──────────────────────────────────────────────────────────
    abuse = _query_abuseipdb(ip)
    if abuse:
        result.threat_score  = int(abuse.get("abuseConfidenceScore", 0))
        result.country_code  = abuse.get("countryCode", "")
        result.isp           = abuse.get("isp", "")
        result.usage_type    = abuse.get("usageType", "")
        result.abuse_reports = int(abuse.get("totalReports", 0))
        result.is_tor        = bool(abuse.get("isTor", False))
        result.hostnames     = [h for h in [abuse.get("domain", "")] if h]

    # ── Shodan ─────────────────────────────────────────────────────────────
    shodan = _query_shodan(ip)
    if shodan:
        result.open_ports   = shodan.get("ports", [])
        result.shodan_tags  = shodan.get("tags", [])
        # Boost threat score if Shodan has malicious tags
        if any(t in ("malware", "mirai", "compromised") for t in result.shodan_tags):
            result.threat_score = min(100, result.threat_score + 20)
        if not result.isp:
            result.isp = shodan.get("isp", "")
        if not result.country_code:
            result.country_code = shodan.get("country_code", "")

    # ── Build human-readable label ─────────────────────────────────────────
    parts = []
    if result.shodan_tags:
        parts.append("/".join(result.shodan_tags[:3]).title())
    if result.is_tor:
        parts.append("Tor Exit Node")
    if result.usage_type:
        parts.append(result.usage_type)
    result.label = ", ".join(parts) if parts else "Unknown Source"

    CACHE[ip] = result
    log.info("OSINT  ip=%-16s  score=%3d  label=%s",
             ip, result.threat_score, result.label)
    return result
