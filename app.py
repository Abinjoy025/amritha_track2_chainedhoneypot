import logging
import json
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET', 'honeypot-secret-key-2025')

# ── Logging ────────────────────────────────────────────────────────────────────
LOG_DIR = os.getenv('LOG_DIR', 'logs')
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(LOG_DIR, 'honeypot_raw.log'),
    level=logging.INFO,
    format='%(asctime)s %(message)s'
)

# ── Legitimate users (NOT honeypot — real access allowed) ─────────────────────
# Username: @betaUser2005   Password: @BetaUsers#
LEGIT_USERS = {
    '@betaUser2005': hashlib.sha256('@BetaUsers#'.encode()).hexdigest(),
}


def _get_ip():
    return (request.headers.get('X-Forwarded-For', '')
            .split(',')[0].strip()
            or request.remote_addr)


def log_attack(ip, username, password, user_agent, extra: dict = None):
    """
    Log an attacker's attempt with full forensic detail:
      - All request headers
      - Raw POST body
      - Query parameters
      - Payload fingerprint (SHA256)
      - User-Agent
    """
    raw_payload = request.get_data(as_text=True) or ''

    # Capture ALL headers (except sensitive ones we store anyway)
    headers_dict = {k: v for k, v in request.headers.items()}

    # Fingerprint the payload
    payload_hash = hashlib.sha256(raw_payload.encode()).hexdigest() if raw_payload else ''

    attack_data = {
        "timestamp":         datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attacker_ip":       ip,
        "target_service":    "Web_Admin_Portal",
        "username_attempt":  username or '',
        "password_attempt":  password or '',
        "user_agent":        user_agent or '',

        # ── New forensic fields ──
        "raw_payload":       raw_payload[:2000],   # cap at 2KB
        "payload_sha256":    payload_hash,
        "request_headers":   headers_dict,
        "query_params":      dict(request.args),
        "cookies":           dict(request.cookies),
        "method":            request.method,
        "path":              request.path,
        "content_type":      request.content_type or '',
        "content_length":    request.content_length or 0,
    }

    if extra:
        attack_data.update(extra)

    # Save to JSON file (one JSON object per line)
    log_file = os.path.join(LOG_DIR, 'honeypot_logs.json')
    with open(log_file, 'a') as f:
        json.dump(attack_data, f)
        f.write("\n")

    logging.info(
        f"ATTACK | ip={ip} user={username!r} ua={user_agent!r} "
        f"payload_hash={payload_hash[:8]}..."
    )
    print(f"⚠️  ATTACK | IP={ip} | user={username!r} | "
          f"payload_len={len(raw_payload)} bytes")


# ── Honeypot trap (the fake admin login) ──────────────────────────────────────

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip_address = _get_ip()
        username   = request.form.get('username', '')
        password   = request.form.get('password', '')
        user_agent = request.headers.get('User-Agent', '')

        # ── Check if this is a legitimate user ────────────────────────────────
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        if username in LEGIT_USERS and LEGIT_USERS[username] == pw_hash:
            session['user'] = username
            session['authenticated'] = True
            logging.info(f"LEGIT LOGIN: {username} from {ip_address}")
            print(f"✅ Legitimate user logged in: {username} from {ip_address}")
            return redirect(url_for('project_portal'))

        # ── Otherwise: attacker — log everything and pretend to fail ──────────
        log_attack(ip_address, username, password, user_agent)
        return render_template('login.html',
                               error="Invalid credentials. Please try again.")

    return render_template('login.html')


# ── Legitimate Portal ─────────────────────────────────────────────────────────

@app.route('/portal')
def project_portal():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    return render_template('portal.html', user=session.get('user'))


@app.route('/portal/logout')
def portal_logout():
    session.clear()
    return redirect(url_for('login'))


# ── Additional honeypot trap endpoints ────────────────────────────────────────

@app.route('/admin', methods=['GET', 'POST'])
@app.route('/wp-admin', methods=['GET', 'POST'])
@app.route('/phpmyadmin', methods=['GET', 'POST'])
@app.route('/api/v1/auth', methods=['GET', 'POST'])
def fake_endpoints():
    """High-value honeypot lure endpoints"""
    ip_address = _get_ip()
    logging.info(f"PROBE: {request.path} from {ip_address}")
    log_attack(ip_address,
               request.form.get('username', ''),
               request.form.get('password', ''),
               request.headers.get('User-Agent', ''),
               extra={'probe_path': request.path})
    if request.method == 'POST':
        return render_template('login.html',
                               error="Access denied.")
    return "Access Denied", 403


if __name__ == '__main__':
    log_file = os.path.join(LOG_DIR, 'honeypot_logs.json')
    if not os.path.exists(log_file):
        open(log_file, 'w').close()

    print("🍯 Honeypot Server Starting...")
    print("📍 Trap at http://localhost:5000")
    print("🔑 Legit portal at http://localhost:5000/portal")
    port = int(os.getenv('HONEYPOT_PORT', 5000))
    host = os.getenv('HONEYPOT_HOST', '0.0.0.0')
    app.run(host=host, port=port, debug=False, use_reloader=False)
