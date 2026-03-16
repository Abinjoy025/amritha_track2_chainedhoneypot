#!/usr/bin/env python3
"""
AI Predictor for analyzing honeypot logs
Loads the trained Random Forest model and classifies attacks.

Feature mode priority:
  1. REAL      — full NSL-KDD vector from live packet capture (most accurate)
  2. HEURISTIC — fallback when no packet data available
"""

import joblib
import numpy as np
import os
import json

# High-risk credential lists (used for heuristic + REAL enrichment)
ATTACK_USERNAMES = {
    'admin', 'root', 'administrator', 'sa', 'postgres',
    'oracle', 'user', 'test', 'guest', 'webadmin',
    'ubuntu', 'pi', 'deploy', 'www', 'ftp', 'mail'
}
COMMON_PASSWORDS = {
    'password', '123456', 'admin', 'root', '12345678',
    'qwerty', 'letmein', 'password1', '111111', 'abc123',
    'pass', '1234', 'welcome', 'monkey', 'dragon'
}


class AttackPredictor:
    def __init__(self, model_dir='../models'):
        self.model_dir      = model_dir
        self.model          = None
        self.scaler         = None
        self.label_encoders = None
        self.feature_names  = None
        self._load_model()

    # ─── Model Loading ───────────────────────────────────────────────────────

    def _load_model(self):
        try:
            self.model = joblib.load(
                os.path.join(self.model_dir, 'random_forest_model.pkl'))
            self.scaler = joblib.load(
                os.path.join(self.model_dir, 'scaler.pkl'))
            self.label_encoders = joblib.load(
                os.path.join(self.model_dir, 'label_encoders.pkl'))
            self.feature_names = joblib.load(
                os.path.join(self.model_dir, 'feature_names.pkl'))
            print("✅ AI Model loaded (Random Forest, NSL-KDD trained)")
            return True
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            print("   Run: python3 ai_module/train_model.py")
            return False

    # ─── Public API ──────────────────────────────────────────────────────────

    def analyze_honeypot_log(self, log_entry, packet_features=None):
        """
        Classify a honeypot log entry.

        Args:
            log_entry:       dict from honeypot_logs.json
            packet_features: dict returned by PacketCapture.get_features(ip)
                             or None to use heuristic fallback

        Returns dict with: is_attack, confidence, severity,
                            feature_mode, attack_prob, log_entry
        """
        if self.model is None:
            return self._heuristic_only(log_entry)

        if packet_features is not None:
            # REAL mode: full NSL-KDD vector from live packets → use RF model
            features, mode = self._build_real_vector(packet_features, log_entry)
            prediction  = self.model.predict([features])[0]
            probability = self.model.predict_proba([features])[0]
            attack_prob = float(probability[1])
            return {
                'is_attack':    bool(prediction),
                'confidence':   attack_prob if prediction == 1
                                else float(probability[0]),
                'attack_prob':  attack_prob,
                'severity':     self._severity(attack_prob),
                'feature_mode': mode,
                'log_entry':    log_entry
            }
        else:
            # HEURISTIC mode: RF trained on network features can't work with
            # credential-only data — use rule-based detection instead
            return self._heuristic_only(log_entry)

    # ─── Feature Builders ────────────────────────────────────────────────────

    def _build_real_vector(self, pkt_feat, log_entry):
        """
        Build a 41-feature NSL-KDD vector from real packet data,
        then enrich features 10-11 from the credential log entry.
        """
        raw = list(pkt_feat['vector'])   # 41 values, categorical still as strings

        # Encode categorical fields using the LabelEncoders from training
        for idx, col, val in [
                (1, 'protocol_type', pkt_feat['protocol']),
                (2, 'service',       pkt_feat['service']),
                (3, 'flag',          pkt_feat['flag'])]:
            le = self.label_encoders.get(col)
            try:
                raw[idx] = int(le.transform([val])[0]) if le else 0
            except (ValueError, AttributeError):
                raw[idx] = 0

        # Enrich with credential context
        username = log_entry.get('username_attempt', '').lower()
        raw[10] = 1                                   # num_failed_logins
        raw[11] = 0                                   # logged_in (never succeeds)
        raw[9]  = 1 if username in ATTACK_USERNAMES else 0  # hot

        features = self.scaler.transform([raw])[0]
        return features, 'REAL'

    # Track per-IP attempt counts for brute-force detection
    _ip_attempt_counts: dict = {}

    def _build_heuristic_vector(self, log_entry):
        """
        Build a best-effort feature vector from credential data alone.
        Used when no packet capture data is available.
        Maps known attack patterns to the NSL-KDD feature space.
        """
        username = log_entry.get('username_attempt', '').lower()
        password = log_entry.get('password_attempt', '')
        attacker_ip = log_entry.get('attacker_ip', '')

        # Track attempts per IP (brute-force indicator)
        AttackPredictor._ip_attempt_counts[attacker_ip] = \
            AttackPredictor._ip_attempt_counts.get(attacker_ip, 0) + 1
        attempt_count = AttackPredictor._ip_attempt_counts[attacker_ip]

        is_attack_user = username in ATTACK_USERNAMES
        is_common_pass = password.lower() in COMMON_PASSWORDS

        # Detect U2R patterns: injection/escalation payloads in password
        U2R_PATTERNS = ['rm -rf', 'chmod', '/etc/passwd', '/etc/shadow',
                        'nc -e', '/bin/sh', 'cat /', 'OR 1=1', "OR '1'='1",
                        '{{', '}}', '../', 'rootkit']
        is_u2r = (username == 'root' or
                  any(p.lower() in password.lower() for p in U2R_PATTERNS) or
                  len(password) > 200)  # buffer overflow

        vec = np.zeros(len(self.feature_names))

        # ── Core traffic features ──────────────────────────────────────────
        vec[0]  = 0                                         # duration
        vec[4]  = len(username) + len(password) + 40       # src_bytes
        vec[5]  = 150                                       # dst_bytes

        # ── R2L / brute-force features ────────────────────────────────────
        vec[9]  = int(is_attack_user)                       # hot
        vec[10] = min(attempt_count, 5)                     # num_failed_logins
        vec[11] = 0                                         # logged_in = always 0
        vec[12] = attempt_count if is_common_pass else 0   # num_compromised

        # ── U2R features ──────────────────────────────────────────────────
        if is_u2r:
            vec[13] = 1                                     # root_shell
            vec[14] = 1                                     # su_attempted
            vec[15] = 1                                     # num_root
            vec[16] = 1                                     # num_file_creations

        # ── Connection stats (simulate brute-force pattern) ───────────────
        vec[22] = min(attempt_count * 10, 511)              # count (same-host)
        vec[23] = min(attempt_count * 10, 511)              # srv_count
        vec[26] = min(attempt_count * 0.1, 1.0)            # rerror_rate
        vec[27] = min(attempt_count * 0.1, 1.0)            # srv_rerror_rate

        # Encode categorical defaults: tcp / http / SF (successful finish)
        # Use REJ flag for heavy brute-force (many rejected connections)
        flag_val = 'REJ' if attempt_count > 5 else 'SF'
        for col, val in [('protocol_type', 'tcp'),
                          ('service', 'http'),
                          ('flag', flag_val)]:
            if col not in self.feature_names:
                continue
            idx = self.feature_names.index(col)
            le  = self.label_encoders.get(col)
            try:
                vec[idx] = int(le.transform([val])[0]) if le else 0
            except (ValueError, AttributeError):
                vec[idx] = 0

        features = self.scaler.transform([vec])[0]
        return features, 'HEURISTIC'

    def _heuristic_only(self, log_entry):
        """Rule-based classification — used whenever packet capture unavailable."""
        username    = log_entry.get('username_attempt', '').lower()
        password    = log_entry.get('password_attempt', '')
        attacker_ip = log_entry.get('attacker_ip', '')

        # Track per-IP attempts (brute-force indicator)
        AttackPredictor._ip_attempt_counts[attacker_ip] = \
            AttackPredictor._ip_attempt_counts.get(attacker_ip, 0) + 1
        attempt_count = AttackPredictor._ip_attempt_counts[attacker_ip]

        is_known_user  = username in ATTACK_USERNAMES
        is_common_pass = password.lower() in COMMON_PASSWORDS
        is_brute_force = attempt_count >= 3

        # U2R: injection / escalation payloads
        U2R_PATTERNS = [
            'rm -rf', 'chmod', '/etc/passwd', '/etc/shadow',
            'nc -e', '/bin/sh', 'cat /', "OR '1'='1", 'OR 1=1',
            '{{', '}}', '../', 'rootkit', 'su root', 'sudo'
        ]
        is_u2r = (username == 'root' or
                  any(p.lower() in password.lower() for p in U2R_PATTERNS) or
                  len(password) > 200)

        # ── Classification rules ───────────────────────────────────────────
        if is_u2r:
            severity, prob, label = 'HIGH',   0.97, 'U2R (Privilege Escalation)'
        elif is_known_user and is_common_pass:
            severity, prob, label = 'HIGH',   0.94, 'R2L (Credential Brute-Force)'
        elif is_known_user and is_brute_force:
            severity, prob, label = 'HIGH',   0.91, 'R2L (Repeated Brute-Force)'
        elif is_known_user:
            severity, prob, label = 'MEDIUM', 0.72, 'R2L (Suspicious Username)'
        elif is_brute_force:
            severity, prob, label = 'MEDIUM', 0.65, 'Probe (Repeated Attempts)'
        else:
            severity, prob, label = 'LOW',    0.20, 'Benign'

        return {
            'is_attack':    prob >= 0.5,
            'confidence':   prob,
            'attack_prob':  prob,
            'severity':     severity,
            'attack_label': label,
            'feature_mode': 'HEURISTIC',
            'attempt_count': attempt_count,
            'log_entry':    log_entry
        }

    def _severity(self, attack_prob):
        if attack_prob >= 0.75:
            return 'HIGH'
        elif attack_prob >= 0.40:
            return 'MEDIUM'
        else:
            return 'LOW'

    # ─── Batch Analysis ──────────────────────────────────────────────────────

    def analyze_log_file(self, log_file='../honeypot_logs.json'):
        """One-shot analysis of existing log file (no packet data available)."""
        if not os.path.exists(log_file):
            print(f"❌ Log file not found: {log_file}")
            return []

        results, line_num = [], 0
        print(f"🔍 Analysing log file: {log_file}")

        with open(log_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    entry  = json.loads(line.strip())
                    result = self.analyze_honeypot_log(entry)
                    if result and result['is_attack']:
                        print(f"🚨 Attack line {line_num} | "
                              f"IP={entry.get('attacker_ip')} | "
                              f"Severity={result['severity']} | "
                              f"Mode={result['feature_mode']} | "
                              f"Prob={result['attack_prob']:.2%}")
                        results.append(result)
                except (json.JSONDecodeError, Exception) as e:
                    print(f"⚠️  Line {line_num}: {e}")

        print(f"\n✅ Done. {len(results)} attack(s) in {line_num} entries.")
        return results


if __name__ == '__main__':
    predictor = AttackPredictor()
    if predictor.model:
        predictor.analyze_log_file()
