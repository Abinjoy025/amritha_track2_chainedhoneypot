#!/usr/bin/env python3
"""
Online Learner — Incremental Model Retraining
==============================================
When the controller confirms a new attack (from heuristics or human review),
this module:
  1. Appends the new sample to a retraining CSV (data/online_samples.csv)
  2. When threshold is reached (default: every 20 new samples),
     retrains the Random Forest on original NSL-KDD data PLUS new honeypot samples
  3. Saves the updated model, overwriting the old one
  4. Logs retraining events to data/retraining_log.json

This gives the model continuous improvement from real attacker data,
going beyond the static NSL-KDD dataset.
"""

import os
import json
import csv
import threading
import joblib
import numpy as np
import pandas as pd
from datetime import datetime

_BASE = os.path.dirname(os.path.abspath(__file__))
_SAMPLES_CSV    = os.path.join(_BASE, '..', 'data', 'online_samples.csv')
_RETRAIN_LOG    = os.path.join(_BASE, '..', 'data', 'retraining_log.json')
_TRAIN_CSV      = os.path.join(_BASE, '..', 'data', 'NSL-KDD_train.csv')
_MODELS_DIR     = os.path.join(_BASE, '..', 'models')

# Retrain every time this many new confirmed samples come in
RETRAIN_THRESHOLD = 20

# NSL-KDD feature names (41 features)
NSL_KDD_COLS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'label'
]


class OnlineLearner:
    """
    Incrementally collects new attack samples and periodically retrains the
    Random Forest model with enriched data.
    """

    def __init__(self, model_dir: str = None):
        self.model_dir = model_dir or _MODELS_DIR
        self._lock = threading.Lock()
        self._ensure_samples_file()

    # ── Public API ─────────────────────────────────────────────────────────────

    def add_sample(self, log_entry: dict, attack_label: str,
                   is_attack: bool, packet_features: dict = None):
        """
        Add a confirmed attack (or confirmed benign) sample.
        After adding, check if retraining threshold is reached.
        """
        with self._lock:
            row = self._build_row(log_entry, attack_label, is_attack, packet_features)
            self._append_sample(row)
            count = self._sample_count()
            print(f"   📚 Online learner: {count} samples collected "
                  f"(retrain every {RETRAIN_THRESHOLD})")

            if count > 0 and count % RETRAIN_THRESHOLD == 0:
                print(f"\n   🔄 Retraining threshold reached ({count} samples)!")
                # Retrain in a background thread so controller doesn't block
                t = threading.Thread(target=self._retrain, daemon=True)
                t.start()

    def force_retrain(self):
        """Manually trigger a retrain."""
        print("\n   🔄 Forced retrain triggered...")
        self._retrain()

    # ── Sample Building ────────────────────────────────────────────────────────

    def _build_row(self, log_entry: dict, attack_label: str,
                   is_attack: bool, packet_features: dict) -> dict:
        """
        Build a NSL-KDD-compatible row from available data.
        Uses real packet features when available, else best-effort heuristics.
        """
        row = {col: 0 for col in NSL_KDD_COLS}

        if packet_features and 'vector' in packet_features:
            v = list(packet_features['vector'])
            for i, col in enumerate(NSL_KDD_COLS[:-1]):   # skip 'label'
                row[col] = v[i] if i < len(v) else 0
        else:
            # Heuristic fill from credential data
            username  = log_entry.get('username_attempt', '').lower()
            password  = log_entry.get('password_attempt', '')
            count_val = log_entry.get('_attempt_number', 1)

            row['protocol_type']     = 'tcp'
            row['service']           = 'http'
            row['flag']              = 'SF'
            row['num_failed_logins'] = 1
            row['logged_in']         = 0
            row['count']             = min(count_val, 511)
            row['srv_count']         = min(count_val, 511)

            # U2R signals
            u2r_keywords = ['rm -rf','chmod','/etc/shadow','/etc/passwd',
                            'nc -e','/bin/sh','cat /','OR 1=1']
            if any(k.lower() in password.lower() for k in u2r_keywords):
                row['root_shell']    = 1
                row['num_root']      = 1
                row['su_attempted']  = 1

            # R2L signals
            if count_val >= 3:
                row['num_failed_logins'] = min(count_val, 5)

        # Attack label → binary
        row['label'] = 1 if is_attack else 0
        return row

    # ── File Operations ───────────────────────────────────────────────────────

    def _ensure_samples_file(self):
        os.makedirs(os.path.dirname(_SAMPLES_CSV), exist_ok=True)
        if not os.path.exists(_SAMPLES_CSV):
            with open(_SAMPLES_CSV, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=NSL_KDD_COLS)
                writer.writeheader()

    def _append_sample(self, row: dict):
        with open(_SAMPLES_CSV, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=NSL_KDD_COLS)
            writer.writerow(row)

    def _sample_count(self) -> int:
        try:
            with open(_SAMPLES_CSV, 'r') as f:
                return max(0, sum(1 for _ in f) - 1)  # minus header
        except Exception:
            return 0

    # ── Retraining ────────────────────────────────────────────────────────────

    def _retrain(self):
        """
        Retrain the Random Forest with original NSL-KDD data + new samples.
        Saves the improved model back to models/ directory.
        """
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import LabelEncoder, StandardScaler
        from sklearn.pipeline import Pipeline

        start = datetime.utcnow()
        print("\n   ⚙️  Retraining Random Forest (background)...")

        try:
            # Load existing model components for LabelEncoders
            le_path = os.path.join(self.model_dir, 'label_encoders.pkl')
            fn_path = os.path.join(self.model_dir, 'feature_names.pkl')

            label_encoders = joblib.load(le_path) if os.path.exists(le_path) else {}
            feature_names  = joblib.load(fn_path) if os.path.exists(fn_path) else NSL_KDD_COLS[:-1]

            # ── Load NSL-KDD training data ──
            if os.path.exists(_TRAIN_CSV):
                df_base = pd.read_csv(_TRAIN_CSV)
                # Normalize column names
                df_base.columns = [c.strip().lower().replace(' ', '_')
                                   for c in df_base.columns]
            else:
                df_base = pd.DataFrame(columns=NSL_KDD_COLS)

            # ── Load new online samples ──
            df_new = pd.read_csv(_SAMPLES_CSV)

            # Combine (give new samples 3x weight by repeating them)
            df_new_weighted = pd.concat([df_new] * 3, ignore_index=True)
            df_combined = pd.concat([df_base, df_new_weighted], ignore_index=True)

            # ── Separate features / labels ──
            label_col = 'label'
            if label_col not in df_combined.columns:
                # Try 'class' column (NSL-KDD variant naming)
                if 'class' in df_combined.columns:
                    df_combined[label_col] = (df_combined['class'] != 'normal').astype(int)
                else:
                    print("   ❌ No label column found — aborting retrain")
                    return

            # Convert label to binary if string
            if df_combined[label_col].dtype == object:
                df_combined[label_col] = (
                    df_combined[label_col].str.lower() != 'normal'
                ).astype(int)

            # Encode categorical columns
            cat_cols = ['protocol_type', 'service', 'flag']
            for col in cat_cols:
                if col in df_combined.columns:
                    le = label_encoders.get(col, LabelEncoder())
                    df_combined[col] = df_combined[col].astype(str)
                    known = list(le.classes_) if hasattr(le, 'classes_') else []
                    new_vals = set(df_combined[col].unique()) - set(known)
                    if new_vals and known:
                        le.classes_ = np.array(sorted(set(known) | new_vals))
                    try:
                        df_combined[col] = le.transform(df_combined[col])
                    except Exception:
                        df_combined[col] = 0
                    label_encoders[col] = le

            # Get feature columns
            feature_cols = [c for c in df_combined.columns
                            if c != label_col and c != 'class']

            X = df_combined[feature_cols].fillna(0).values.astype(float)
            y = df_combined[label_col].values.astype(int)

            # ── Train ──
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            clf = RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                n_jobs=-1,
                random_state=42,
                class_weight='balanced'
            )
            clf.fit(X_scaled, y)

            # ── Save ──
            joblib.dump(clf,            os.path.join(self.model_dir, 'random_forest_model.pkl'))
            joblib.dump(scaler,         os.path.join(self.model_dir, 'scaler.pkl'))
            joblib.dump(label_encoders, os.path.join(self.model_dir, 'label_encoders.pkl'))
            joblib.dump(feature_cols,   os.path.join(self.model_dir, 'feature_names.pkl'))

            elapsed = (datetime.utcnow() - start).total_seconds()
            n_attack  = int(y.sum())
            n_benign  = int(len(y) - n_attack)

            print(f"   ✅ Retrain complete in {elapsed:.1f}s")
            print(f"      Training set: {len(y)} samples "
                  f"({n_attack} attack, {n_benign} benign)")

            # Log event
            self._log_retrain(len(y), n_attack, elapsed)

        except Exception as e:
            print(f"   ❌ Retrain failed: {e}")
            import traceback; traceback.print_exc()

    def _log_retrain(self, total: int, attacks: int, elapsed: float):
        log = []
        if os.path.exists(_RETRAIN_LOG):
            try:
                with open(_RETRAIN_LOG, 'r') as f:
                    log = json.load(f)
            except Exception:
                log = []
        log.append({
            'timestamp': datetime.utcnow().isoformat(),
            'total_samples': total,
            'attack_samples': attacks,
            'elapsed_seconds': round(elapsed, 2),
        })
        with open(_RETRAIN_LOG, 'w') as f:
            json.dump(log, f, indent=2)
