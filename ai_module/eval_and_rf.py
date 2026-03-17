#!/usr/bin/env python3
"""
ai_module/eval_and_rf.py
────────────────────────
Uses the already-saved xgb_model.pkl to:
  1. Evaluate XGBoost on CIC-IDS test split  (classification report)
  2. Train the RF stacking layer on XGBoost probability output
  3. Save rf_model.pkl

Usage:
  python3 ai_module/eval_and_rf.py --data data/cic-ids/
"""

import argparse
import glob
import os
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore")

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")

LABEL_MAP = {
    "BENIGN":                        "Benign",
    "Benign":                        "Benign",
    "DoS Hulk":                      "DoS",
    "DoS GoldenEye":                 "DoS",
    "DoS slowloris":                 "DoS",
    "DoS Slowhttptest":              "DoS",
    "DDoS":                          "DDoS",
    "PortScan":                      "PortScan",
    "FTP-Patator":                   "BruteForce",
    "SSH-Patator":                   "BruteForce",
    "Bot":                           "Bot",
    "Web Attack \x96 Brute Force":   "WebAttack",
    "Web Attack \xe2\x80\x93 Brute Force": "WebAttack",
    "Web Attack \u2013 Brute Force": "WebAttack",
    "Web Attack \x96 XSS":           "WebAttack",
    "Web Attack \u2013 XSS":         "WebAttack",
    "Web Attack \x96 Sql Injection": "WebAttack",
    "Web Attack \u2013 Sql Injection": "WebAttack",
    "Infiltration":                  "Infiltration",
    "Heartbleed":                    "Heartbleed",
}


def load_csvs(data_dir):
    pattern = os.path.join(data_dir, "**", "*.csv")
    files = glob.glob(pattern, recursive=True)
    if not files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")
    print(f"Found {len(files)} CSV file(s)")
    frames = []
    for f in files:
        print(f"  Loading {os.path.basename(f)} ...", end="", flush=True)
        df = pd.read_csv(f, encoding="utf-8", low_memory=False)
        df.columns = df.columns.str.strip()
        frames.append(df)
        print(f"  {len(df):,} rows")
    return pd.concat(frames, ignore_index=True)


def preprocess(df, feature_names, label_encoder):
    label_col = next((c for c in df.columns if c.strip().lower() == "label"), None)
    if label_col is None:
        raise ValueError("Could not find 'Label' column in dataset.")

    df[label_col] = df[label_col].str.strip().map(LABEL_MAP).fillna("Unknown")
    df = df[df[label_col] != "Unknown"]

    for c in feature_names:
        if c not in df.columns:
            df[c] = 0.0

    X = df[feature_names].copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    y_raw = df[label_col]

    # Refit label encoder on current dataset (saved one may be missing Benign)
    y = label_encoder.fit_transform(y_raw)

    print(f"\nSaved XGBoost classes : {list(label_encoder.classes_)}")
    print("\nClass distribution:")
    for cls, cnt in zip(label_encoder.classes_, np.bincount(y)):
        print(f"  {cls:<22} {cnt:>8,}")

    return X.values.astype(np.float32), y


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=os.path.join(
        os.path.dirname(__file__), "..", "data", "cic-ids"))
    parser.add_argument("--model-dir", default=MODEL_DIR)
    args = parser.parse_args()

    mdir = args.model_dir

    print("\n--- Loading saved models ---")
    xgb_model     = joblib.load(os.path.join(mdir, "xgb_model.pkl"))
    scaler        = joblib.load(os.path.join(mdir, "scaler.pkl"))
    label_encoder = joblib.load(os.path.join(mdir, "label_encoder.pkl"))
    feature_names = joblib.load(os.path.join(mdir, "feature_names.pkl"))
    print(f"  xgb_model      : loaded  ({len(label_encoder.classes_)} classes)")
    print(f"  scaler         : loaded")
    print(f"  label_encoder  : {list(label_encoder.classes_)}")
    print(f"  feature_names  : {len(feature_names)} features")

    print("\n--- Loading CIC-IDS dataset ---")
    df = load_csvs(args.data)
    print(f"Total rows: {len(df):,}")

    # Save original XGBoost class names before refitting label encoder
    xgb_classes = list(label_encoder.classes_)
    print(f"  XGBoost was trained on classes: {xgb_classes}")

    print("\n--- Preprocessing ---")
    X, y = preprocess(df, feature_names, label_encoder)
    # label_encoder is now refit with all classes (including Benign)
    all_classes = list(label_encoder.classes_)
    print(f"  Full label set: {all_classes}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"\nTrain: {len(X_train):,}   Test: {len(X_test):,}")

    X_train_s = scaler.transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # ── XGBoost evaluation (attack classes only) ────────────────────────────
    # XGBoost was trained without Benign; evaluate only on attack samples.
    benign_idx = all_classes.index("Benign")
    attack_mask_test  = (y_test  != benign_idx)
    attack_mask_train = (y_train != benign_idx)

    X_test_atk  = X_test_s[attack_mask_test]
    y_test_atk  = y_test[attack_mask_test]

    # XGBoost internal indices map to xgb_classes (original training classes)
    # Re-encode y_test_atk into XGBoost's 0..N-1 space using xgb_classes order
    class_name_test = [all_classes[i] for i in y_test_atk]
    # Filter to only known XGBoost classes (drop WebAttack / Benign if absent)
    known_mask  = [c in xgb_classes for c in class_name_test]
    X_test_xgb  = X_test_atk[known_mask]
    y_xgb_names = [c for c, m in zip(class_name_test, known_mask) if m]
    y_xgb_true  = np.array([xgb_classes.index(c) for c in y_xgb_names])

    print("\n--- XGBoost Evaluation on Attack-Only Test Set ---")
    y_xgb_pred = xgb_model.predict(X_test_xgb)
    print(classification_report(
        y_xgb_true, y_xgb_pred,
        target_names=xgb_classes,
        zero_division=0,
    ))

    # ── RF stacking layer training ──────────────────────────────────────────
    print("--- Training RF stacking layer on XGBoost probabilities ---")
    # Use ALL samples (including Benign) so RF learns Benign vs Malicious
    meta_train = xgb_model.predict_proba(X_train_s)
    meta_test  = xgb_model.predict_proba(X_test_s)

    y_bin_train = (y_train != benign_idx).astype(int)
    y_bin_test  = (y_test  != benign_idx).astype(int)

    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    rf.fit(meta_train, y_bin_train)

    y_rf_pred = rf.predict(meta_test)
    print("\nRF Binary Report (Benign vs Malicious):")
    print(classification_report(
        y_bin_test, y_rf_pred,
        target_names=["Benign", "Malicious"],
        zero_division=0,
    ))

    rf_path = os.path.join(mdir, "rf_model.pkl")
    joblib.dump(rf, rf_path)
    print(f"rf_model saved -> {rf_path}")


if __name__ == "__main__":
    main()
