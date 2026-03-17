#!/usr/bin/env python3
"""
ai_module/train_model.py
─────────────────────────
Phase 2 – XGBoost Intrusion-Detection Model
Dataset: CIC-IDS 2017 (or 2018)

CIC-IDS CSV columns end with a 'Label' column:
  BENIGN, DoS Hulk, PortScan, DDoS, DoS GoldenEye, FTP-Patator,
  SSH-Patator, DoS slowloris, DoS Slowhttptest, Bot,
  Web Attack – Brute Force, Web Attack – XSS, Web Attack – Sql Injection,
  Infiltration, Heartbleed

Usage:
  python3 ai_module/train_model.py --data data/cic-ids/
"""

import argparse
import glob
import os
import warnings

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.utils.class_weight import compute_sample_weight

warnings.filterwarnings("ignore")

# ─── CIC-IDS 2017 feature names (matching dhoogla/cicids2017 parquet schema) ──
CIC_IDS_FEATURES = [
    "Protocol","Flow Duration","Total Fwd Packets",
    "Total Backward Packets","Fwd Packets Length Total",
    "Bwd Packets Length Total","Fwd Packet Length Max",
    "Fwd Packet Length Min","Fwd Packet Length Mean","Fwd Packet Length Std",
    "Bwd Packet Length Max","Bwd Packet Length Min","Bwd Packet Length Mean",
    "Bwd Packet Length Std","Flow Bytes/s","Flow Packets/s",
    "Flow IAT Mean","Flow IAT Std","Flow IAT Max","Flow IAT Min",
    "Fwd IAT Total","Fwd IAT Mean","Fwd IAT Std","Fwd IAT Max","Fwd IAT Min",
    "Bwd IAT Total","Bwd IAT Mean","Bwd IAT Std","Bwd IAT Max","Bwd IAT Min",
    "Fwd PSH Flags","Bwd PSH Flags","Fwd URG Flags","Bwd URG Flags",
    "Fwd Header Length","Bwd Header Length","Fwd Packets/s","Bwd Packets/s",
    "Packet Length Min","Packet Length Max","Packet Length Mean",
    "Packet Length Std","Packet Length Variance","FIN Flag Count",
    "SYN Flag Count","RST Flag Count","PSH Flag Count","ACK Flag Count",
    "URG Flag Count","CWE Flag Count","ECE Flag Count","Down/Up Ratio",
    "Avg Packet Size","Avg Fwd Segment Size","Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk","Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate","Bwd Avg Bytes/Bulk","Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate","Subflow Fwd Packets","Subflow Fwd Bytes",
    "Subflow Bwd Packets","Subflow Bwd Bytes","Init Fwd Win Bytes",
    "Init Bwd Win Bytes","Fwd Act Data Packets","Fwd Seg Size Min",
    "Active Mean","Active Std","Active Max","Active Min",
    "Idle Mean","Idle Std","Idle Max","Idle Min",
]

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
    "Web Attack – Brute Force":      "WebAttack",
    "Web Attack \x96 XSS":           "WebAttack",
    "Web Attack – XSS":              "WebAttack",
    "Web Attack \x96 Sql Injection": "WebAttack",
    "Web Attack – Sql Injection":    "WebAttack",
    "Infiltration":                  "Infiltration",
    "Heartbleed":                    "Heartbleed",
}

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")


class CICIDSTrainer:
    def __init__(self, model_dir: str = MODEL_DIR):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names: list = []

    def _load_csvs(self, data_dir: str) -> pd.DataFrame:
        pattern = os.path.join(data_dir, "**", "*.csv")
        files = glob.glob(pattern, recursive=True)
        if not files:
            raise FileNotFoundError(
                f"No CSV files found in {data_dir}.\n"
                "Download CIC-IDS 2017 from https://www.unb.ca/cic/datasets/ids-2017.html"
            )
        print(f"📂 Found {len(files)} CSV file(s)")
        frames = []
        for f in files:
            print(f"   Loading {os.path.basename(f)} …", end="", flush=True)
            df = pd.read_csv(f, encoding="utf-8", low_memory=False)
            df.columns = df.columns.str.strip()
            frames.append(df)
            print(f"  {len(df):,} rows")
        return pd.concat(frames, ignore_index=True)

    def _preprocess(self, df: pd.DataFrame):
        label_col = next(
            (c for c in df.columns if c.strip().lower() == "label"), None
        )
        if label_col is None:
            raise ValueError("Could not find 'Label' column in dataset.")

        df[label_col] = df[label_col].str.strip().map(LABEL_MAP).fillna("Unknown")
        df = df[df[label_col] != "Unknown"]

        available = [c for c in CIC_IDS_FEATURES if c in df.columns]
        missing   = [c for c in CIC_IDS_FEATURES if c not in df.columns]
        if missing:
            print(f"   ⚠️  {len(missing)} features not in dataset (zero-filled)")
        for c in missing:
            df[c] = 0.0

        self.feature_names = CIC_IDS_FEATURES
        X = df[self.feature_names].copy()
        y_raw = df[label_col]

        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        X.fillna(0, inplace=True)

        y = self.label_encoder.fit_transform(y_raw)

        print("\n📊 Class distribution:")
        for cls, cnt in zip(self.label_encoder.classes_, np.bincount(y)):
            print(f"   {cls:<22} {cnt:>8,}")
        return X.values.astype(np.float32), y

    def train(self, data_dir: str) -> None:
        print("\n🚀  XGBoost training on CIC-IDS …")
        df = self._load_csvs(data_dir)
        print(f"📊 Total rows: {len(df):,}")
        X, y = self._preprocess(df)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=42, stratify=y
        )
        print(f"🔀 Train: {len(X_train):,}   Test: {len(X_test):,}")

        X_train = self.scaler.fit_transform(X_train)
        X_test  = self.scaler.transform(X_test)

        n_classes = len(self.label_encoder.classes_)
        params = dict(
            n_estimators=600, max_depth=10, learning_rate=0.08,
            subsample=0.85, colsample_bytree=0.85,
            min_child_weight=2, gamma=0.05,
            eval_metric="mlogloss" if n_classes > 2 else "logloss",
            tree_method="hist", n_jobs=-1, random_state=42,
            objective="multi:softprob" if n_classes > 2 else "binary:logistic",
        )
        if n_classes > 2:
            params["num_class"] = n_classes

        # Balanced sample weights: up-weights rare classes (e.g. Heartbleed has
        # only ~11 samples in CIC-IDS 2017; Bot/Infiltration are also imbalanced).
        # This directly boosts per-class confidence for minority attack types.
        sample_weights = compute_sample_weight("balanced", y_train)

        self.model = xgb.XGBClassifier(**params)
        print(f"🌲  Training XGBoost (classes={n_classes}) …")
        self.model.fit(
            X_train, y_train,
            sample_weight=sample_weights,
            eval_set=[(X_test, y_test)],
            verbose=50,
        )

        y_pred = self.model.predict(X_test)
        print("\n📈 Classification Report:")
        print(classification_report(y_test, y_pred,
              target_names=self.label_encoder.classes_, zero_division=0))

        joblib.dump(self.model,         os.path.join(self.model_dir, "xgb_model.pkl"))
        joblib.dump(self.scaler,        os.path.join(self.model_dir, "scaler.pkl"))
        joblib.dump(self.label_encoder, os.path.join(self.model_dir, "label_encoder.pkl"))
        joblib.dump(self.feature_names, os.path.join(self.model_dir, "feature_names.pkl"))
        print(f"\n✅  Models saved to {self.model_dir}/")

        self._train_rf_stage(X_train, y_train, X_test, y_test)

    def _train_rf_stage(
        self,
        X_train: np.ndarray, y_train: np.ndarray,
        X_test:  np.ndarray, y_test:  np.ndarray,
    ) -> None:
        """
        Stage 2: Random Forest binary classifier (Benign vs Malicious).
        Uses XGBoost class probabilities as meta-features.
        """
        print("\n🌲  Training Random Forest on XGBoost probabilities …")

        benign_idx = list(self.label_encoder.classes_).index("Benign")

        # Meta-features: XGBoost probability vector for each sample
        meta_train = self.model.predict_proba(X_train)
        meta_test  = self.model.predict_proba(X_test)

        # Binary labels: 0 = Benign, 1 = Malicious
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
        print("\n📈 RF Binary Report (Benign vs Malicious):")
        print(classification_report(
            y_bin_test, y_rf_pred,
            target_names=["Benign", "Malicious"],
            zero_division=0,
        ))

        rf_path = os.path.join(self.model_dir, "rf_model.pkl")
        joblib.dump(rf, rf_path)
        print(f"✅  RF model saved → {rf_path}")


def main():
    parser = argparse.ArgumentParser(description="Train XGBoost on CIC-IDS 2017/2018")
    parser.add_argument("--data", default=os.path.join(
        os.path.dirname(__file__), "..", "data", "cic-ids"),
        help="Folder with CIC-IDS CSV files")
    parser.add_argument("--model-dir", default=MODEL_DIR)
    args = parser.parse_args()
    CICIDSTrainer(model_dir=args.model_dir).train(data_dir=args.data)

if __name__ == "__main__":
    main()
