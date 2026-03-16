#!/usr/bin/env python3
"""
CIC-IDS 2017 Dataset Downloader (via kagglehub)
Uses kagglehub.dataset_download to fetch dhoogla/cicids2017 parquet files,
combines them, and saves a single CSV to data/cic-ids/ for train_model.py.

Requires:
  pip install kagglehub pyarrow pandas
  Kaggle credentials: ~/.kaggle/kaggle.json  or  KAGGLE_USERNAME + KAGGLE_KEY
"""

import os
import sys
import glob

KAGGLE_DATASET  = "dhoogla/cicids2017"
DEFAULT_SAVE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "cic-ids")


def download_dataset(save_dir: str = None) -> bool:
    try:
        import kagglehub
        import pandas as pd
    except ImportError:
        print("❌ Missing deps. Run: pip install kagglehub pyarrow pandas")
        return False

    if save_dir is None:
        save_dir = DEFAULT_SAVE_DIR
    os.makedirs(save_dir, exist_ok=True)

    out_path = os.path.join(save_dir, "cicids2017_combined.csv")
    if os.path.exists(out_path) and os.path.getsize(out_path) > 1024 * 1024:
        print(f"✅ Dataset already exists: {out_path}")
        return True

    print(f"⬇️  Downloading CIC-IDS 2017 from Kaggle ({KAGGLE_DATASET}) …")
    try:
        path = kagglehub.dataset_download(KAGGLE_DATASET)
    except Exception as exc:
        print(f"❌ Download failed: {exc}")
        print("   Ensure ~/.kaggle/kaggle.json exists or KAGGLE_USERNAME/KAGGLE_KEY are set.")
        return False

    print(f"📁 Dataset path: {path}")

    parquet_files = sorted(glob.glob(os.path.join(path, "**", "*.parquet"), recursive=True))
    if not parquet_files:
        print("❌ No parquet files found.")
        return False

    frames = []
    for pf in parquet_files:
        df = pd.read_parquet(pf)
        print(f"   {os.path.basename(pf)}: {len(df):,} rows")
        frames.append(df)

    combined = pd.concat(frames, ignore_index=True)
    print(f"\n📊 Combined: {len(combined):,} rows, {len(combined.columns)} columns")

    combined.to_csv(out_path, index=False)
    size_mb = os.path.getsize(out_path) / 1024 / 1024
    print(f"✅ Saved: {out_path}  ({size_mb:.1f} MB)")
    return True


if __name__ == "__main__":
    save = sys.argv[1] if len(sys.argv) > 1 else None
    ok = download_dataset(save)
    sys.exit(0 if ok else 1)
