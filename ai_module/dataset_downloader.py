#!/usr/bin/env python3
"""
NSL-KDD Dataset Downloader
Downloads the famous NSL-KDD dataset for intrusion detection training
"""

import os
import urllib.request
import pandas as pd

# NSL-KDD Dataset URLs (publicly available)
DATASET_URLS = {
    'train': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt',
    'test': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt'
}

# Column names for NSL-KDD dataset
COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack_type', 'difficulty'
]

def download_dataset(save_dir='../data'):
    """Download NSL-KDD dataset"""
    print("📥 Downloading NSL-KDD Dataset...")
    
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
    
    for dataset_type, url in DATASET_URLS.items():
        file_path = os.path.join(save_dir, f'NSL-KDD_{dataset_type}.csv')
        
        if os.path.exists(file_path):
            print(f"✅ {dataset_type} dataset already exists at {file_path}")
            continue
        
        try:
            print(f"⬇️  Downloading {dataset_type} dataset from {url}")
            urllib.request.urlretrieve(url, file_path)
            print(f"✅ Downloaded {dataset_type} dataset to {file_path}")
        except Exception as e:
            print(f"❌ Error downloading {dataset_type} dataset: {e}")
            return False
    
    print("✅ Dataset download complete!")
    return True

def load_and_preprocess(file_path):
    """Load dataset and add column names"""
    df = pd.read_csv(file_path, header=None, names=COLUMN_NAMES)
    
    # Remove difficulty column (last column)
    df = df.drop('difficulty', axis=1)
    
    # Simplify attack types to binary classification (Normal vs Attack)
    df['label'] = df['attack_type'].apply(lambda x: 0 if x == 'normal' else 1)
    
    print(f"📊 Dataset shape: {df.shape}")
    print(f"📊 Attack distribution:\n{df['label'].value_counts()}")
    
    return df

if __name__ == '__main__':
    # Run the downloader
    success = download_dataset()
    
    if success:
        print("\n🔍 Testing dataset load...")
        train_df = load_and_preprocess('../data/NSL-KDD_train.csv')
        print("\n✅ Dataset ready for training!")
