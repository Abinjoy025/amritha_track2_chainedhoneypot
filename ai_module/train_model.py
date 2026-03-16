#!/usr/bin/env python3
"""
Random Forest AI Model Trainer for Intrusion Detection
Trains on NSL-KDD dataset and saves the model
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os

class IntrusionDetectionModel:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_names = []
        
    def preprocess_data(self, df):
        """Preprocess the NSL-KDD dataset"""
        print("🔧 Preprocessing data...")
        
        # Separate features and target
        X = df.drop(['attack_type', 'label'], axis=1)
        y = df['label']
        
        # Store feature names
        self.feature_names = X.columns.tolist()
        
        # Encode categorical features
        categorical_columns = ['protocol_type', 'service', 'flag']
        
        for col in categorical_columns:
            if col in X.columns:
                le = LabelEncoder()
                X[col] = le.fit_transform(X[col])
                self.label_encoders[col] = le
        
        # Scale numerical features
        X_scaled = self.scaler.fit_transform(X)
        
        return X_scaled, y
    
    def train(self, train_file='../data/NSL-KDD_train.csv'):
        """Train the Random Forest model"""
        print("🚀 Starting model training...")
        
        # Load dataset
        print("📂 Loading dataset...")
        df = pd.read_csv(train_file, header=None)
        
        # Add column names
        column_names = [
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
        df.columns = column_names
        
        # Remove difficulty and create binary labels
        df = df.drop('difficulty', axis=1)
        df['label'] = df['attack_type'].apply(lambda x: 0 if x == 'normal' else 1)
        
        print(f"📊 Dataset shape: {df.shape}")
        print(f"📊 Normal: {(df['label'] == 0).sum()}, Attack: {(df['label'] == 1).sum()}")
        
        # Preprocess
        X, y = self.preprocess_data(df)
        
        # Split for validation
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"🎯 Training samples: {len(X_train)}, Validation samples: {len(X_val)}")
        
        # Train Random Forest
        print("🌲 Training Random Forest Classifier...")
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            verbose=1
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate
        print("\n📈 Evaluating model...")
        train_pred = self.model.predict(X_train)
        val_pred = self.model.predict(X_val)
        
        train_acc = accuracy_score(y_train, train_pred)
        val_acc = accuracy_score(y_val, val_pred)
        
        print(f"\n✅ Training Accuracy: {train_acc:.4f}")
        print(f"✅ Validation Accuracy: {val_acc:.4f}")
        
        print("\n📊 Classification Report (Validation):")
        print(classification_report(y_val, val_pred, target_names=['Normal', 'Attack']))
        
        print("\n📊 Confusion Matrix:")
        print(confusion_matrix(y_val, val_pred))
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("\n🔍 Top 10 Most Important Features:")
        print(feature_importance.head(10))
        
        return self.model
    
    def save_model(self, model_dir='../models'):
        """Save the trained model and preprocessors"""
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
        
        print(f"\n💾 Saving model to {model_dir}...")
        
        joblib.dump(self.model, os.path.join(model_dir, 'random_forest_model.pkl'))
        joblib.dump(self.scaler, os.path.join(model_dir, 'scaler.pkl'))
        joblib.dump(self.label_encoders, os.path.join(model_dir, 'label_encoders.pkl'))
        joblib.dump(self.feature_names, os.path.join(model_dir, 'feature_names.pkl'))
        
        print("✅ Model saved successfully!")

if __name__ == '__main__':
    # Train the model
    model = IntrusionDetectionModel()
    model.train()
    model.save_model()
    
    print("\n🎉 Training complete! Model ready for deployment.")
