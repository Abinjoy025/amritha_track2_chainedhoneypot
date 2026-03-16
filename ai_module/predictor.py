#!/usr/bin/env python3
"""
ai_module/predictor.py
──────────────────────
Phase 2  – XGBoost Inference Engine + SHAP Explainability

Loads the pre-trained XGBoost classifier (trained on CIC-IDS 2017/2018).
Accepts a feature vector extracted by feature_extractor.py.

Returns:
  {
    "attack_type":   "BruteForce",      # canonical label
    "confidence":    0.94,
    "is_attack":     True,
    "shap": {
      "top_features": [
        {"name": "Flow Bytes/s",        "shap_value": 1.42},
        {"name": "SYN Flag Count",      "shap_value": 0.88},
        {"name": "Total Fwd Packets",   "shap_value": 0.73}
      ],
      "base_value": 0.11
    }
  }
"""

import os
import joblib
import numpy as np

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")


class AttackPredictor:
    def __init__(self, model_dir: str = MODEL_DIR):
        self.model_dir     = model_dir
        self.model         = None
        self.scaler        = None
        self.label_encoder = None
        self.feature_names = None
        self._explainer    = None   # lazy-loaded SHAP TreeExplainer
        self._load_model()

    # ─── Loading ──────────────────────────────────────────────────────────────

    def _load_model(self) -> bool:
        try:
            self.model         = joblib.load(os.path.join(self.model_dir, "xgb_model.pkl"))
            self.scaler        = joblib.load(os.path.join(self.model_dir, "scaler.pkl"))
            self.label_encoder = joblib.load(os.path.join(self.model_dir, "label_encoder.pkl"))
            self.feature_names = joblib.load(os.path.join(self.model_dir, "feature_names.pkl"))
            print("✅ XGBoost model loaded (CIC-IDS trained)")
            return True
        except Exception as exc:
            print(f"❌ Model load failed: {exc}")
            print("   Run: python3 ai_module/train_model.py --data data/cic-ids/")
            return False

    def _get_explainer(self):
        if self._explainer is None:
            import shap
            self._explainer = shap.TreeExplainer(self.model)
        return self._explainer

    # ─── Public API ───────────────────────────────────────────────────────────

    def predict(self, feature_vector: dict) -> dict:
        """
        Classify one traffic flow.

        Args:
            feature_vector: dict mapping CIC-IDS feature names → float values
                            (produced by feature_extractor.CICFlowExtractor)

        Returns: prediction dict (see module docstring)
        """
        if self.model is None:
            return self._heuristic_fallback(feature_vector)

        # Build ordered numpy array matching training column order
        X_raw = np.array(
            [float(feature_vector.get(f, 0.0)) for f in self.feature_names],
            dtype=np.float32,
        ).reshape(1, -1)

        X_scaled = self.scaler.transform(X_raw)

        # XGBoost prediction
        pred_idx  = int(self.model.predict(X_scaled)[0])
        proba     = self.model.predict_proba(X_scaled)[0]
        confidence = float(proba[pred_idx])
        attack_type = self.label_encoder.inverse_transform([pred_idx])[0]
        is_attack   = attack_type != "Benign"

        # SHAP explanation
        shap_info = self._explain(X_scaled, pred_idx)

        return {
            "attack_type": attack_type,
            "confidence":  round(confidence, 4),
            "is_attack":   is_attack,
            "all_proba":   {
                cls: round(float(p), 4)
                for cls, p in zip(self.label_encoder.classes_, proba)
            },
            "shap":        shap_info,
        }

    # ─── SHAP Explainability ─────────────────────────────────────────────────

    def _explain(self, X_scaled: np.ndarray, class_idx: int) -> dict:
        """Return top-3 SHAP features for the predicted class."""
        try:
            explainer   = self._get_explainer()
            shap_values = explainer.shap_values(X_scaled)

            # Multi-class: shap_values can be:
            #   list  → [n_classes][n_samples, n_features]  (shap < 0.46)
            #   ndarray (3D) → (n_samples, n_features, n_classes)  (shap >= 0.46)
            if isinstance(shap_values, list):
                sv = shap_values[class_idx][0]
            elif shap_values.ndim == 3:
                sv = shap_values[0, :, class_idx]
            else:
                sv = shap_values[0]

            # Top 3 by absolute value
            top3_idx = np.argsort(np.abs(sv))[::-1][:3]
            top_features = [
                {
                    "name":       self.feature_names[i],
                    "shap_value": round(float(sv[i]), 4),
                }
                for i in top3_idx
            ]
            base = float(explainer.expected_value[class_idx]
                         if isinstance(explainer.expected_value, (list, np.ndarray))
                         else explainer.expected_value)
            return {"top_features": top_features, "base_value": round(base, 4)}
        except Exception as exc:
            return {"top_features": [], "base_value": 0.0, "error": str(exc)}

    # ─── Heuristic fallback (no model) ──────────────────────────────────────

    def _heuristic_fallback(self, fv: dict) -> dict:
        """Very simple rule-based classifier when the model is missing."""
        syn_count   = float(fv.get("SYN Flag Count", 0))
        flow_bytes  = float(fv.get("Flow Bytes/s", 0))
        fwd_packets = float(fv.get("Total Fwd Packets", 0))

        if syn_count > 50:
            label, conf = "DDoS",       0.72
        elif flow_bytes > 1_000_000:
            label, conf = "DoS",        0.65
        elif fwd_packets > 200:
            label, conf = "PortScan",   0.60
        else:
            label, conf = "Benign",     0.55

        return {
            "attack_type": label,
            "confidence":  conf,
            "is_attack":   label != "Benign",
            "all_proba":   {},
            "shap":        {"top_features": [], "base_value": 0.0,
                            "note": "heuristic fallback – no model loaded"},
        }
