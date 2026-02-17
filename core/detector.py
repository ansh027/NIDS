"""
Detection engine — loads the trained Random Forest model and classifies
network flow feature vectors.
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import MODEL_PATH, FEATURE_COLUMNS, LABEL_MAP, ATTACK_TYPES


class Detector:
    """
    Network intrusion detector backed by a trained Random Forest model.
    """

    def __init__(self, model_path: str = None):
        self.model_path = model_path or MODEL_PATH
        self.model = None
        self._load_model()

    def _load_model(self):
        """Load the serialized model from disk."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"Trained model not found at: {self.model_path}\n"
                f"Run training first:  python cli.py train"
            )
        self.model = joblib.load(self.model_path)

    def predict(self, features_df: pd.DataFrame) -> list[dict]:
        """
        Classify network flows.

        Parameters
        ----------
        features_df : pd.DataFrame
            DataFrame with columns matching FEATURE_COLUMNS.

        Returns
        -------
        list[dict]
            List of dicts with keys:
              - index: row index
              - prediction: 0–4 (attack type code)
              - label: "Normal" or "Intrusion"
              - attack_type: specific attack name (e.g. "Port Scan")
              - confidence: probability of the predicted class
              - severity: "safe" / "suspicious" / "malicious"
              - probabilities: dict of {class: probability}
        """
        if features_df.empty:
            return []

        # Ensure correct column order
        X = features_df[FEATURE_COLUMNS].values
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)

        results = []
        for i, (pred, probs) in enumerate(zip(predictions, probabilities)):
            confidence = float(np.max(probs))
            pred_int = int(pred)
            is_intrusion = pred_int != 0
            severity = self._get_severity(is_intrusion, confidence)

            results.append({
                "index": i,
                "prediction": 1 if is_intrusion else 0,
                "attack_type_code": pred_int,
                "label": "Intrusion" if is_intrusion else "Normal",
                "attack_type": ATTACK_TYPES.get(pred_int, "Unknown"),
                "confidence": round(confidence, 4),
                "severity": severity,
                "probabilities": {
                    ATTACK_TYPES.get(cls, str(cls)): round(float(p), 4)
                    for cls, p in enumerate(probs)
                },
            })

        return results

    def predict_dataframe(self, features_df: pd.DataFrame) -> pd.DataFrame:
        """
        Same as predict() but returns an enriched DataFrame.
        """
        results = self.predict(features_df)
        if not results:
            return features_df.copy()

        df = features_df.copy()
        df["prediction"] = [r["prediction"] for r in results]
        df["label"] = [r["label"] for r in results]
        df["attack_type"] = [r["attack_type"] for r in results]
        df["confidence"] = [r["confidence"] for r in results]
        df["severity"] = [r["severity"] for r in results]
        return df

    @staticmethod
    def _get_severity(is_intrusion: bool, confidence: float) -> str:
        """Derive a severity tag from the prediction and confidence."""
        if not is_intrusion:
            return "safe"
        elif confidence >= 0.85:
            return "malicious"
        else:
            return "suspicious"

    def summary(self, results: list[dict]) -> dict:
        """
        Generate a summary of detection results.
        """
        total = len(results)
        if total == 0:
            return {"total": 0, "normal": 0, "intrusion": 0,
                    "malicious": 0, "suspicious": 0, "safe": 0,
                    "attack_breakdown": {}}

        normal = sum(1 for r in results if r["prediction"] == 0)
        intrusion = total - normal
        malicious = sum(1 for r in results if r["severity"] == "malicious")
        suspicious = sum(1 for r in results if r["severity"] == "suspicious")
        safe = sum(1 for r in results if r["severity"] == "safe")

        # Count by attack type
        attack_breakdown = {}
        for r in results:
            atype = r["attack_type"]
            attack_breakdown[atype] = attack_breakdown.get(atype, 0) + 1

        return {
            "total": total,
            "normal": normal,
            "intrusion": intrusion,
            "malicious": malicious,
            "suspicious": suspicious,
            "safe": safe,
            "intrusion_rate": round(intrusion / total * 100, 2),
            "attack_breakdown": attack_breakdown,
        }

