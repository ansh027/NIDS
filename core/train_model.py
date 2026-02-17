"""
Train and evaluate a Random Forest classifier for network intrusion detection.

Usage:
    from core.train_model import train
    train()
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    DATASET_PATH,
    MODEL_PATH,
    MODELS_DIR,
    FEATURE_COLUMNS,
    RF_N_ESTIMATORS,
    RF_MAX_DEPTH,
    RF_RANDOM_STATE,
)


def train(
    data_path: str = None,
    model_path: str = None,
    test_size: float = 0.25,
    verbose: bool = True,
) -> dict:
    """
    Train a Random Forest model on the network intrusion dataset.

    Parameters
    ----------
    data_path : str, optional
        Path to the CSV dataset. Defaults to config.DATASET_PATH.
    model_path : str, optional
        Where to save the trained model. Defaults to config.MODEL_PATH.
    test_size : float
        Fraction of data to hold out for testing.
    verbose : bool
        Whether to print progress and metrics.

    Returns
    -------
    dict
        Dictionary with keys: accuracy, report, confusion_matrix, model_path.
    """
    data_path = data_path or DATASET_PATH
    model_path = model_path or MODEL_PATH

    # --- Load data ---
    if verbose:
        print(f"[*] Loading dataset from: {data_path}")
    df = pd.read_csv(data_path)

    if verbose:
        print(f"[+] Loaded {len(df)} samples")
        print(f"[+] Attack type distribution:\n{df['attack_type'].value_counts().to_string()}")

    # --- Prepare features and labels (multi-class: attack_type 0-4) ---
    X = df[FEATURE_COLUMNS].values
    y = df["attack_type"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=RF_RANDOM_STATE, stratify=y
    )

    if verbose:
        print(f"\n[*] Training set: {len(X_train)} samples")
        print(f"[*] Test set:     {len(X_test)} samples")

    # --- Train model ---
    if verbose:
        print(f"\n[*] Training RandomForestClassifier "
              f"(n_estimators={RF_N_ESTIMATORS}, max_depth={RF_MAX_DEPTH})...")

    model = RandomForestClassifier(
        n_estimators=RF_N_ESTIMATORS,
        max_depth=RF_MAX_DEPTH,
        random_state=RF_RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    # --- Evaluate ---
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    target_names = ["Normal", "Port Scan", "DoS Flood", "Brute Force", "Data Exfiltration"]
    report = classification_report(y_test, y_pred, target_names=target_names)
    cm = confusion_matrix(y_test, y_pred)

    if verbose:
        print(f"\n{'='*50}")
        print(f"  MODEL EVALUATION RESULTS")
        print(f"{'='*50}")
        print(f"\n  Accuracy: {acc:.4f} ({acc*100:.2f}%)")
        print(f"\n  Classification Report:")
        print(report)
        print(f"  Confusion Matrix:")
        print(f"  {cm}")

        # Feature importance
        importances = model.feature_importances_
        indices = np.argsort(importances)[::-1]
        print(f"\n  Top Feature Importances:")
        for i, idx in enumerate(indices[:7]):
            print(f"    {i+1}. {FEATURE_COLUMNS[idx]}: {importances[idx]:.4f}")

    # --- Save model ---
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(model, model_path)
    if verbose:
        print(f"\n[+] Model saved to: {model_path}")

    return {
        "accuracy": acc,
        "report": report,
        "confusion_matrix": cm.tolist(),
        "model_path": model_path,
    }


if __name__ == "__main__":
    train()
