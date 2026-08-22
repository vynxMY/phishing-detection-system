"""Evaluation metrics for phishing detection models."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.calibration import calibration_curve
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from ml.config import LABEL_NAMES, REPORTS_DIR


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray | None = None) -> dict:
    """Compute full evaluation metrics per spec."""
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

    total = tn + fp + fn + tp
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    metrics = {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "false_positive_rate": round(float(fpr), 4),
        "false_negative_rate": round(float(fnr), 4),
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
        "support": {
            "legitimate": int((y_true == 0).sum()),
            "phishing": int((y_true == 1).sum()),
        },
    }

    if y_proba is not None:
        phishing_proba = y_proba[:, 1] if y_proba.ndim == 2 else y_proba
        try:
            metrics["roc_auc"] = round(float(roc_auc_score(y_true, phishing_proba)), 4)
        except ValueError:
            metrics["roc_auc"] = None
        try:
            metrics["pr_auc"] = round(float(average_precision_score(y_true, phishing_proba)), 4)
        except ValueError:
            metrics["pr_auc"] = None

        # Calibration summary (mean predicted prob vs actual rate)
        try:
            prob_true, prob_pred = calibration_curve(y_true, phishing_proba, n_bins=10)
            metrics["calibration"] = {
                "mean_predicted": round(float(np.mean(prob_pred)), 4),
                "mean_actual": round(float(np.mean(prob_true)), 4),
            }
        except ValueError:
            metrics["calibration"] = None

    return metrics


def print_metrics(metrics: dict, dataset_name: str = "test") -> None:
    """Pretty-print evaluation metrics."""
    print(f"\n{'=' * 50}")
    print(f"Evaluation Results — {dataset_name.upper()} SET")
    print(f"{'=' * 50}")
    print(f"  Accuracy:              {metrics['accuracy']:.2%}")
    print(f"  Precision:             {metrics['precision']:.2%}")
    print(f"  Recall:                {metrics['recall']:.2%}")
    print(f"  F1-score:              {metrics['f1']:.2%}")
    if metrics.get("roc_auc") is not None:
        print(f"  ROC-AUC:               {metrics['roc_auc']:.2%}")
    if metrics.get("pr_auc") is not None:
        print(f"  PR-AUC:                {metrics['pr_auc']:.2%}")
    print(f"  False Positive Rate:   {metrics['false_positive_rate']:.2%}")
    print(f"  False Negative Rate:   {metrics['false_negative_rate']:.2%}")

    cm = metrics["confusion_matrix"]
    print(f"\n  Confusion Matrix:")
    print(f"                    Predicted")
    print(f"                 Legit  Phishing")
    print(f"  Actual Legit    {cm['true_negative']:5d}  {cm['false_positive']:5d}")
    print(f"  Actual Phishing {cm['false_negative']:5d}  {cm['true_positive']:5d}")
    print(f"{'=' * 50}\n")


def evaluate_model(
    model,
    X: np.ndarray,
    y: np.ndarray,
    dataset_name: str = "test",
) -> dict:
    """Run prediction and compute metrics."""
    y_pred = model.predict(X)
    y_proba = model.predict_proba(X) if hasattr(model, "predict_proba") else None
    metrics = compute_metrics(y, y_pred, y_proba)
    print_metrics(metrics, dataset_name)
    return metrics


def save_report(
    metrics: dict,
    version: str,
    dataset_name: str = "test",
    extra: dict | None = None,
) -> Path:
    """Save evaluation report as JSON."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "model_version": version,
        "algorithm": "logistic_regression",
        "dataset": dataset_name,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics,
        **(extra or {}),
    }
    path = REPORTS_DIR / f"lr_{version}_{dataset_name}_report.json"
    path.write_text(json.dumps(report, indent=2))
    print(f"Report saved: {path}")
    return path
