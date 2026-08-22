"""Compare text-only vs text+metadata Logistic Regression models."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from ml.config import ARTIFACTS_DIR, REPORTS_DIR
from ml.evaluation.evaluate import evaluate_model, print_metrics, save_report
from ml.features.combined_features import CombinedFeatureExtractor
from ml.models.logistic_regression import LogisticRegressionModel


def _train_and_evaluate(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    mode: str,
    version: str,
    tune: bool,
    fixed_c: float | None = None,
) -> dict:
    label = "text_only" if mode == "text_only" else "text_metadata"
    print(f"\n{'─' * 50}")
    print(f"Training: {label.upper()} model")
    print(f"{'─' * 50}")

    extractor = CombinedFeatureExtractor(mode=mode)
    X_train = extractor.fit_transform(train_df)
    X_val = extractor.transform(val_df)
    X_test = extractor.transform(test_df)

    y_train = train_df["label"].values
    y_val = val_df["label"].values
    y_test = test_df["label"].values

    print(f"  Feature matrix: {X_train.shape}")

    model_version = f"{version}-{label}"
    lr = LogisticRegressionModel(version=model_version)
    lr.train(X_train, y_train, tune=tune, fixed_c=fixed_c)

    print("\n  Validation:")
    val_metrics = evaluate_model(lr.model, X_val, y_val, "validation")

    print("\n  Test:")
    test_metrics = evaluate_model(lr.model, X_test, y_test, "test")

    model_path = lr.save()
    import joblib
    extractor_path = ARTIFACTS_DIR / f"feature_extractor_{model_version}.joblib"
    joblib.dump(extractor, extractor_path)

    save_report(val_metrics, model_version, "validation", {"mode": mode, "best_params": lr.best_params})
    save_report(test_metrics, model_version, "test", {"mode": mode, "best_params": lr.best_params})

    return {
        "mode": mode,
        "label": label,
        "feature_shape": list(X_train.shape),
        "best_params": lr.best_params,
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
        "model_path": str(model_path.name),
        "extractor_path": str(extractor_path.name),
    }


def print_comparison(results: list[dict]) -> None:
    """Print side-by-side comparison table."""
    print(f"\n{'=' * 70}")
    print("SPRINT 4 — MODEL COMPARISON (Test Set)")
    print(f"{'=' * 70}")
    print(f"{'Metric':<22} {'Text Only':>18} {'Text + Metadata':>18} {'Delta':>10}")
    print(f"{'─' * 70}")

    text_only = next(r for r in results if r["mode"] == "text_only")
    full = next(r for r in results if r["mode"] == "full")

    metrics_keys = [
        ("accuracy", "Accuracy"),
        ("precision", "Precision"),
        ("recall", "Recall"),
        ("f1", "F1-score"),
        ("roc_auc", "ROC-AUC"),
        ("pr_auc", "PR-AUC"),
        ("false_positive_rate", "False Positive Rate"),
        ("false_negative_rate", "False Negative Rate"),
    ]

    for key, label in metrics_keys:
        v1 = text_only["test_metrics"].get(key)
        v2 = full["test_metrics"].get(key)
        if v1 is None or v2 is None:
            continue
        delta = v2 - v1
        sign = "+" if delta >= 0 else ""
        # For FPR/FNR lower is better — invert delta interpretation in display
        if key in ("false_positive_rate", "false_negative_rate"):
            better = "↓" if delta < 0 else ("↑" if delta > 0 else "=")
        else:
            better = "↑" if delta > 0 else ("↓" if delta < 0 else "=")
        print(f"{label:<22} {v1:>17.2%} {v2:>17.2%} {sign}{delta:.2%} {better}")

    print(f"{'─' * 70}")
    print(f"{'Features':<22} {str(text_only['feature_shape'][1]):>18} {str(full['feature_shape'][1]):>18}")
    print(f"{'=' * 70}\n")


def run_comparison(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    version: str = "v1.1.0",
    tune: bool = True,
    fixed_c: float | None = None,
) -> dict:
    """Train and compare text-only vs text+metadata models."""
    results = []

    for mode in ("text_only", "full"):
        result = _train_and_evaluate(
            train_df, val_df, test_df, mode, version, tune, fixed_c=fixed_c
        )
        results.append(result)

    print_comparison(results)

    summary = {
        "comparison_version": version,
        "compared_at": datetime.now(timezone.utc).isoformat(),
        "models": results,
        "winner": _determine_winner(results),
    }

    report_path = REPORTS_DIR / f"comparison_{version}.json"
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(summary, indent=2))
    print(f"Comparison report saved: {report_path}")

    return summary


def _determine_winner(results: list[dict]) -> dict:
    """Determine winner based on F1, with FNR as tiebreaker."""
    text_only = next(r for r in results if r["mode"] == "text_only")
    full = next(r for r in results if r["mode"] == "full")

    t_f1 = text_only["test_metrics"]["f1"]
    f_f1 = full["test_metrics"]["f1"]
    t_fnr = text_only["test_metrics"]["false_negative_rate"]
    f_fnr = full["test_metrics"]["false_negative_rate"]

    if f_f1 > t_f1:
        winner = "text_metadata"
    elif f_f1 < t_f1:
        winner = "text_only"
    elif f_fnr < t_fnr:
        winner = "text_metadata"
    else:
        winner = "text_only"

    return {
        "model": winner,
        "text_only_f1": t_f1,
        "text_metadata_f1": f_f1,
        "text_only_fnr": t_fnr,
        "text_metadata_fnr": f_fnr,
    }
