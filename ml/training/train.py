"""Training pipeline CLI for Logistic Regression."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

# Allow running as `python -m ml.training.train`
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml.config import (
    ARTIFACTS_DIR,
    DEFAULT_MODEL_VERSION,
    PROCESSED_DIR,
    TEST_CSV,
    TRAIN_CSV,
    VAL_CSV,
)
from ml.evaluation.compare_models import run_comparison
from ml.evaluation.evaluate import evaluate_model, save_report
from ml.features.text_features import TextFeatureExtractor
from ml.models.logistic_regression import LogisticRegressionModel
from ml.preprocessing.clean import run_cleaning_pipeline
from ml.preprocessing.download import download_all
from ml.preprocessing.split import run_split_pipeline


def load_split(name: str) -> pd.DataFrame:
    paths = {"train": TRAIN_CSV, "val": VAL_CSV, "test": TEST_CSV}
    path = paths[name]
    if not path.exists():
        raise FileNotFoundError(f"Split not found: {path}. Run preprocessing first.")
    return pd.read_csv(path)


def run_preprocessing(force_fallback: bool = False) -> None:
    """Sprint 2: download → clean → split."""
    print("\n" + "=" * 50)
    print("SPRINT 2 — Dataset & Preprocessing")
    print("=" * 50 + "\n")

    print("[1/3] Downloading datasets ...")
    records = download_all(force_fallback=force_fallback)

    print("\n[2/3] Cleaning and validating ...")
    run_cleaning_pipeline(records)

    print("\n[3/3] Splitting train/val/test ...")
    run_split_pipeline()

    print("\nPreprocessing complete.\n")


def run_training(version: str = DEFAULT_MODEL_VERSION, tune: bool = True) -> dict:
    """Sprint 3: train Logistic Regression and evaluate."""
    print("\n" + "=" * 50)
    print("SPRINT 3 — Logistic Regression Training")
    print("=" * 50 + "\n")

    train_df = load_split("train")
    val_df = load_split("val")
    test_df = load_split("test")

    print(f"Train: {len(train_df)}, Val: {len(val_df)}, Test: {len(test_df)}")

    # Feature extraction
    print("\n[1/4] Extracting TF-IDF + n-gram + linguistic features ...")
    extractor = TextFeatureExtractor()
    X_train = extractor.fit_transform(train_df["text"])
    X_val = extractor.transform(val_df["text"])
    X_test = extractor.transform(test_df["text"])

    y_train = train_df["label"].values
    y_val = val_df["label"].values
    y_test = test_df["label"].values

    print(f"  Feature matrix shape: {X_train.shape}")

    # Train
    print("\n[2/4] Training Logistic Regression ...")
    lr_model = LogisticRegressionModel(version=version)
    lr_model.train(X_train, y_train, tune=tune)

    # Evaluate on validation set
    print("\n[3/4] Validation evaluation ...")
    val_metrics = evaluate_model(lr_model.model, X_val, y_val, "validation")

    # Final test evaluation (once)
    print("\n[4/4] Final test evaluation ...")
    test_metrics = evaluate_model(lr_model.model, X_test, y_test, "test")

    # Save model + feature extractor
    model_path = lr_model.save()
    extractor_path = ARTIFACTS_DIR / f"feature_extractor_{version}.joblib"
    import joblib
    joblib.dump(extractor, extractor_path)
    print(f"Feature extractor saved: {extractor_path}")

    # Save reports
    save_report(val_metrics, version, "validation", {"best_params": lr_model.best_params})
    save_report(test_metrics, version, "test", {"best_params": lr_model.best_params})

    # Combined training summary
    summary = {
        "model_version": version,
        "algorithm": "logistic_regression",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "feature_shape": list(X_train.shape),
        "best_params": lr_model.best_params,
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
        "artifacts": {
            "model": str(model_path.name),
            "feature_extractor": str(extractor_path.name),
        },
    }
    summary_path = ARTIFACTS_DIR / f"training_summary_{version}.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    print(f"Training summary: {summary_path}")

    return summary


def run_enhanced_training(
    version: str = "v1.1.0",
    tune: bool = True,
    fixed_c: float | None = 100.0,
) -> dict:
    """Sprint 4: compare text-only vs text+metadata Logistic Regression."""
    print("\n" + "=" * 50)
    print("SPRINT 4 — Enhanced Detection (URL + Sender + Metadata)")
    print("=" * 50)

    train_df = load_split("train")
    val_df = load_split("val")
    test_df = load_split("test")

    print(f"\nDataset: train={len(train_df)}, val={len(val_df)}, test={len(test_df)}")
    if fixed_c is not None:
        print(f"Using fixed C={fixed_c} (skip grid search)")
    elif not tune:
        print("Training without hyperparameter tuning")

    return run_comparison(
        train_df, val_df, test_df, version=version, tune=tune, fixed_c=fixed_c
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Phishing Detection ML Training Pipeline")
    parser.add_argument(
        "command",
        choices=["preprocess", "train", "enhanced", "all"],
        help="preprocess=Sprint2, train=Sprint3, enhanced=Sprint4, all=Sprint2+3",
    )
    parser.add_argument("--version", default=DEFAULT_MODEL_VERSION, help="Model version tag")
    parser.add_argument("--no-tune", action="store_true", help="Skip hyperparameter tuning")
    parser.add_argument(
        "--fixed-c",
        type=float,
        default=None,
        help="Use fixed C value (skips grid search). Default for enhanced: 100.0",
    )
    parser.add_argument(
        "--tune",
        action="store_true",
        help="Enable grid search tuning (overrides default fixed C for enhanced)",
    )
    parser.add_argument(
        "--fallback",
        action="store_true",
        help="Use synthetic dataset only (skip network downloads)",
    )
    args = parser.parse_args()

    if args.command in ("preprocess", "all"):
        run_preprocessing(force_fallback=args.fallback)

    if args.command in ("train", "all"):
        run_training(version=args.version, tune=not args.no_tune)

    if args.command == "enhanced":
        tune = args.tune
        fixed_c = args.fixed_c if args.fixed_c is not None else (None if tune else 100.0)
        run_enhanced_training(version=args.version, tune=tune, fixed_c=fixed_c)


if __name__ == "__main__":
    main()
