"""Stratified train / validation / test split."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

from ml.config import (
    PROCESSED_DIR,
    RANDOM_SEED,
    TEST_CSV,
    TEST_RATIO,
    TRAIN_CSV,
    TRAIN_RATIO,
    VAL_CSV,
    VAL_RATIO,
)
from ml.preprocessing.clean import content_hash, load_merged_dataset


def dedupe_by_text(df: pd.DataFrame) -> pd.DataFrame:
    """Keep one row per content_hash (same definition as cleaning)."""
    if "text" not in df.columns:
        return df
    before = len(df)
    out = df.copy()
    if "content_hash" not in out.columns:
        out["content_hash"] = out["text"].map(content_hash)
    out = out.drop_duplicates(subset=["content_hash"], keep="first")
    removed = before - len(out)
    if removed:
        print(f"Removed {removed} duplicate texts before split")
    return out.reset_index(drop=True)


def _remove_cross_split_leakage(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Ensure identical texts never appear in more than one split (train wins)."""
    for frame in (train_df, val_df, test_df):
        if "content_hash" not in frame.columns:
            frame["content_hash"] = frame["text"].map(content_hash)

    train_hashes = set(train_df["content_hash"])
    val_df = val_df[~val_df["content_hash"].isin(train_hashes)].copy()
    test_df = test_df[~test_df["content_hash"].isin(train_hashes)].copy()

    val_hashes = set(val_df["content_hash"])
    test_df = test_df[~test_df["content_hash"].isin(val_hashes)].copy()
    return train_df.reset_index(drop=True), val_df.reset_index(drop=True), test_df.reset_index(drop=True)


def split_dataset(
    df: pd.DataFrame | None = None,
    train_ratio: float = TRAIN_RATIO,
    val_ratio: float = VAL_RATIO,
    test_ratio: float = TEST_RATIO,
    random_state: int = RANDOM_SEED,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Stratified split into train / val / test.

    Default ratios: 70% / 15% / 15%
    """
    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-6, "Ratios must sum to 1.0"

    if df is None:
        df = load_merged_dataset()

    df = dedupe_by_text(df)

    # First split: train vs (val + test)
    temp_ratio = val_ratio + test_ratio
    train_df, temp_df = train_test_split(
        df,
        test_size=temp_ratio,
        random_state=random_state,
        stratify=df["label"],
    )

    # Second split: val vs test (proportional)
    relative_test = test_ratio / temp_ratio
    val_df, test_df = train_test_split(
        temp_df,
        test_size=relative_test,
        random_state=random_state,
        stratify=temp_df["label"],
    )

    train_df, val_df, test_df = _remove_cross_split_leakage(train_df, val_df, test_df)

    print(f"Split: train={len(train_df)}, val={len(val_df)}, test={len(test_df)}")
    for name, split_df in [("train", train_df), ("val", val_df), ("test", test_df)]:
        counts = split_df["label"].value_counts().to_dict()
        print(f"  {name}: legitimate={counts.get(0, 0)}, phishing={counts.get(1, 0)}")

    return train_df, val_df, test_df


def save_splits(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
) -> dict[str, Path]:
    """Persist split CSVs and split manifest."""
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    paths = {
        "train": TRAIN_CSV,
        "val": VAL_CSV,
        "test": TEST_CSV,
    }

    train_df.to_csv(TRAIN_CSV, index=False)
    val_df.to_csv(VAL_CSV, index=False)
    test_df.to_csv(TEST_CSV, index=False)

    train_hashes = set(train_df["text"].map(content_hash))
    val_hashes = set(val_df["text"].map(content_hash))
    test_hashes = set(test_df["text"].map(content_hash))

    manifest = {
        "train_size": len(train_df),
        "val_size": len(val_df),
        "test_size": len(test_df),
        "train_phishing_rate": round(float(train_df["label"].mean()), 4),
        "val_phishing_rate": round(float(val_df["label"].mean()), 4),
        "test_phishing_rate": round(float(test_df["label"].mean()), 4),
        "random_seed": RANDOM_SEED,
        "deduped_by_text": True,
        "leakage": {
            "train_val_overlap": len(train_hashes & val_hashes),
            "train_test_overlap": len(train_hashes & test_hashes),
            "val_test_overlap": len(val_hashes & test_hashes),
        },
    }
    manifest_path = PROCESSED_DIR / "split_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    print(f"Splits saved to {PROCESSED_DIR}")
    return paths


def run_split_pipeline() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Load merged data, split, and save."""
    df = load_merged_dataset()
    train_df, val_df, test_df = split_dataset(df)
    save_splits(train_df, val_df, test_df)
    return train_df, val_df, test_df
