"""Dataset cleaning, deduplication, and label validation."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from ml.config import (
    LABEL_NAMES,
    MERGED_CSV,
    MIN_DATASET_SIZE,
    PROCESSED_DIR,
    RAW_DIR,
)


def normalize_text(text: str) -> str:
    """Normalize email text for deduplication and feature extraction."""
    if not isinstance(text, str):
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def content_hash(text: str) -> str:
    """SHA-256 hash of normalized lowercase text."""
    normalized = normalize_text(text).lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean merged dataset:
    - Drop empty/short emails
    - Normalize text
    - Remove exact duplicates
    - Validate labels
    """
    initial_count = len(df)

    df = df.copy()
    df["text"] = df["text"].map(normalize_text)
    df = df[df["text"].str.len() >= 30]
    df = df[df["label"].isin([0, 1])]
    df["label"] = df["label"].astype(int)

    df["content_hash"] = df["text"].map(content_hash)
    df = df.drop_duplicates(subset=["content_hash"], keep="first")

    df = df.reset_index(drop=True)
    df["id"] = range(1, len(df) + 1)

    removed = initial_count - len(df)
    print(f"Cleaning: {initial_count} → {len(df)} records ({removed} removed)")

    label_counts = df["label"].value_counts().to_dict()
    for label_val, count in label_counts.items():
        print(f"  {LABEL_NAMES[label_val]}: {count}")

    return df


def validate_labels(df: pd.DataFrame, sample_fraction: float = 0.05) -> dict:
    """
    Validate label quality by checking heuristic signals on a random sample.

    Returns a validation report dict (for manifest).
    """
    sample_size = max(10, int(len(df) * sample_fraction))
    sample = df.sample(n=min(sample_size, len(df)), random_state=42)

    phishing_keywords = re.compile(
        r"\b(urgent|verify|suspend|click here|password|account|immediately|"
        r"confirm your|security alert|unusual activity|invoice|payment)\b",
        re.IGNORECASE,
    )

    mismatches = 0
    for _, row in sample.iterrows():
        has_phishing_signal = bool(phishing_keywords.search(row["text"]))
        if row["label"] == 1 and not has_phishing_signal:
            # Phishing without obvious keywords — not necessarily wrong
            continue
        if row["label"] == 0 and has_phishing_signal:
            # Possible mislabel — count as soft mismatch
            mismatches += 1

    mismatch_rate = mismatches / len(sample) if len(sample) else 0.0
    report = {
        "sample_size": len(sample),
        "soft_mismatch_count": mismatches,
        "soft_mismatch_rate": round(mismatch_rate, 4),
        "passed": mismatch_rate < 0.30,
    }
    print(f"Label validation: {mismatches}/{len(sample)} soft mismatches ({mismatch_rate:.1%})")
    return report


def build_merged_dataset(records: list[dict]) -> pd.DataFrame:
    """Convert raw records to cleaned merged DataFrame."""
    df = pd.DataFrame(records)
    required = {"text", "label", "source"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Records missing columns: {missing}")

    if "subject" not in df.columns:
        df["subject"] = ""

    return clean_dataframe(df)


def save_merged_dataset(df: pd.DataFrame, validation_report: dict | None = None) -> Path:
    """Save cleaned merged dataset and manifest."""
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    if len(df) < MIN_DATASET_SIZE:
        print(f"Warning: dataset has {len(df)} records (minimum recommended: {MIN_DATASET_SIZE})")

    df.to_csv(MERGED_CSV, index=False)

    label_dist = df["label"].value_counts(normalize=True).to_dict()
    source_dist = df["source"].value_counts().to_dict()

    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "total_records": len(df),
        "dataset_hash": hashlib.sha256(
            df["content_hash"].sort_values().str.cat().encode()
        ).hexdigest(),
        "label_distribution": {LABEL_NAMES.get(int(k), str(k)): round(v, 4) for k, v in label_dist.items()},
        "source_distribution": source_dist,
        "validation": validation_report or {},
        "columns": list(df.columns),
    }

    manifest_path = PROCESSED_DIR / "dataset_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"Saved merged dataset: {MERGED_CSV} ({len(df)} records)")
    return MERGED_CSV


def load_merged_dataset() -> pd.DataFrame:
    """Load the processed merged dataset."""
    if not MERGED_CSV.exists():
        raise FileNotFoundError(f"Merged dataset not found: {MERGED_CSV}. Run preprocessing first.")
    return pd.read_csv(MERGED_CSV)


def run_cleaning_pipeline(records: list[dict]) -> pd.DataFrame:
    """Full cleaning pipeline: clean → validate → save."""
    df = build_merged_dataset(records)
    validation_report = validate_labels(df)
    save_merged_dataset(df, validation_report)
    return df
