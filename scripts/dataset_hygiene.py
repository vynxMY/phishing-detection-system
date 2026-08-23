"""Lightweight dataset hygiene checks for FYP evaluation honesty."""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ml.config import MERGED_CSV, TEST_CSV, TRAIN_CSV, VAL_CSV
from ml.preprocessing.clean import content_hash


def check_split(name: str, path: Path) -> dict:
    if not path.exists():
        return {"name": name, "missing": True}
    df = pd.read_csv(path)
    text_col = "text" if "text" in df.columns else df.columns[0]
    hashes = df[text_col].map(content_hash)
    dup_count = int(len(hashes) - hashes.nunique())
    label_counts = {}
    if "label" in df.columns:
        label_counts = {str(k): int(v) for k, v in Counter(df["label"]).items()}
    return {
        "name": name,
        "rows": int(len(df)),
        "duplicate_texts": dup_count,
        "duplicate_rate": round(dup_count / max(1, len(df)), 4),
        "label_counts": label_counts,
    }


def check_leakage() -> dict:
    paths = {"train": TRAIN_CSV, "val": VAL_CSV, "test": TEST_CSV}
    if not all(p.exists() for p in paths.values()):
        return {"skipped": True, "reason": "splits missing"}

    sets = {}
    for name, path in paths.items():
        df = pd.read_csv(path)
        text_col = "text" if "text" in df.columns else df.columns[0]
        sets[name] = set(df[text_col].map(content_hash))

    return {
        "train_val_overlap": len(sets["train"] & sets["val"]),
        "train_test_overlap": len(sets["train"] & sets["test"]),
        "val_test_overlap": len(sets["val"] & sets["test"]),
    }


def main() -> None:
    print("Dataset hygiene (content_hash)\n")
    for name, path in (
        ("merged", MERGED_CSV),
        ("train", TRAIN_CSV),
        ("val", VAL_CSV),
        ("test", TEST_CSV),
    ):
        info = check_split(name, path)
        print(info)

    leak = check_leakage()
    print("\nSplit leakage:")
    print(leak)
    if not leak.get("skipped"):
        bad = (
            leak["train_val_overlap"]
            + leak["train_test_overlap"]
            + leak["val_test_overlap"]
        )
        if bad:
            print(
                "\nWARNING: identical texts appear across splits. "
                "Fix before claiming held-out metrics."
            )
        else:
            print("\nNo exact-text overlap across train/val/test.")


if __name__ == "__main__":
    main()
