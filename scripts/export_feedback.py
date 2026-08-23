"""Export approved feedback into a review/training CSV (Sprint 10).

Does NOT retrain production automatically — admin must run training separately.
Bodies are intentionally omitted (privacy default); export is for label audit
and offline dataset curation, not a drop-in TF-IDF training file.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.app import create_app
from backend.app.services.feedback_export import FIELDNAMES, iter_approved_feedback_rows


def export_feedback(output: Path) -> int:
    app = create_app()
    with app.app_context():
        records = list(iter_approved_feedback_rows())
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
            writer.writeheader()
            for row in records:
                writer.writerow(row)
        print(f"Exported {len(records)} approved feedback rows → {output}")
        print("Note: raw email bodies are not exported (privacy default).")
        print("Next: review the CSV, merge curated samples into ml/datasets, then run:")
        print("  python -m ml.training.train train --version v1.2.0")
        return len(records)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export approved feedback for offline retraining")
    parser.add_argument(
        "-o", "--output",
        default=str(ROOT / "ml" / "datasets" / "processed" / "feedback_export.csv"),
    )
    args = parser.parse_args()
    export_feedback(Path(args.output))


if __name__ == "__main__":
    main()
