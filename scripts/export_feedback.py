"""Export approved feedback into a training CSV (Sprint 10).

Does NOT retrain production automatically — admin must run training separately.
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
from backend.app.database import EmailScan, Feedback


def export_feedback(output: Path) -> int:
    app = create_app()
    with app.app_context():
        rows = (
            Feedback.query.filter_by(approved=True, reviewed=True)
            .order_by(Feedback.created_at.asc())
            .all()
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        count = 0
        with output.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=["scan_id", "subject", "sender", "predicted", "actual_label", "is_correct", "error_categories"],
            )
            writer.writeheader()
            for fb in rows:
                scan = fb.scan or EmailScan.query.get(fb.scan_id)
                if scan is None:
                    continue
                # Only incorrect→corrected labels become training candidates
                label = fb.actual_label
                if fb.is_correct:
                    # Map classification to binary label
                    label = "phishing" if scan.classification in ("phishing", "high_risk") else "legitimate"
                writer.writerow({
                    "scan_id": scan.id,
                    "subject": scan.subject or "",
                    "sender": scan.sender or "",
                    "predicted": scan.classification,
                    "actual_label": label or "",
                    "is_correct": fb.is_correct,
                    "error_categories": fb.error_categories or "[]",
                })
                count += 1
        print(f"Exported {count} approved feedback rows → {output}")
        print("Next: review the CSV, merge into ml/datasets, then run:")
        print("  python -m ml.training.train train --version v1.2.0")
        return count


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
