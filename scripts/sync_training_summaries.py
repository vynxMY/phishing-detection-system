"""Write training_summary_*.json from existing evaluation reports.

Does not invent metrics — copies held-out numbers already produced by training.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ml.config import ARTIFACTS_DIR, REPORTS_DIR


def _write_summary_from_reports(model_version: str) -> Path | None:
    val_path = REPORTS_DIR / f"lr_{model_version}_validation_report.json"
    test_path = REPORTS_DIR / f"lr_{model_version}_test_report.json"
    if not test_path.exists():
        print(f"Skip {model_version}: missing {test_path.name}")
        return None

    test_report = json.loads(test_path.read_text(encoding="utf-8"))
    val_metrics = None
    if val_path.exists():
        val_metrics = json.loads(val_path.read_text(encoding="utf-8")).get("metrics")

    summary = {
        "model_version": model_version,
        "algorithm": test_report.get("algorithm") or "logistic_regression",
        "trained_at": test_report.get("evaluated_at"),
        "source_reports": {
            "validation": val_path.name if val_path.exists() else None,
            "test": test_path.name,
        },
        "best_params": test_report.get("best_params") or {},
        "validation_metrics": val_metrics,
        "test_metrics": test_report.get("metrics"),
        "artifacts": {
            "model": f"logistic_regression_{model_version}.joblib",
            "feature_extractor": f"feature_extractor_{model_version}.joblib",
        },
        "note": (
            "Held-out metrics copied from evaluation reports. "
            "Primary story: Precision / Recall / F1 (not accuracy alone)."
        ),
    }

    out = ARTIFACTS_DIR / f"training_summary_{model_version}.json"
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Wrote {out}")
    return out


def main() -> None:
    for version in (
        "v1.0.0",
        "v1.1.0-text_only",
        "v1.1.0-text_metadata",
    ):
        _write_summary_from_reports(version)


if __name__ == "__main__":
    main()
