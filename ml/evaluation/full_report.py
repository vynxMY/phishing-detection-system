"""Sprint 15 — full ML evaluation report on held-out test set + scenario suite."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ml.config import ARTIFACTS_DIR, REPORTS_DIR, TEST_CSV
from ml.evaluation.evaluate import compute_metrics, print_metrics

SCENARIOS = [
    {
        "id": "url_obfuscation",
        "label": 1,
        "text": "URGENT verify PayPal now http://paypa1-secure-login.xyz/auth enter password",
    },
    {
        "id": "brand_impersonation",
        "label": 1,
        "text": "From: Microsoft Support <help@micr0soft-security.com>\n\nYour Microsoft account will be suspended. Confirm identity.",
    },
    {
        "id": "bec_style",
        "label": 1,
        "text": "Hi, I'm in a meeting. Please wire $8500 to this account today. Send confirmation ASAP. — CEO",
    },
    {
        "id": "legitimate_meeting",
        "label": 0,
        "text": "Hi team, reminder that standup is at 10am in Conference Room B. Thanks, Jordan",
    },
    {
        "id": "legitimate_shipping",
        "label": 0,
        "text": "Your order #48219 has shipped and will arrive Friday. Track it in your account dashboard.",
    },
]


def _load_text_model(version: str = "v1.0.0"):
    candidates = [
        (f"logistic_regression_{version}.joblib", f"feature_extractor_{version}.joblib"),
        (f"logistic_regression_{version}-text_only.joblib", f"feature_extractor_{version}-text_only.joblib"),
        ("logistic_regression_v1.1.0-text_only.joblib", "feature_extractor_v1.1.0-text_only.joblib"),
    ]
    for model_name, ext_name in candidates:
        mp, ep = ARTIFACTS_DIR / model_name, ARTIFACTS_DIR / ext_name
        if mp.exists() and ep.exists():
            return joblib.load(mp), joblib.load(ep), model_name
    raise FileNotFoundError("No trained model artifacts found")


def evaluate_test_set(model, extractor) -> dict:
    df = pd.read_csv(TEST_CSV)
    if hasattr(extractor, "mode"):
        X = extractor.transform(df)
    else:
        X = extractor.transform(df["text"])
    y = df["label"].values
    y_pred = model.predict(X)
    y_proba = model.predict_proba(X)
    metrics = compute_metrics(y, y_pred, y_proba)
    print_metrics(metrics, "held-out test")
    return metrics


def evaluate_scenarios(model, extractor) -> list[dict]:
    results = []
    for case in SCENARIOS:
        if hasattr(extractor, "mode"):
            X = extractor.transform(pd.DataFrame([{"text": case["text"], "subject": ""}]))
        else:
            X = extractor.transform(pd.Series([case["text"]]))
        pred = int(model.predict(X)[0])
        proba = float(model.predict_proba(X)[0][1])
        results.append({
            **{k: case[k] for k in ("id", "label")},
            "predicted": pred,
            "phishing_probability": round(proba, 4),
            "correct": pred == case["label"],
        })
        status = "OK" if pred == case["label"] else "MISS"
        print(f"  [{status}] {case['id']}: pred={pred} truth={case['label']} p={proba:.3f}")
    return results


def main(version: str = "v1.0.0") -> Path:
    print("=" * 60)
    print("SPRINT 15 — ML Evaluation Report")
    print("=" * 60)
    model, extractor, artifact = _load_text_model(version)
    print(f"Artifact: {artifact}")

    test_metrics = evaluate_test_set(model, extractor)
    print("\nScenario suite:")
    scenarios = evaluate_scenarios(model, extractor)
    scenario_acc = sum(1 for s in scenarios if s["correct"]) / len(scenarios)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifact": artifact,
        "held_out_test": test_metrics,
        "scenario_suite": {
            "accuracy": round(scenario_acc, 4),
            "cases": scenarios,
        },
        "notes": [
            "Held-out test set never used during training (15% stratified split).",
            "Scenario suite covers URL obfuscation, brand impersonation, BEC-style, and legitimate mail.",
            "False negative rate is the primary security-focused metric.",
        ],
    }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out = REPORTS_DIR / f"sprint15_ml_evaluation_{version}.json"
    out.write_text(json.dumps(report, indent=2))

    md = REPORTS_DIR / f"sprint15_ml_evaluation_{version}.md"
    md.write_text(
        "\n".join([
            f"# Sprint 15 ML Evaluation ({version})",
            "",
            f"Generated: {report['generated_at']}",
            f"Artifact: `{artifact}`",
            "",
            "## Held-out test set",
            "",
            f"| Metric | Value |",
            f"|---|---|",
            f"| Accuracy | {test_metrics['accuracy']:.2%} |",
            f"| Precision | {test_metrics['precision']:.2%} |",
            f"| Recall | {test_metrics['recall']:.2%} |",
            f"| F1 | {test_metrics['f1']:.2%} |",
            f"| ROC-AUC | {test_metrics.get('roc_auc')} |",
            f"| PR-AUC | {test_metrics.get('pr_auc')} |",
            f"| FPR | {test_metrics['false_positive_rate']:.2%} |",
            f"| FNR | {test_metrics['false_negative_rate']:.2%} |",
            "",
            f"## Scenario suite accuracy: {scenario_acc:.0%}",
            "",
            *[
                f"- `{c['id']}`: {'pass' if c['correct'] else 'FAIL'} (p={c['phishing_probability']})"
                for c in scenarios
            ],
            "",
        ])
    )
    print(f"\nReport written: {out}")
    print(f"Markdown written: {md}")
    return out


if __name__ == "__main__":
    ver = sys.argv[1] if len(sys.argv) > 1 else "v1.0.0"
    main(ver)
