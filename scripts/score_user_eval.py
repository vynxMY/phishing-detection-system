#!/usr/bin/env python3
"""Score Sprint 16 user-evaluation survey CSV against email_pack truths."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--survey",
        default=str(ROOT / "docs" / "user_eval" / "survey_template.csv"),
    )
    parser.add_argument(
        "--pack",
        default=str(ROOT / "docs" / "user_eval" / "email_pack.json"),
    )
    args = parser.parse_args()

    truths = {e["id"]: e["truth"] for e in json.loads(Path(args.pack).read_text())}
    rows = list(csv.DictReader(Path(args.survey).open(encoding="utf-8")))

    by_phase = defaultdict(list)
    usefulness = []
    trust = []

    for row in rows:
        eid = row["email_id"]
        phase = row["phase"].upper()
        label = (row.get("user_label") or "").strip().lower()
        truth = truths.get(eid)
        if truth and label in ("phishing", "legitimate"):
            by_phase[phase].append(label == truth)
        if row.get("explanation_useful_1_to_5"):
            usefulness.append(float(row["explanation_useful_1_to_5"]))
        if row.get("trust_1_to_5"):
            trust.append(float(row["trust_1_to_5"]))

    print("Sprint 16 — User evaluation summary")
    for phase, vals in sorted(by_phase.items()):
        acc = sum(vals) / len(vals) if vals else 0
        print(f"  Phase {phase} accuracy: {acc:.0%} ({sum(vals)}/{len(vals)})")
    if usefulness:
        print(f"  Mean explanation usefulness: {sum(usefulness)/len(usefulness):.2f}/5")
    if trust:
        print(f"  Mean trust: {sum(trust)/len(trust):.2f}/5")
    if "A" in by_phase and "B" in by_phase and by_phase["A"] and by_phase["B"]:
        a = sum(by_phase["A"]) / len(by_phase["A"])
        b = sum(by_phase["B"]) / len(by_phase["B"])
        print(f"  Accuracy lift (B - A): {b - a:+.0%}")


if __name__ == "__main__":
    main()
