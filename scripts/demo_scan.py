#!/usr/bin/env python3
"""Demo CLI for Sprints 5–7 detection pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.detection.pipeline import DetectionPipeline

DEMO_PHISHING = """\
From: Microsoft Support <support@micr0soft-security.com>
Reply-To: attacker@evil-domain.xyz
Subject: URGENT: Verify your account immediately
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Date: Sat, 22 Aug 2026 10:00:00 +0000

Dear Customer,

We detected unusual activity on your Microsoft account.
Confirm your identity now or your account will be suspended within 24 hours:

Click here: http://paypal-login.verify-account.xyz/auth

Enter your password to continue.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan an email with the detection pipeline")
    parser.add_argument("--text", help="Raw email text")
    parser.add_argument("--file", help="Path to .eml or text file")
    parser.add_argument("--demo", action="store_true", help="Run built-in phishing demo")
    parser.add_argument("--level", default="detailed", choices=["simple", "detailed", "technical", "all"])
    parser.add_argument("--version", default="v1.0.0", help="ML model version")
    parser.add_argument("--json", action="store_true", help="Print full JSON result")
    args = parser.parse_args()

    pipeline = DetectionPipeline(model_version=args.version)

    if args.demo:
        result = pipeline.scan(text=DEMO_PHISHING, explanation_level=args.level)
    elif args.file:
        path = Path(args.file)
        if path.suffix.lower() == ".eml":
            result = pipeline.scan(eml_path=path, explanation_level=args.level)
        else:
            result = pipeline.scan(text=path.read_text(encoding="utf-8", errors="replace"), explanation_level=args.level)
    elif args.text:
        result = pipeline.scan(text=args.text, explanation_level=args.level)
    else:
        parser.print_help()
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return

    print("=" * 60)
    print(f"Risk Score:      {result['risk_score']}/100")
    print(f"Classification:  {result['classification'].replace('_', ' ').upper()}")
    print(f"Confidence:      {result['confidence']:.0%}")
    print(f"Model:           {result.get('model_version')}")
    print("-" * 60)
    print("Breakdown:")
    for cat, pts in result["breakdown"].items():
        print(f"  {cat:<16} +{pts}")
    print("-" * 60)
    print("Why?")
    print(f"  {result['explanations']['simple']}")
    for finding in result["explanations"].get("findings", [])[:5]:
        icon = {"critical": "!", "warning": "*", "info": "-"}.get(finding["severity"], "-")
        print(f"  [{icon}] {finding['text']}")
    print("-" * 60)
    print("DO NOT:")
    for item in result["advice"]["do_not"]:
        print(f"  x {item}")
    print("DO:")
    for item in result["advice"]["do"]:
        print(f"  + {item}")
    print("=" * 60)


if __name__ == "__main__":
    main()
