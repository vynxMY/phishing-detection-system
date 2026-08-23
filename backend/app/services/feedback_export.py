"""Shared approved-feedback export rows (CLI + admin download)."""

from __future__ import annotations

import json
from typing import Iterator

from backend.app.database import EmailScan, Feedback

FIELDNAMES = [
    "scan_id",
    "subject",
    "sender",
    "predicted",
    "risk_score",
    "actual_label",
    "is_correct",
    "error_categories",
    "explanation_simple",
    "findings_text",
    "model_version",
]


def iter_approved_feedback_rows() -> Iterator[dict]:
    rows = (
        Feedback.query.filter_by(approved=True, reviewed=True)
        .order_by(Feedback.created_at.asc())
        .all()
    )
    for fb in rows:
        scan = fb.scan or EmailScan.query.get(fb.scan_id)
        if scan is None:
            continue
        label = fb.actual_label
        if fb.is_correct:
            label = (
                "phishing"
                if scan.classification in ("phishing", "high_risk")
                else "legitimate"
            )
        try:
            expl = json.loads(scan.explanations_json or "{}")
        except json.JSONDecodeError:
            expl = {}
        findings = expl.get("findings") or []
        findings_text = " | ".join(
            (f.get("text") or "").strip() for f in findings[:8] if f.get("text")
        )
        yield {
            "scan_id": scan.id,
            "subject": scan.subject or "",
            "sender": scan.sender or "",
            "predicted": scan.classification,
            "risk_score": scan.risk_score,
            "actual_label": label or "",
            "is_correct": fb.is_correct,
            "error_categories": fb.error_categories or "[]",
            "explanation_simple": (expl.get("simple") or "")[:500],
            "findings_text": findings_text[:1000],
            "model_version": scan.model_version or "",
        }
