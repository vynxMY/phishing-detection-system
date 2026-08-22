"""Header analysis signals (Sprint 4+)."""

from __future__ import annotations

import re

from backend.app.email_parser.models import NormalizedEmail


def analyze_headers(email: NormalizedEmail) -> dict:
    """Lightweight header anomaly signals."""
    score = 0
    issues = []
    received = email.headers.received or []
    raw = email.raw_headers or {}

    if len(received) >= 8:
        score += 10
        issues.append({
            "type": "many_received",
            "severity": "info",
            "text": f"Message has {len(received)} Received hops (unusually high).",
        })

    auth = email.headers.authentication_results or ""
    if not auth and not email.headers.spf:
        # Missing auth headers is common for pasted text; mild signal only
        if email.sender.email:
            score += 5

    subject = email.subject or ""
    if re.search(r"(re|fwd)\s*:.+\1\s*:", subject, re.I):
        score += 10
        issues.append({
            "type": "subject_chain_noise",
            "severity": "info",
            "text": "Subject contains repeated Re:/Fwd: markers.",
        })

    return {
        "score": min(100, score),
        "received_count": len(received),
        "header_keys": list(raw.keys())[:40],
        "issues": issues,
    }
