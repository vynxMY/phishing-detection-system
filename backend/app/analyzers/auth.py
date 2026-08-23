"""Authentication (SPF/DKIM/DMARC) analysis."""

from __future__ import annotations

import re

from backend.app.email_parser.models import NormalizedEmail


def _result(value: str) -> str:
    value = (value or "").lower().strip()
    if value in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"):
        return value
    return "none"


def analyze_auth(email: NormalizedEmail) -> dict:
    spf = _result(email.headers.spf)
    dmarc = _result(email.headers.dmarc)

    auth_blob = email.headers.authentication_results or ""
    if spf == "none":
        m = re.search(r"spf\s*=\s*(\w+)", auth_blob, re.I)
        if m:
            spf = _result(m.group(1))
    dkim = "none"
    m = re.search(r"dkim\s*=\s*(\w+)", auth_blob, re.I)
    if m:
        dkim = _result(m.group(1))
    elif email.headers.dkim_signature:
        dkim = "present"
    if dmarc == "none":
        m = re.search(r"dmarc\s*=\s*(\w+)", auth_blob, re.I)
        if m:
            dmarc = _result(m.group(1))

    score = 0
    issues = []

    if spf == "fail":
        score += 30
        issues.append({
            "type": "spf_fail",
            "severity": "warning",
            "contribution": 0.15,
            "text": "SPF authentication failed — the sending server is not authorized for this domain.",
        })
    elif spf == "softfail":
        score += 15
        issues.append({
            "type": "spf_softfail",
            "severity": "info",
            "contribution": 0.06,
            "text": "SPF softfail — the sending server is not explicitly authorized.",
        })

    if dkim == "fail":
        score += 25
        issues.append({
            "type": "dkim_fail",
            "severity": "warning",
            "contribution": 0.12,
            "text": "DKIM authentication failed — the message signature could not be verified.",
        })

    if dmarc == "fail":
        score += 30
        issues.append({
            "type": "dmarc_fail",
            "severity": "warning",
            "contribution": 0.15,
            "text": "DMARC authentication failed — domain policy rejected this message alignment.",
        })

    # Note: auth failure alone ≠ phishing; score is evidence only
    return {
        "score": min(100, score),
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "issues": issues,
        "available": any(v != "none" for v in (spf, dkim, dmarc)),
    }
