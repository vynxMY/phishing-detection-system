"""Content analysis signals for risk scoring."""

from __future__ import annotations

import re

from backend.app.email_parser.models import NormalizedEmail

URGENCY = re.compile(
    r"\b(?:urgent|immediately|asap|act now|expire|deadline|within 24 hours|"
    r"limited time|hurry|right away|final notice|last chance|respond now|"
    r"action required|time sensitive|expires? (?:today|tonight|soon))\b",
    re.I,
)
THREAT = re.compile(
    r"\b(?:suspend|terminated|closed|locked|unauthorized|legal action|"
    r"consequences|failure to|will be disabled|account closure|"
    r"permanently deleted|arrest|lawsuit|prosecution)\b",
    re.I,
)
CREDENTIAL = re.compile(
    r"\b(?:password|login|verify your account|confirm your identity|"
    r"update your information|security verification|credentials|"
    r"enter your|sign in|one[- ]time (?:code|password)|otp|"
    r"re-?authenticate|unlock your account)\b",
    re.I,
)
FINANCIAL = re.compile(
    r"\b(?:payment|invoice|refund|wire transfer|bank account|credit card|"
    r"billing|overdue|transaction|gift card|bank details|iban|swift)\b",
    re.I,
)
SOCIAL_ENGINEERING = re.compile(
    r"\b(?:dear customer|dear user|dear valued|click (?:here|below)|"
    r"confirm (?:now|immediately)|verify (?:now|immediately)|"
    r"unusual (?:sign[- ]?in|activity)|we noticed|your account has been)\b",
    re.I,
)


def _phrase_hits(pattern: re.Pattern, text: str) -> list[str]:
    return [m.group(0) for m in pattern.finditer(text or "")]


def analyze_content(email: NormalizedEmail) -> dict:
    text = email.combined_text()
    subject = email.subject or ""

    urgency_hits = _phrase_hits(URGENCY, text)
    threat_hits = _phrase_hits(THREAT, text)
    credential_hits = _phrase_hits(CREDENTIAL, text)
    financial_hits = _phrase_hits(FINANCIAL, text)
    social_hits = _phrase_hits(SOCIAL_ENGINEERING, text)

    score = 0
    score += min(40, len(urgency_hits) * 15)
    score += min(30, len(threat_hits) * 15)
    score += min(35, len(credential_hits) * 15)
    score += min(20, len(financial_hits) * 10)
    score += min(20, len(social_hits) * 8)
    if URGENCY.search(subject):
        score += 15
    if CREDENTIAL.search(subject):
        score += 10
    if THREAT.search(subject):
        score += 10

    # Caps / punctuation heuristics
    letters = [c for c in subject if c.isalpha()]
    if letters:
        upper_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
        if upper_ratio >= 0.6 and len(letters) >= 8:
            score += 10
    if subject.count("!") + text[:400].count("!") >= 3:
        score += 8

    issues = []
    if urgency_hits:
        issues.append({
            "type": "urgency_language",
            "severity": "warning",
            "contribution": min(0.25, 0.08 * len(urgency_hits)),
            "text": "The message pressures you to act quickly (urgency language).",
        })
    if threat_hits:
        issues.append({
            "type": "threat_language",
            "severity": "warning",
            "contribution": min(0.22, 0.08 * len(threat_hits)),
            "text": "The message threatens account loss, suspension, or other consequences.",
        })
    if credential_hits:
        issues.append({
            "type": "credential_request",
            "severity": "critical",
            "contribution": min(0.28, 0.1 * len(credential_hits)),
            "text": "The message asks you to verify, sign in, or share account credentials.",
        })
    if financial_hits:
        issues.append({
            "type": "financial_request",
            "severity": "warning",
            "contribution": min(0.18, 0.07 * len(financial_hits)),
            "text": "The message involves payment, refund, or banking language.",
        })

    return {
        "score": min(100, score),
        "urgency_count": len(urgency_hits),
        "threat_count": len(threat_hits),
        "credential_count": len(credential_hits),
        "financial_count": len(financial_hits),
        "social_engineering_count": len(social_hits),
        "matched_phrases": list(
            dict.fromkeys([p.lower() for p in urgency_hits + threat_hits + credential_hits + financial_hits + social_hits])
        )[:20],
        "issues": issues,
    }
