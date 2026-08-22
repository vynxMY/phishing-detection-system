"""Content analysis signals for risk scoring."""

from __future__ import annotations

import re

from backend.app.email_parser.models import NormalizedEmail

URGENCY = re.compile(
    r"\b(urgent|immediately|asap|act now|expire|deadline|within 24 hours|"
    r"limited time|hurry|right away|final notice)\b",
    re.I,
)
THREAT = re.compile(
    r"\b(suspend|terminated|closed|locked|unauthorized|legal action|"
    r"consequences|failure to|will be disabled|account closure)\b",
    re.I,
)
CREDENTIAL = re.compile(
    r"\b(password|login|verify your account|confirm your identity|"
    r"update your information|security verification|credentials|"
    r"enter your|sign in)\b",
    re.I,
)
FINANCIAL = re.compile(
    r"\b(payment|invoice|refund|wire transfer|bank account|credit card|"
    r"billing|overdue|transaction|gift card)\b",
    re.I,
)


def analyze_content(email: NormalizedEmail) -> dict:
    text = email.combined_text()
    subject = email.subject or ""

    urgency_hits = URGENCY.findall(text)
    threat_hits = THREAT.findall(text)
    credential_hits = CREDENTIAL.findall(text)
    financial_hits = FINANCIAL.findall(text)

    score = 0
    score += min(40, len(urgency_hits) * 15)
    score += min(30, len(threat_hits) * 15)
    score += min(35, len(credential_hits) * 15)
    score += min(20, len(financial_hits) * 10)
    if URGENCY.search(subject):
        score += 15
    if CREDENTIAL.search(subject):
        score += 10

    return {
        "score": min(100, score),
        "urgency_count": len(urgency_hits),
        "threat_count": len(threat_hits),
        "credential_count": len(credential_hits),
        "financial_count": len(financial_hits),
        "matched_phrases": list(
            dict.fromkeys(
                [p.lower() for p in urgency_hits + threat_hits + credential_hits + financial_hits]
            )
        )[:20],
    }
