"""Suspicious text highlighting (Sprint 7)."""

from __future__ import annotations

import re

from backend.app.analyzers.content import CREDENTIAL, FINANCIAL, THREAT, URGENCY

PATTERNS = [
    ("urgency", URGENCY),
    ("threat", THREAT),
    ("credential", CREDENTIAL),
    ("financial", FINANCIAL),
]


def highlight_suspicious_text(text: str) -> dict:
    """Return highlighted spans and a marked HTML-ish preview."""
    if not text:
        return {"spans": [], "preview": ""}

    spans = []
    for category, pattern in PATTERNS:
        for match in pattern.finditer(text):
            spans.append({
                "start": match.start(),
                "end": match.end(),
                "text": match.group(0),
                "category": category,
            })

    # Sort and merge overlaps (keep first)
    spans.sort(key=lambda s: (s["start"], -s["end"]))
    merged = []
    last_end = -1
    for span in spans:
        if span["start"] < last_end:
            continue
        merged.append(span)
        last_end = span["end"]

    # Build preview with markers
    parts = []
    cursor = 0
    for span in merged:
        parts.append(text[cursor:span["start"]])
        parts.append(f"[[{span['category'].upper()}:{span['text']}]]")
        cursor = span["end"]
    parts.append(text[cursor:])

    return {
        "spans": merged,
        "preview": "".join(parts),
        "span_count": len(merged),
    }
