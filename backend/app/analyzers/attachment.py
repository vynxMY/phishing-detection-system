"""Static attachment risk signals — delegates to Sprint 9 analyzer."""

from __future__ import annotations

from backend.app.attachments.static_analyzer import analyze_attachments as _analyze
from backend.app.email_parser.models import NormalizedEmail


def analyze_attachments(email: NormalizedEmail) -> dict:
    return _analyze(email)
