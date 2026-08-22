"""Persist scan results without storing raw email bodies."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from backend.app.database import EmailFeature, EmailScan, User, db


def _hash_message(subject: str, sender: str, body_preview: str) -> str:
    raw = f"{subject}|{sender}|{body_preview[:500]}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def save_scan_result(user: User | None, result: dict[str, Any], provider: str = "web") -> EmailScan:
    summary = result.get("email_summary") or {}
    subject = (summary.get("subject") or "")[:500]
    sender = (summary.get("sender") or "")[:255]
    message_hash = _hash_message(subject, sender, subject)

    analyses = result.get("analyses") or {}
    explanations = result.get("explanations") or {}

    scan = EmailScan(
        user_id=user.id if user else None,
        provider=provider,
        message_hash=message_hash,
        subject=subject or None,
        sender=sender or None,
        classification=result["classification"],
        risk_score=int(result["risk_score"]),
        confidence=result.get("confidence"),
        model_version=result.get("model_version"),
        breakdown_json=json.dumps(result.get("breakdown") or {}),
        explanations_json=json.dumps({
            "simple": explanations.get("simple"),
            "findings": explanations.get("findings", [])[:15],
        }),
        advice_json=json.dumps(result.get("advice") or {}),
        findings_json=json.dumps(explanations.get("findings", [])[:15]),
    )
    db.session.add(scan)
    db.session.flush()

    features = EmailFeature(
        scan_id=scan.id,
        content_score=int(analyses.get("content", {}).get("score", 0)),
        url_score=int(analyses.get("url", {}).get("score", 0)),
        sender_score=int(analyses.get("sender", {}).get("score", 0)),
        auth_score=int(analyses.get("authentication", {}).get("score", 0)),
        attachment_score=int(analyses.get("attachment", {}).get("score", 0)),
        brand_score=int(analyses.get("brand", {}).get("score", 0)),
    )
    db.session.add(features)
    db.session.commit()
    return scan


def scan_to_view(scan: EmailScan) -> dict[str, Any]:
    import json

    return {
        "id": scan.id,
        "subject": scan.subject or "(no subject)",
        "sender": scan.sender or "unknown",
        "classification": scan.classification,
        "risk_score": scan.risk_score,
        "confidence": scan.confidence,
        "model_version": scan.model_version,
        "created_at": scan.created_at,
        "breakdown": json.loads(scan.breakdown_json or "{}"),
        "explanations": json.loads(scan.explanations_json or "{}"),
        "advice": json.loads(scan.advice_json or "{}"),
        "findings": json.loads(scan.findings_json or "[]"),
        "features": {
            "content": scan.features.content_score if scan.features else 0,
            "url": scan.features.url_score if scan.features else 0,
            "sender": scan.features.sender_score if scan.features else 0,
            "authentication": scan.features.auth_score if scan.features else 0,
            "attachment": scan.features.attachment_score if scan.features else 0,
            "brand": scan.features.brand_score if scan.features else 0,
        } if scan.features else {},
        "provider": scan.provider or "web",
    }
