"""End-to-end detection pipeline (Sprints 5–7)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from backend.app.analyzers import (
    analyze_attachments,
    analyze_auth,
    analyze_brand,
    analyze_content,
    analyze_headers,
    analyze_reputation,
    analyze_sender,
    analyze_urls,
)
from backend.app.detection.ml_inference import MLInference
from backend.app.detection.risk_fusion import fuse_risk
from backend.app.email_parser import parse_email
from backend.app.email_parser.models import NormalizedEmail
from backend.app.explainability.explainer import build_explanations


class DetectionPipeline:
    """Parse → Analyse → ML → Risk Fusion → Explain."""

    def __init__(self, model_version: str = "v1.1.0", lazy_ml: bool = True):
        self.model_version = model_version
        self._ml: MLInference | None = None
        self._lazy_ml = lazy_ml
        if not lazy_ml:
            self._ml = MLInference(version=model_version)

    @property
    def ml(self) -> MLInference:
        if self._ml is None:
            self._ml = MLInference(version=self.model_version)
        return self._ml

    def analyze_email_object(
        self,
        email: NormalizedEmail,
        *,
        scan_attachments: bool = True,
    ) -> dict[str, Any]:
        url = analyze_urls(email)
        reputation = analyze_reputation(email)
        # Fold offline reputation into URL score (keeps DB feature schema stable)
        if reputation.get("score"):
            url["score"] = min(100, int(url.get("score", 0)) + int(reputation["score"] * 0.45))
        attachment = (
            analyze_attachments(email)
            if scan_attachments
            else {"score": 0, "count": 0, "issues": [], "details": [], "skipped": True}
        )
        return {
            "content": analyze_content(email),
            "url": url,
            "sender": analyze_sender(email),
            "header": analyze_headers(email),
            "authentication": analyze_auth(email),
            "attachment": attachment,
            "brand": analyze_brand(email),
            "reputation": reputation,
        }

    def scan(
        self,
        text: str | None = None,
        eml_path: str | Path | None = None,
        eml_bytes: bytes | None = None,
        explanation_level: str = "detailed",
        include_raw_email: bool = False,
        scan_attachments: bool = True,
    ) -> dict[str, Any]:
        email = parse_email(text=text, eml_path=eml_path, eml_bytes=eml_bytes)
        analyses = self.analyze_email_object(email, scan_attachments=scan_attachments)

        try:
            ml_result = self.ml.predict(email)
        except FileNotFoundError as exc:
            ml_result = {
                "prediction": "unknown",
                "phishing_probability": None,
                "legitimate_probability": None,
                "model_version": None,
                "error": str(exc),
            }

        risk = fuse_risk(analyses, ml_result.get("phishing_probability"))
        explanations = build_explanations(
            email, analyses, risk, ml_result, level=explanation_level
        )

        # Keep slim attachment file list for UI persistence (no bytes / no archive listing)
        analyses_public: dict[str, Any] = {}
        for key, value in analyses.items():
            if key == "attachment":
                analyses_public[key] = {
                    "score": value.get("score", 0),
                    "count": value.get("count", 0),
                    "issues": value.get("issues") or [],
                    "skipped": value.get("skipped", False),
                    "details": [
                        {
                            "filename": d.get("filename"),
                            "size_bytes": d.get("size_bytes"),
                            "score": d.get("score"),
                        }
                        for d in (value.get("details") or [])[:8]
                    ],
                }
            else:
                analyses_public[key] = {
                    kk: vv for kk, vv in value.items() if kk != "details"
                }

        result = {
            "scan_id": email.message_id,
            "risk_score": risk.risk_score,
            "classification": risk.classification,
            "confidence": risk.confidence,
            "breakdown": risk.breakdown,
            "ml": ml_result,
            "analyses": analyses_public,
            "explanations": explanations,
            "advice": explanations.get("advice"),
            "model_version": ml_result.get("model_version"),
            "email_summary": {
                "subject": email.subject,
                "sender": email.sender.email or email.sender.display_name,
                "sender_domain": email.sender.domain,
                "reply_to": email.reply_to.email,
                "url_count": len(email.urls),
                "attachment_count": len(email.attachments),
            },
        }

        if include_raw_email:
            result["email"] = email.to_dict(include_attachment_content=False)

        return result


def scan_email(**kwargs) -> dict[str, Any]:
    """Convenience function using default pipeline."""
    return DetectionPipeline().scan(**kwargs)
