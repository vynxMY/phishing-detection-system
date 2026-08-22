"""End-to-end detection pipeline (Sprints 5–7)."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from backend.app.analyzers import (
    analyze_attachments,
    analyze_auth,
    analyze_brand,
    analyze_content,
    analyze_headers,
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

    def __init__(self, model_version: str = "v1.0.0", lazy_ml: bool = True):
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

    def analyze_email_object(self, email: NormalizedEmail) -> dict[str, Any]:
        return {
            "content": analyze_content(email),
            "url": analyze_urls(email),
            "sender": analyze_sender(email),
            "header": analyze_headers(email),
            "authentication": analyze_auth(email),
            "attachment": analyze_attachments(email),
            "brand": analyze_brand(email),
        }

    def scan(
        self,
        text: str | None = None,
        eml_path: str | Path | None = None,
        eml_bytes: bytes | None = None,
        explanation_level: str = "detailed",
        include_raw_email: bool = False,
    ) -> dict[str, Any]:
        email = parse_email(text=text, eml_path=eml_path, eml_bytes=eml_bytes)
        analyses = self.analyze_email_object(email)

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

        result = {
            "scan_id": email.message_id,
            "risk_score": risk.risk_score,
            "classification": risk.classification,
            "confidence": risk.confidence,
            "breakdown": risk.breakdown,
            "ml": ml_result,
            "analyses": {
                k: {kk: vv for kk, vv in v.items() if kk != "details"}
                for k, v in analyses.items()
            },
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
