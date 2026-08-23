"""Counterfactual explanations (Sprint 7 — Extension)."""

from __future__ import annotations

from backend.app.detection.risk_fusion import fuse_risk


def generate_counterfactual(analyses: dict, current_score: int, ml_prob: float | None) -> dict:
    """
    Estimate how risk would change if key signals were flipped to safe values.

    This re-runs fusion on a perturbed analysis dict. Marked as estimated.
    """
    current = {
        "SPF": analyses.get("authentication", {}).get("spf", "none"),
        "Reply-To mismatch": any(
            i.get("type") == "reply_to_mismatch"
            for i in analyses.get("sender", {}).get("issues", [])
        ),
        "Suspicious URL": any(
            i.get("severity") == "critical"
            for i in analyses.get("url", {}).get("issues", [])
        ),
        "Dangerous attachment": any(
            i.get("severity") == "critical"
            for i in analyses.get("attachment", {}).get("issues", [])
        ),
    }

    # Build safe-ish copy
    perturbed = {
        "content": {**analyses.get("content", {}), "score": min(analyses.get("content", {}).get("score", 0), 20)},
        "url": {"score": 0, "issues": [], "url_count": analyses.get("url", {}).get("url_count", 0)},
        "sender": {
            **analyses.get("sender", {}),
            "score": 0,
            "issues": [],
        },
        "authentication": {
            "score": 0,
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
            "issues": [],
            "available": True,
        },
        "attachment": {"score": 0, "count": analyses.get("attachment", {}).get("count", 0), "issues": []},
        "brand": {"score": 0, "issues": [], "claimed_brand": analyses.get("brand", {}).get("claimed_brand")},
    }

    estimated = fuse_risk(perturbed, ml_phishing_probability=min(ml_prob or 0.2, 0.3))
    delta = current_score - estimated.risk_score
    if delta > 0:
        summary = (
            f"If authentication passed and the suspicious URL/sender/attachment signals "
            f"were removed, estimated risk would drop by about {delta} points "
            f"(to ~{estimated.risk_score}/100)."
        )
    else:
        summary = (
            "Even after removing common phishing signals, estimated risk stays elevated — "
            "review the message carefully."
        )

    return {
        "current_risk": current_score,
        "estimated_risk": estimated.risk_score,
        "delta": delta,
        "summary": summary,
        "current_signals": {
            k: ("FAIL" if v == "fail" else ("YES" if v is True else ("NO" if v is False else str(v).upper())))
            for k, v in current.items()
        },
        "if_changed_to": {
            "SPF": "PASS",
            "Reply-To mismatch": "NO",
            "Suspicious URL": "NO",
            "Dangerous attachment": "NO",
        },
        "note": "Estimated only — not a guarantee. Based on re-running the risk fusion engine.",
    }
