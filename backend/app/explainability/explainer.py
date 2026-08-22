"""Explainability engine — simple / detailed / technical (Sprint 7)."""

from __future__ import annotations

from backend.app.email_parser.models import NormalizedEmail
from backend.app.explainability.advice import generate_advice
from backend.app.explainability.counterfactual import generate_counterfactual
from backend.app.explainability.highlighter import highlight_suspicious_text


SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def build_explanations(
    email: NormalizedEmail,
    analyses: dict,
    risk_result,
    ml_result: dict,
    level: str = "simple",
) -> dict:
    """Build multi-level explanations from analysis results."""
    findings = _collect_findings(analyses, risk_result)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["category"]))

    triggered_cats = list({f["category"] for f in findings if f["severity"] in ("critical", "warning")})
    advice = generate_advice(risk_result.classification, triggered_cats)
    highlights = highlight_suspicious_text(email.body.plain or email.combined_text())

    simple = _simple_summary(risk_result, findings)
    detailed = {
        "findings": findings,
        "breakdown": risk_result.breakdown,
        "categories": _detailed_by_category(analyses, findings),
        "highlights": highlights,
    }
    technical = {
        "model_version": ml_result.get("model_version"),
        "ml_prediction": ml_result.get("prediction"),
        "ml_phishing_probability": ml_result.get("phishing_probability"),
        "category_scores": {
            "content": analyses.get("content", {}).get("score", 0),
            "url": analyses.get("url", {}).get("score", 0),
            "sender": analyses.get("sender", {}).get("score", 0),
            "authentication": analyses.get("authentication", {}).get("score", 0),
            "attachment": analyses.get("attachment", {}).get("score", 0),
            "brand": analyses.get("brand", {}).get("score", 0),
        },
        "contributions": risk_result.contributions,
        "floor_applied": risk_result.floor_applied,
        "rule_triggers": risk_result.rule_triggers,
        "confidence": risk_result.confidence,
        "auth": {
            "spf": analyses.get("authentication", {}).get("spf"),
            "dkim": analyses.get("authentication", {}).get("dkim"),
            "dmarc": analyses.get("authentication", {}).get("dmarc"),
        },
    }

    counterfactual = None
    if level in ("detailed", "technical", "all"):
        counterfactual = generate_counterfactual(
            analyses,
            risk_result.risk_score,
            ml_result.get("phishing_probability"),
        )

    payload = {
        "level": level,
        "simple": simple,
        "advice": advice,
        "findings": findings[:10],
    }

    if level in ("detailed", "all"):
        payload["detailed"] = detailed
        payload["counterfactual"] = counterfactual
    if level in ("technical", "all"):
        payload["technical"] = technical
        payload["counterfactual"] = counterfactual
    if level == "simple":
        # Always include light highlights for UI
        payload["highlight_count"] = highlights["span_count"]

    return payload


def _collect_findings(analyses: dict, risk_result) -> list[dict]:
    findings = []
    for category in ("url", "sender", "authentication", "attachment", "brand", "content"):
        for issue in analyses.get(category, {}).get("issues", []):
            findings.append({
                "category": category,
                "type": issue.get("type", "signal"),
                "severity": issue.get("severity", "info"),
                "text": issue.get("text", ""),
                "feature": issue.get("type"),
            })
        # Content: synthesise findings from matched phrases
        if category == "content":
            phrases = analyses.get("content", {}).get("matched_phrases", [])
            if phrases:
                findings.append({
                    "category": "content",
                    "type": "suspicious_language",
                    "severity": "warning" if analyses["content"].get("score", 0) >= 40 else "info",
                    "text": f"Suspicious language detected: {', '.join(phrases[:6])}.",
                    "feature": "matched_phrases",
                })

    for rule in risk_result.rule_triggers:
        findings.append({
            "category": rule.get("category", "rule"),
            "type": rule.get("rule", "hard_rule"),
            "severity": rule.get("severity", "critical"),
            "text": rule.get("text", ""),
            "feature": rule.get("rule"),
        })
    return findings


def _simple_summary(risk_result, findings: list[dict]) -> str:
    label = risk_result.classification.replace("_", " ").upper()
    critical = [f for f in findings if f["severity"] == "critical"]
    warnings = [f for f in findings if f["severity"] == "warning"]

    if risk_result.classification == "safe":
        return (
            f"This email appears safe (risk score {risk_result.risk_score}/100). "
            "No strong phishing indicators were found."
        )

    reasons = []
    for f in (critical + warnings)[:3]:
        reasons.append(f["text"].rstrip("."))
    if not reasons:
        reasons.append("multiple weak phishing indicators were present")

    reason_text = "; ".join(reasons)
    return (
        f"This email is classified as {label} "
        f"(risk score {risk_result.risk_score}/100) because {reason_text}."
    )


def _detailed_by_category(analyses: dict, findings: list[dict]) -> dict:
    out = {}
    for cat in ("content", "url", "sender", "authentication", "attachment", "brand"):
        out[cat] = {
            "score": analyses.get(cat, {}).get("score", 0),
            "findings": [f for f in findings if f["category"] == cat],
        }
    return out
