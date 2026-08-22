"""Risk fusion engine — combine signals into 0–100 score (Sprint 6)."""

from __future__ import annotations

from dataclasses import dataclass

from backend.app.detection.rule_engine import apply_hard_rules

# Spec section 7.2 / 7.4
CATEGORY_WEIGHTS = {
    "content": 0.20,
    "url": 0.25,
    "sender": 0.15,
    "authentication": 0.15,
    "attachment": 0.15,
    "brand": 0.10,
}

THRESHOLDS = [
    (0, 19, "safe"),
    (20, 39, "low_risk"),
    (40, 59, "suspicious"),
    (60, 79, "high_risk"),
    (80, 100, "phishing"),
]


@dataclass
class RiskResult:
    risk_score: int
    classification: str
    breakdown: dict[str, int]
    contributions: dict[str, float]
    confidence: float
    floor_applied: int | None
    rule_triggers: list[dict]


def classify_score(score: int) -> str:
    score = max(0, min(100, score))
    for low, high, label in THRESHOLDS:
        if low <= score <= high:
            return label
    return "phishing"


def fuse_risk(
    analyses: dict,
    ml_phishing_probability: float | None = None,
) -> RiskResult:
    """
    Fuse category scores (+ optional ML probability) into final risk.

    Category scores are 0–100 from analysers.
    ML probability (0–1) is blended into the content category when available.
    """
    category_scores = {
        "content": int(analyses.get("content", {}).get("score", 0)),
        "url": int(analyses.get("url", {}).get("score", 0)),
        "sender": int(analyses.get("sender", {}).get("score", 0)),
        "authentication": int(analyses.get("authentication", {}).get("score", 0)),
        "attachment": int(analyses.get("attachment", {}).get("score", 0)),
        "brand": int(analyses.get("brand", {}).get("score", 0)),
    }

    # Blend ML probability into content score (keeps interpretable layer)
    if ml_phishing_probability is not None:
        ml_score = int(round(ml_phishing_probability * 100))
        category_scores["content"] = int(
            round(0.4 * category_scores["content"] + 0.6 * ml_score)
        )

    category_scores, rule_triggers, floor = apply_hard_rules(category_scores, analyses)

    # Weighted fusion → absolute contribution points that sum toward 100
    contributions: dict[str, float] = {}
    weighted_sum = 0.0
    for cat, weight in CATEGORY_WEIGHTS.items():
        contrib = weight * category_scores[cat]
        contributions[cat] = round(contrib, 2)
        weighted_sum += contrib

    risk_score = int(round(min(100, weighted_sum)))

    if floor is not None:
        risk_score = max(risk_score, floor)

    # Confidence: distance from decision boundaries + ML agreement
    confidence = _estimate_confidence(risk_score, ml_phishing_probability, category_scores)

    # Human-readable breakdown as integer "points" that sum ≈ risk_score
    breakdown = {cat: int(round(contributions[cat])) for cat in CATEGORY_WEIGHTS}
    # Adjust rounding so sum matches risk_score when no floor
    if floor is None:
        diff = risk_score - sum(breakdown.values())
        if diff != 0:
            top = max(breakdown, key=breakdown.get)
            breakdown[top] = max(0, breakdown[top] + diff)

    return RiskResult(
        risk_score=risk_score,
        classification=classify_score(risk_score),
        breakdown=breakdown,
        contributions=contributions,
        confidence=confidence,
        floor_applied=floor,
        rule_triggers=rule_triggers,
    )


def _estimate_confidence(
    risk_score: int,
    ml_prob: float | None,
    category_scores: dict[str, int],
) -> float:
    # Higher confidence when score is near extremes
    extremity = abs(risk_score - 50) / 50.0
    signal_strength = sum(1 for v in category_scores.values() if v >= 40) / len(category_scores)
    ml_factor = 0.5
    if ml_prob is not None:
        ml_factor = abs(ml_prob - 0.5) * 2
    confidence = 0.4 * extremity + 0.3 * signal_strength + 0.3 * ml_factor
    return round(min(1.0, max(0.0, confidence)), 3)
