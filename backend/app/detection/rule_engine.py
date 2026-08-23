"""Hard-rule engine for risk boosts (Sprint 6)."""

from __future__ import annotations


def apply_hard_rules(
    category_scores: dict[str, int],
    analyses: dict,
) -> tuple[dict[str, int], list[dict], int | None]:
    """
    Apply hard rules.

    Returns:
        updated category scores, rule-triggered explanations, optional floor score
    """
    scores = dict(category_scores)
    triggered: list[dict] = []
    floor: int | None = None

    attachment_issues = analyses.get("attachment", {}).get("issues", [])
    has_ext_mismatch = any(i.get("type") == "extension_mismatch" for i in attachment_issues)
    has_dangerous = any(i.get("type") == "dangerous_type" for i in attachment_issues)

    if has_ext_mismatch or has_dangerous:
        scores["attachment"] = min(100, scores.get("attachment", 0) + 30)
        floor = 80
        triggered.append({
            "type": "hard_rule",
            "rule": "dangerous_attachment",
            "severity": "critical",
            "category": "attachment",
            "text": "Dangerous attachment pattern detected — risk floor raised to 80.",
        })

    auth = analyses.get("authentication", {})
    sender = analyses.get("sender", {})
    urls = analyses.get("url", {})

    spf_fail = auth.get("spf") == "fail"
    reply_mismatch = any(i.get("type") == "reply_to_mismatch" for i in sender.get("issues", []))
    suspicious_url = any(
        i.get("severity") in ("critical", "warning")
        for i in urls.get("issues", [])
    ) or urls.get("score", 0) >= 40

    if spf_fail and reply_mismatch and suspicious_url:
        floor = max(floor or 0, 70)
        triggered.append({
            "type": "hard_rule",
            "rule": "spf_reply_url_combo",
            "severity": "critical",
            "category": "authentication",
            "text": (
                "SPF fail + Reply-To mismatch + suspicious URL — "
                "risk floor raised to 70."
            ),
        })

    brand_issues = analyses.get("brand", {}).get("issues", [])
    url_issues = analyses.get("url", {}).get("issues", [])
    brand_impersonation = any(
        i.get("type") in ("brand_in_url_host", "lookalike_domain", "brand_in_subdomain", "lookalike_url_domain")
        for i in brand_issues + url_issues
    )
    credential_ask = any(
        i.get("type") == "credential_request"
        for i in analyses.get("content", {}).get("issues", [])
    )
    if brand_impersonation and (credential_ask or suspicious_url):
        floor = max(floor or 0, 85)
        triggered.append({
            "type": "hard_rule",
            "rule": "brand_impersonation_combo",
            "severity": "critical",
            "category": "brand",
            "text": (
                "Brand impersonation combined with a credential request or suspicious URL — "
                "risk floor raised to 85."
            ),
        })

    return scores, triggered, floor
