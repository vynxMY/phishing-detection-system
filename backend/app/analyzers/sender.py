"""Sender and brand impersonation analysis."""

from __future__ import annotations

from backend.app.detection.brand_utils import (
    BRANDS,
    brand_in_hostname,
    lookalike_brand_domain,
)
from backend.app.email_parser.models import NormalizedEmail

FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "protonmail.com", "icloud.com", "live.com", "msn.com",
}


def analyze_sender(email: NormalizedEmail) -> dict:
    issues = []
    score = 0

    from_domain = email.sender.domain.lower()
    reply_domain = email.reply_to.domain.lower()
    return_path = (email.return_path or "").lower()
    return_domain = ""
    if "@" in return_path:
        return_domain = return_path.split("@")[-1].strip(">")

    if from_domain and reply_domain and from_domain != reply_domain:
        score += 35
        issues.append({
            "type": "reply_to_mismatch",
            "severity": "critical",
            "contribution": 0.25,
            "text": (
                f"Reply-To domain ({reply_domain}) differs from "
                f"sender domain ({from_domain})."
            ),
        })

    if from_domain and return_domain and from_domain != return_domain:
        score += 20
        issues.append({
            "type": "return_path_mismatch",
            "severity": "warning",
            "contribution": 0.12,
            "text": (
                f"Return-Path domain ({return_domain}) differs from "
                f"sender domain ({from_domain})."
            ),
        })

    display = (email.sender.display_name or "").lower()
    for brand, domains in BRANDS.items():
        token = brand.split()[0]
        if token in display and from_domain and domains:
            if not any(from_domain.endswith(d) for d in domains):
                score += 30
                issues.append({
                    "type": "display_name_brand_mismatch",
                    "severity": "critical",
                    "contribution": 0.22,
                    "text": (
                        f"Display name suggests {brand.title()}, but sender domain "
                        f"is {from_domain}."
                    ),
                })
                break

    lookalike = lookalike_brand_domain(from_domain)
    if lookalike:
        score += 35
        issues.append({
            "type": "lookalike_sender_domain",
            "severity": "critical",
            "contribution": 0.28,
            "text": (
                f"Sender domain '{lookalike['registered_domain']}' looks similar to "
                f"official '{lookalike['official_domain']}' "
                f"(possible {lookalike['brand'].title()} impersonation)."
            ),
        })

    return {
        "score": min(100, score),
        "from_domain": from_domain,
        "reply_to_domain": reply_domain,
        "return_path_domain": return_domain,
        "free_email_provider": from_domain in FREE_PROVIDERS,
        "issues": issues,
    }


def analyze_brand(email: NormalizedEmail) -> dict:
    text = email.combined_text().lower()
    display = (email.sender.display_name or "").lower()
    from_domain = email.sender.domain.lower()
    issues = []
    score = 0
    claimed = None

    for brand, domains in BRANDS.items():
        token = brand.split()[0]
        mentioned = token in text or token in display
        if not mentioned:
            continue
        claimed = brand
        if from_domain and domains and not any(from_domain.endswith(d) for d in domains):
            lookalike = lookalike_brand_domain(from_domain)
            if lookalike and lookalike["brand"] == brand:
                score += 40
                issues.append({
                    "type": "lookalike_domain",
                    "severity": "critical",
                    "contribution": 0.3,
                    "text": (
                        f"Sender domain '{from_domain}' looks similar to "
                        f"legitimate '{lookalike['official_domain']}' "
                        f"(possible impersonation of {brand.title()})."
                    ),
                })
            else:
                score += 25
                issues.append({
                    "type": "brand_impersonation",
                    "severity": "warning",
                    "contribution": 0.18,
                    "text": (
                        f"Message appears to reference {brand.title()}, but sender "
                        f"domain is {from_domain or 'unknown'}."
                    ),
                })
        break

    # Brand tokens inside linked hostnames (paypal.com.evil.tld)
    for u in email.urls:
        host = (u.href or "").lower()
        hit = brand_in_hostname(host)
        if hit:
            score += 35
            issues.append({
                "type": "brand_in_url_host",
                "severity": "critical",
                "contribution": 0.3,
                "text": (
                    f"A link uses '{hit['brand']}' in the hostname, but the real "
                    f"registered domain is '{hit['registered_domain']}' — not an "
                    f"official {hit['brand'].title()} domain."
                ),
            })
            claimed = claimed or hit["brand"]
            break

    return {
        "score": min(100, score),
        "claimed_brand": claimed,
        "issues": issues,
    }
