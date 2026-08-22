"""Sender and brand impersonation analysis."""

from __future__ import annotations

import re

from backend.app.email_parser.models import NormalizedEmail

BRANDS = {
    "microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.co.uk"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "netflix": ["netflix.com"],
    "bank": [],  # generic keyword only
}

FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "protonmail.com", "icloud.com", "live.com", "msn.com",
}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


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
            "text": (
                f"Return-Path domain ({return_domain}) differs from "
                f"sender domain ({from_domain})."
            ),
        })

    display = (email.sender.display_name or "").lower()
    for brand, domains in BRANDS.items():
        if brand in display and from_domain and not any(from_domain.endswith(d) for d in domains or [brand + ".com"]):
            if domains and not any(from_domain.endswith(d) for d in domains):
                score += 30
                issues.append({
                    "type": "display_name_brand_mismatch",
                    "severity": "critical",
                    "text": (
                        f"Display name suggests {brand.title()}, but sender domain "
                        f"is {from_domain}."
                    ),
                })
                break

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
        if brand == "bank":
            continue
        mentioned = brand in text or brand in display
        if not mentioned:
            continue
        claimed = brand
        if from_domain and domains and not any(from_domain.endswith(d) for d in domains):
            # Check lookalike domain
            for legit in domains:
                base = legit.split(".")[0]
                if base in from_domain and from_domain != legit:
                    dist = _levenshtein(from_domain, legit)
                    if 0 < dist <= 3:
                        score += 40
                        issues.append({
                            "type": "lookalike_domain",
                            "severity": "critical",
                            "text": (
                                f"Sender domain '{from_domain}' looks similar to "
                                f"legitimate '{legit}' (possible impersonation of {brand.title()})."
                            ),
                        })
                        break
            else:
                score += 25
                issues.append({
                    "type": "brand_impersonation",
                    "severity": "warning",
                    "text": (
                        f"Message appears to reference {brand.title()}, but sender "
                        f"domain is {from_domain or 'unknown'}."
                    ),
                })
        break

    return {
        "score": min(100, score),
        "claimed_brand": claimed,
        "issues": issues,
    }
