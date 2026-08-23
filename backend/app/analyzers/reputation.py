"""Local domain reputation heuristics (no external APIs).

WHOIS / VirusTotal-style live reputation are PSM Startup.
This module uses offline signals: trusted brand domains, suspicious TLDs,
phishing keyword hosts, and "new-looking" domain shape proxies.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ml.features.url_utils import SUSPICIOUS_TLDS, parse_url_parts

from backend.app.detection.brand_utils import BRANDS, registered_domain
from backend.app.email_parser.models import NormalizedEmail

# Tokens often used in disposable / newly registered phishing hosts
PHISH_HOST_TOKENS = re.compile(
    r"(login|signin|sign-in|secure|verify|verification|account|update|confirm|"
    r"support|security|wallet|billing|recovery|authenticate|webmail)",
    re.I,
)

# Domains treated as higher trust when they match exactly (offline allowlist)
TRUSTED_DOMAINS: set[str] = set()
for _domains in BRANDS.values():
    TRUSTED_DOMAINS.update(_domains)


def _host_from_url(href: str) -> str:
    try:
        host = urlparse(href if "://" in href else "http://" + href).hostname or ""
    except ValueError:
        return ""
    return host.lower().removeprefix("www.")


def _new_looking_domain(reg: str) -> bool:
    """Proxy for 'recently registered' without WHOIS: digit-heavy / random SLD."""
    if not reg or "." not in reg:
        return False
    sld = reg.rsplit(".", 1)[0]
    if not sld:
        return False
    digits = sum(ch.isdigit() for ch in sld)
    if digits >= 3 and digits / max(1, len(sld)) >= 0.35:
        return True
    if len(sld) >= 16 and sum(ch.isalpha() for ch in sld) >= 12:
        # Long alphabetic SLD without common separators → often auto-generated
        if "-" not in sld and digits >= 2:
            return True
    return False


def analyze_reputation(email: NormalizedEmail) -> dict:
    """Score domain reputation for sender + linked hosts."""
    issues: list[dict] = []
    score = 0
    hosts: list[str] = []

    sender_domain = (email.sender.domain or "").lower().removeprefix("www.")
    if sender_domain:
        hosts.append(sender_domain)

    for u in email.urls:
        host = _host_from_url(u.href)
        if host and host not in hosts:
            hosts.append(host)

    trusted_hits = 0
    suspicious_hits = 0

    for host in hosts:
        reg = registered_domain(host)
        parts = parse_url_parts("https://" + host) if host else {}

        if reg in TRUSTED_DOMAINS or any(reg.endswith("." + d) for d in TRUSTED_DOMAINS):
            trusted_hits += 1
            continue

        if any(host.endswith(tld) or reg.endswith(tld) for tld in SUSPICIOUS_TLDS):
            suspicious_hits += 1
            score += 18
            issues.append({
                "type": "suspicious_tld_reputation",
                "severity": "warning",
                "contribution": 0.12,
                "domain": reg or host,
                "text": f"Domain '{reg or host}' uses a TLD frequently abused in phishing campaigns.",
            })

        if PHISH_HOST_TOKENS.search(host):
            score += 15
            issues.append({
                "type": "phishing_keyword_host",
                "severity": "warning",
                "contribution": 0.12,
                "domain": reg or host,
                "text": (
                    f"Hostname '{host}' contains login/security keywords that "
                    "are common in phishing domains."
                ),
            })

        if _new_looking_domain(reg):
            score += 12
            issues.append({
                "type": "new_looking_domain",
                "severity": "info",
                "contribution": 0.08,
                "domain": reg,
                "text": (
                    f"Domain '{reg}' looks newly generated (digit-heavy or unusual shape). "
                    "This is a proxy signal — not a live WHOIS age lookup."
                ),
            })

        if parts.get("has_shortener"):
            score += 10
            issues.append({
                "type": "shortener_reputation",
                "severity": "warning",
                "contribution": 0.1,
                "domain": host,
                "text": f"Shortened URL host '{host}' hides the final destination.",
            })

    if trusted_hits and not suspicious_hits and score == 0:
        issues.append({
            "type": "trusted_domain",
            "severity": "info",
            "contribution": -0.05,
            "text": "Sender or linked domain matches a known official brand domain (offline allowlist).",
        })

    # Cap and de-dupe by type+domain
    seen: set[tuple] = set()
    unique: list[dict] = []
    for issue in issues:
        key = (issue.get("type"), issue.get("domain"), issue.get("text"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(issue)

    return {
        "score": min(100, score),
        "hosts_checked": hosts[:20],
        "trusted_hits": trusted_hits,
        "issues": unique[:12],
    }
