"""URL analysis signals for risk scoring and explanations."""

from __future__ import annotations

from urllib.parse import urlparse

from ml.features.url_utils import parse_url_parts

from backend.app.detection.brand_utils import brand_in_hostname, lookalike_brand_domain
from backend.app.email_parser.models import NormalizedEmail


def _domains_look_similar(a: str, b: str) -> bool:
    a = a.lower().removeprefix("www.")
    b = b.lower().removeprefix("www.")
    if not a or not b:
        return True
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def analyze_urls(email: NormalizedEmail) -> dict:
    urls = email.urls
    if not urls:
        return {"score": 0, "url_count": 0, "issues": [], "details": []}

    issues: list[dict] = []
    score = 0
    details = []

    for u in urls:
        parts = parse_url_parts(u.href)
        if not parts:
            continue
        details.append(parts)
        hostname = parts.get("hostname") or (urlparse(parts["url"]).hostname or "")

        if parts.get("has_ip"):
            score += 25
            issues.append({
                "type": "ip_url",
                "severity": "critical",
                "url": u.href,
                "contribution": 0.25,
                "text": "URL uses a raw IP address instead of a domain name.",
            })
        if parts.get("has_shortener"):
            score += 20
            issues.append({
                "type": "shortener",
                "severity": "warning",
                "url": u.href,
                "contribution": 0.15,
                "text": f"URL uses a known shortening service ({hostname}).",
            })
        if parts.get("has_suspicious_tld"):
            score += 25
            issues.append({
                "type": "suspicious_tld",
                "severity": "critical",
                "url": u.href,
                "contribution": 0.2,
                "text": f"URL uses a suspicious top-level domain ({hostname}).",
            })
        if parts.get("has_punycode"):
            score += 25
            issues.append({
                "type": "punycode",
                "severity": "critical",
                "url": u.href,
                "contribution": 0.2,
                "text": "URL contains punycode (possible homograph attack).",
            })
        if parts.get("has_at"):
            score += 30
            issues.append({
                "type": "at_in_url",
                "severity": "critical",
                "url": u.href,
                "contribution": 0.25,
                "text": "URL contains '@', which can hide the real destination.",
            })
        if parts.get("subdomain_count", 0) >= 3:
            score += 12
            issues.append({
                "type": "deep_subdomain",
                "severity": "warning",
                "url": u.href,
                "contribution": 0.12,
                "text": "URL has an unusually deep subdomain structure.",
            })
        if parts.get("hyphen_count", 0) >= 3:
            score += 8
            issues.append({
                "type": "many_hyphens",
                "severity": "warning",
                "url": u.href,
                "contribution": 0.08,
                "text": "Domain contains many hyphens, which is common in phishing hosts.",
            })
        if parts.get("length", 0) >= 90:
            score += 8
            issues.append({
                "type": "long_url",
                "severity": "info",
                "url": u.href,
                "contribution": 0.06,
                "text": "URL is unusually long.",
            })
        if parts.get("has_login_path"):
            score += 10
            issues.append({
                "type": "login_path",
                "severity": "warning",
                "url": u.href,
                "contribution": 0.1,
                "text": "URL path looks like a login or account-verification page.",
            })
        if parts.get("entropy", 0) >= 3.5 and parts.get("domain_length", 0) >= 20:
            score += 8
            issues.append({
                "type": "high_entropy_host",
                "severity": "warning",
                "url": u.href,
                "contribution": 0.08,
                "text": "Hostname looks randomly generated (high character entropy).",
            })
        if not parts.get("has_https"):
            score += 5

        brand_hit = brand_in_hostname(hostname)
        if brand_hit:
            score += 35
            brand = brand_hit["brand"].title()
            reg = brand_hit["registered_domain"]
            issues.append({
                "type": "brand_in_subdomain",
                "severity": "critical",
                "url": u.href,
                "contribution": 0.3,
                "text": (
                    f"This link appears to impersonate {brand}. "
                    f"The registered domain is '{reg}', while '{brand_hit['brand']}' "
                    "only appears in a subdomain or path-like hostname segment."
                ),
            })

        lookalike = lookalike_brand_domain(hostname)
        if lookalike:
            score += 30
            issues.append({
                "type": "lookalike_url_domain",
                "severity": "critical",
                "url": u.href,
                "contribution": 0.28,
                "text": (
                    f"Domain '{lookalike['registered_domain']}' looks similar to "
                    f"official '{lookalike['official_domain']}' "
                    f"(possible {lookalike['brand'].title()} impersonation)."
                ),
            })

        displayed = (u.displayed_text or u.anchor_text or "").strip()
        if displayed and ("http" in displayed.lower() or "www." in displayed.lower()):
            try:
                disp_host = urlparse(
                    displayed if "://" in displayed else "http://" + displayed
                ).hostname or ""
            except Exception:
                disp_host = ""
            if disp_host and hostname and not _domains_look_similar(disp_host, hostname):
                score += 30
                issues.append({
                    "type": "anchor_mismatch",
                    "severity": "critical",
                    "url": u.href,
                    "contribution": 0.28,
                    "text": (
                        f"Displayed destination ({disp_host}) does not match "
                        f"the actual domain ({hostname})."
                    ),
                })

    score = min(100, score + min(15, len(urls) * 3))

    seen = set()
    unique_issues = []
    for issue in issues:
        key = (issue.get("type"), issue.get("url"))
        if key in seen:
            continue
        seen.add(key)
        unique_issues.append(issue)

    return {
        "score": score,
        "url_count": len(urls),
        "issues": unique_issues,
        "details": details,
    }
