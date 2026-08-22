"""URL analysis signals for risk scoring."""

from __future__ import annotations

from urllib.parse import urlparse

from ml.features.url_utils import parse_url_parts

from backend.app.email_parser.models import NormalizedEmail


def _domains_look_similar(a: str, b: str) -> bool:
    """Simple display/href domain mismatch check."""
    a = a.lower().removeprefix("www.")
    b = b.lower().removeprefix("www.")
    if not a or not b:
        return True
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def analyze_urls(email: NormalizedEmail) -> dict:
    urls = email.urls
    if not urls:
        return {
            "score": 0,
            "url_count": 0,
            "issues": [],
            "details": [],
        }

    issues: list[dict] = []
    score = 0
    details = []

    for u in urls:
        parts = parse_url_parts(u.href)
        if not parts:
            continue
        details.append(parts)
        hostname = urlparse(parts["url"]).hostname or ""

        if parts.get("has_ip"):
            score += 25
            issues.append({"type": "ip_url", "severity": "critical", "url": u.href,
                           "text": "URL uses a raw IP address instead of a domain name."})
        if parts.get("has_shortener"):
            score += 20
            issues.append({"type": "shortener", "severity": "warning", "url": u.href,
                           "text": f"URL uses a known shortening service ({hostname})."})
        if parts.get("has_suspicious_tld"):
            score += 25
            issues.append({"type": "suspicious_tld", "severity": "critical", "url": u.href,
                           "text": f"URL uses a suspicious top-level domain ({hostname})."})
        if parts.get("has_punycode"):
            score += 25
            issues.append({"type": "punycode", "severity": "critical", "url": u.href,
                           "text": "URL contains punycode (possible homograph attack)."})
        if parts.get("subdomain_count", 0) >= 3:
            score += 10
            issues.append({"type": "deep_subdomain", "severity": "warning", "url": u.href,
                           "text": "URL has an unusually deep subdomain structure."})
        if not parts.get("has_https"):
            score += 5

        # Anchor mismatch
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
                    "text": (
                        f"Displayed destination ({disp_host}) does not match "
                        f"the actual domain ({hostname})."
                    ),
                })

    # Cap and scale by count presence
    score = min(100, score + min(15, len(urls) * 3))

    # Deduplicate issues by type+url
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
