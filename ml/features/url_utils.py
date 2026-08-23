"""URL extraction and normalization from email text."""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlparse

# Standard URLs
URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+|www\.[^\s<>\"']+",
    re.IGNORECASE,
)

# Obfuscated URLs: www . domain . com or http : // ...
OBFUSCATED_URL_PATTERN = re.compile(
    r"(?:https?\s*:\s*//|www)\s*[\w\s.\-]+",
    re.IGNORECASE,
)

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "cutt.ly", "rb.gy", "shorturl.at",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".link", ".tk",
    ".ml", ".ga", ".cf", ".gq", ".buzz", ".cam", ".rest", ".surf",
}

IP_IN_URL = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.IGNORECASE)
PUNYCODE_PATTERN = re.compile(r"xn--", re.IGNORECASE)
LOGIN_PATH = re.compile(
    r"/(login|signin|sign-in|verify|secure|account|update|password|credential)",
    re.I,
)


def normalize_obfuscated_text(text: str) -> str:
    """Collapse spaces within common URL obfuscation patterns."""
    text = re.sub(r"(www)\s*\.\s*", r"\1.", text, flags=re.IGNORECASE)
    text = re.sub(
        r"\s*\.\s*(com|org|net|edu|gov|io|co|uk|de|fr|info|biz|ru|cn|my)\b",
        r".\1",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"https?\s*:\s*//", "https://", text, flags=re.IGNORECASE)
    return text


def extract_urls(text: str) -> list[str]:
    """Extract and deduplicate URLs from email text."""
    if not text:
        return []

    normalized = normalize_obfuscated_text(str(text))
    urls: list[str] = []

    for pattern in (URL_PATTERN, OBFUSCATED_URL_PATTERN):
        for match in pattern.finditer(normalized):
            url = match.group(0).strip().rstrip(".,;:!?)")
            if len(url) >= 7 and url not in urls:
                urls.append(url)

    return urls


def _ensure_scheme(url: str) -> str:
    if url.lower().startswith("www."):
        return "http://" + url
    return url


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def parse_url_parts(url: str) -> dict:
    """Parse a single URL into feature-relevant components.

    Core keys (length, has_https, has_ip, …) stay stable for the trained LR
    URL feature extractor. Extra keys support runtime URL analysis / explanations.
    """
    url = _ensure_scheme(url)
    try:
        parsed = urlparse(url)
    except ValueError:
        return {}

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    parts = hostname.split(".") if hostname else []
    host_no_www = hostname.removeprefix("www.")

    return {
        # Stable keys used by ML URLFeatureExtractor v1.x
        "url": url,
        "length": len(url),
        "domain_length": len(hostname),
        "subdomain_count": max(0, len(parts) - 2),
        "path_length": len(path),
        "has_https": int(parsed.scheme.lower() == "https"),
        "has_ip": int(bool(IP_IN_URL.search(url))),
        "has_port": int(parsed.port is not None),
        "has_shortener": int(any(s in hostname for s in URL_SHORTENERS)),
        "has_suspicious_tld": int(any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)),
        "has_punycode": int(bool(PUNYCODE_PATTERN.search(url))),
        # Phase-1 enrichment for analyzers / explainability
        "dot_count": host_no_www.count("."),
        "hyphen_count": host_no_www.count("-"),
        "digit_count": sum(ch.isdigit() for ch in host_no_www),
        "query_param_count": len([p for p in query.split("&") if p]) if query else 0,
        "entropy": round(_shannon_entropy(host_no_www), 4),
        "has_at": int("@" in url),
        "has_login_path": int(bool(LOGIN_PATH.search(path))),
        "hostname": hostname,
    }
