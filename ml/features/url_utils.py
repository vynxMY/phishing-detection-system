"""URL extraction and normalization from email text."""

from __future__ import annotations

import re
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


def normalize_obfuscated_text(text: str) -> str:
    """Collapse spaces within common URL obfuscation patterns."""
    # www . foo . bar . com -> www.foo.bar.com
    text = re.sub(
        r"(www)\s*\.\s*",
        r"\1.",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\s*\.\s*(com|org|net|edu|gov|io|co|uk|de|fr|info|biz|ru|cn)\b",
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


def parse_url_parts(url: str) -> dict:
    """Parse a single URL into feature-relevant components."""
    url = _ensure_scheme(url)
    try:
        parsed = urlparse(url)
    except ValueError:
        return {}

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    parts = hostname.split(".") if hostname else []

    return {
        "url": url,
        "length": len(url),
        "domain_length": len(hostname),
        "subdomain_count": max(0, len(parts) - 2),
        "path_length": len(path),
        "has_https": int(parsed.scheme.lower() == "https"),
        "has_ip": int(bool(IP_IN_URL.search(url))),
        "has_port": int(parsed.port is not None),
        "has_shortener": int(any(s in hostname.lower() for s in URL_SHORTENERS)),
        "has_suspicious_tld": int(any(hostname.lower().endswith(tld) for tld in SUSPICIOUS_TLDS)),
        "has_punycode": int(bool(PUNYCODE_PATTERN.search(url))),
    }
