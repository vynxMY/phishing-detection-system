"""HTML sanitization and link extraction."""

from __future__ import annotations

import re
from html import unescape

import bleach
from bs4 import BeautifulSoup

from backend.app.email_parser.models import EmailUrl

ALLOWED_TAGS = [
    "p", "br", "div", "span", "a", "b", "i", "u", "strong", "em",
    "ul", "ol", "li", "table", "tr", "td", "th", "thead", "tbody",
    "h1", "h2", "h3", "h4", "h5", "h6", "img",
]
ALLOWED_ATTRIBUTES = {
    "a": ["href", "title"],
    "img": ["src", "alt"],
}


def sanitize_html(html: str) -> str:
    """Strip scripts and active content; keep safe tags."""
    if not html:
        return ""
    return bleach.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True,
    )


def html_to_plain(html: str) -> str:
    """Extract visible text from HTML."""
    if not html:
        return ""
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style"]):
        tag.decompose()
    text = soup.get_text(separator="\n")
    text = unescape(text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def extract_urls_from_html(html: str) -> list[EmailUrl]:
    """Extract href/anchor pairs from HTML."""
    if not html:
        return []
    soup = BeautifulSoup(html, "lxml")
    urls: list[EmailUrl] = []
    seen: set[str] = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("mailto:", "tel:", "#")):
            continue
        if href in seen:
            continue
        seen.add(href)
        anchor = a.get_text(strip=True)
        urls.append(
            EmailUrl(
                href=href,
                anchor_text=anchor,
                displayed_text=anchor,
            )
        )
    return urls
