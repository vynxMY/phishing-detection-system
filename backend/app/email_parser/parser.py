"""Main email parser — paste text, HTML, or .eml → NormalizedEmail."""

from __future__ import annotations

import re
from pathlib import Path

from ml.features.url_utils import extract_urls

from backend.app.email_parser.eml_parser import parse_eml_bytes, parse_eml_string
from backend.app.email_parser.html_parser import (
    extract_urls_from_html,
    html_to_plain,
    sanitize_html,
)
from backend.app.email_parser.models import (
    EmailAddress,
    EmailBody,
    EmailHeaders,
    EmailUrl,
    NormalizedEmail,
)

HEADER_LINE = re.compile(
    r"^(From|To|Cc|Subject|Date|Reply-To|Return-Path|Sender|"
    r"Authentication-Results|DKIM-Signature|Received):\s*(.*)$",
    re.IGNORECASE | re.MULTILINE,
)
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


def _parse_address_string(raw: str) -> EmailAddress:
    raw = (raw or "").strip()
    match = EMAIL_RE.search(raw)
    email = match.group(0).lower() if match else ""
    domain = email.split("@")[-1] if email else ""
    display = raw
    if "<" in raw:
        display = raw.split("<")[0].strip().strip('"')
    elif email and email in raw.lower():
        display = raw.replace(match.group(0), "").strip(" <>\"'") if match else ""
    return EmailAddress(display_name=display, email=email, domain=domain)


def _looks_like_eml(text: str) -> bool:
    head = text[:2000].lower()
    return "from:" in head and ("subject:" in head or "date:" in head or "mime-version:" in head)


def _looks_like_html(text: str) -> bool:
    lowered = text.lower()
    return "<html" in lowered or "<body" in lowered or ("<a " in lowered and "href=" in lowered)


def parse_paste_text(text: str) -> NormalizedEmail:
    """Heuristic parser for pasted email text or headers+body."""
    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        return NormalizedEmail()

    if _looks_like_eml(text):
        try:
            return _enrich_urls_from_text(parse_eml_string(text))
        except Exception:
            pass

    if _looks_like_html(text):
        html = sanitize_html(text)
        plain = html_to_plain(html)
        urls = extract_urls_from_html(html)
        email = NormalizedEmail(
            subject="",
            body=EmailBody(plain=plain, html=html),
            urls=urls,
        )
        return _enrich_urls_from_text(email)

    headers: dict[str, list[str]] = {}
    body_lines: list[str] = []
    in_body = False
    lines = text.split("\n")

    for i, line in enumerate(lines):
        if not in_body:
            if line.strip() == "" and i > 0:
                in_body = True
                continue
            m = HEADER_LINE.match(line)
            if m:
                key = m.group(1).lower()
                headers.setdefault(key, []).append(m.group(2).strip())
                continue
            # First non-header line without blank separator → treat rest as body
            if not headers:
                body_lines = lines[i:]
                break
            in_body = True
            body_lines.append(line)
        else:
            body_lines.append(line)

    body_text = "\n".join(body_lines).strip() if body_lines else text
    if not headers and not body_lines:
        body_text = text

    subject = headers.get("subject", [""])[0]
    sender = _parse_address_string(headers.get("from", [""])[0])
    reply_to = _parse_address_string(headers.get("reply-to", [""])[0])
    return_path = headers.get("return-path", [""])[0].strip("<> ")
    auth = headers.get("authentication-results", [""])[0]

    email = NormalizedEmail(
        subject=subject,
        sender=sender,
        reply_to=reply_to,
        return_path=return_path,
        recipients=[
            _parse_address_string(r).email
            for r in headers.get("to", []) + headers.get("cc", [])
            if _parse_address_string(r).email
        ],
        date=headers.get("date", [""])[0],
        body=EmailBody(plain=body_text, html=""),
        headers=EmailHeaders(
            received=headers.get("received", []),
            authentication_results=auth,
            dkim_signature=headers.get("dkim-signature", [""])[0],
            spf=_auth_token(auth, "spf"),
            dmarc=_auth_token(auth, "dmarc"),
        ),
        raw_headers={k: " | ".join(v) for k, v in headers.items()},
    )
    return _enrich_urls_from_text(email)


def parse_eml_file(path: str | Path) -> NormalizedEmail:
    data = Path(path).read_bytes()
    email = parse_eml_bytes(data)
    return _enrich_urls_from_text(email)


def parse_email(
    text: str | None = None,
    eml_path: str | Path | None = None,
    eml_bytes: bytes | None = None,
) -> NormalizedEmail:
    """Unified entry point for all input formats."""
    if eml_bytes is not None:
        email = parse_eml_bytes(eml_bytes)
        return _enrich_urls_from_text(email)
    if eml_path is not None:
        return parse_eml_file(eml_path)
    if text is not None:
        return parse_paste_text(text)
    raise ValueError("Provide text, eml_path, or eml_bytes")


def _auth_token(auth: str, mechanism: str) -> str:
    m = re.search(rf"{mechanism}\s*=\s*(\w+)", auth or "", re.IGNORECASE)
    return m.group(1).lower() if m else ""


def _enrich_urls_from_text(email: NormalizedEmail) -> NormalizedEmail:
    """Merge regex-extracted URLs from plain text into the URL list."""
    existing = {u.href for u in email.urls}
    for href in extract_urls(email.body.plain):
        if href not in existing:
            email.urls.append(EmailUrl(href=href, anchor_text="", displayed_text=href))
            existing.add(href)
    for href in extract_urls(email.subject):
        if href not in existing:
            email.urls.append(EmailUrl(href=href, anchor_text="", displayed_text=href))
            existing.add(href)
    return email
