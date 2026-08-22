"""RFC 822 / .eml parsing."""

from __future__ import annotations

import base64
import re
from email import policy
from email.header import decode_header, make_header
from email.message import Message
from email.parser import BytesParser, Parser
from email.utils import parseaddr

from backend.app.email_parser.html_parser import (
    extract_urls_from_html,
    html_to_plain,
    sanitize_html,
)
from backend.app.email_parser.models import (
    EmailAddress,
    EmailAttachment,
    EmailBody,
    EmailHeaders,
    EmailUrl,
    NormalizedEmail,
)


def _decode_header_value(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _parse_address(raw: str | None) -> EmailAddress:
    display, addr = parseaddr(raw or "")
    display = _decode_header_value(display)
    addr = addr.lower().strip()
    domain = addr.split("@")[-1] if "@" in addr else ""
    return EmailAddress(display_name=display, email=addr, domain=domain)


def _get_payload_text(part: Message) -> tuple[str, str]:
    """Return (plain, html) from a MIME part."""
    content_type = part.get_content_type()
    try:
        payload = part.get_content()
    except Exception:
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            charset = part.get_content_charset() or "utf-8"
            payload = payload.decode(charset, errors="replace")

    if not isinstance(payload, str):
        return "", ""

    if content_type == "text/html":
        return "", payload
    if content_type == "text/plain":
        return payload, ""
    return payload, ""


def parse_eml_bytes(data: bytes) -> NormalizedEmail:
    message = BytesParser(policy=policy.default).parsebytes(data)
    return _message_to_normalized(message)


def parse_eml_string(text: str) -> NormalizedEmail:
    message = Parser(policy=policy.default).parsestr(text)
    return _message_to_normalized(message)


def _message_to_normalized(message: Message) -> NormalizedEmail:
    subject = _decode_header_value(message.get("Subject"))
    sender = _parse_address(message.get("From"))
    reply_to = _parse_address(message.get("Reply-To"))
    return_path = (message.get("Return-Path") or "").strip("<> ")

    recipients = []
    for field in ("To", "Cc"):
        value = message.get(field)
        if value:
            for part in value.split(","):
                addr = _parse_address(part)
                if addr.email:
                    recipients.append(addr.email)

    date = message.get("Date") or ""

    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[EmailAttachment] = []

    if message.is_multipart():
        for part in message.walk():
            disposition = str(part.get("Content-Disposition") or "").lower()
            filename = part.get_filename()
            if filename or "attachment" in disposition:
                payload = part.get_payload(decode=True) or b""
                attachments.append(
                    EmailAttachment(
                        filename=_decode_header_value(filename) or "attachment",
                        content_type=part.get_content_type(),
                        size_bytes=len(payload),
                        content_base64=base64.b64encode(payload).decode("ascii"),
                    )
                )
                continue
            if part.get_content_maintype() == "multipart":
                continue
            p, h = _get_payload_text(part)
            if p:
                plain_parts.append(p)
            if h:
                html_parts.append(h)
    else:
        p, h = _get_payload_text(message)
        if p:
            plain_parts.append(p)
        if h:
            html_parts.append(h)

    html = sanitize_html("\n".join(html_parts))
    plain = "\n".join(plain_parts).strip()
    if not plain and html:
        plain = html_to_plain(html)

    urls = extract_urls_from_html(html)
    # Also collect text URLs later in main parser

    auth_results = message.get("Authentication-Results") or ""
    headers = EmailHeaders(
        received=[str(v) for v in message.get_all("Received", [])],
        authentication_results=auth_results,
        dkim_signature=message.get("DKIM-Signature") or "",
        spf=_extract_auth_token(auth_results, "spf"),
        dmarc=_extract_auth_token(auth_results, "dmarc"),
    )

    raw_headers = {k: _decode_header_value(v) for k, v in message.items()}

    return NormalizedEmail(
        subject=subject,
        sender=sender,
        reply_to=reply_to,
        return_path=return_path,
        recipients=recipients,
        date=str(date),
        body=EmailBody(plain=plain, html=html),
        urls=urls,
        attachments=attachments,
        headers=headers,
        raw_headers=raw_headers,
    )


def _extract_auth_token(auth_results: str, mechanism: str) -> str:
    match = re.search(rf"{mechanism}\s*=\s*(\w+)", auth_results, re.IGNORECASE)
    return match.group(1).lower() if match else ""
