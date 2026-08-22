"""Normalized email data model (Sprint 5)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4


@dataclass
class EmailAddress:
    display_name: str = ""
    email: str = ""
    domain: str = ""


@dataclass
class EmailBody:
    plain: str = ""
    html: str = ""


@dataclass
class EmailUrl:
    href: str = ""
    anchor_text: str = ""
    displayed_text: str = ""


@dataclass
class EmailAttachment:
    filename: str = ""
    content_type: str = ""
    size_bytes: int = 0
    content_base64: str = ""  # transient — never persist by default


@dataclass
class EmailHeaders:
    received: list[str] = field(default_factory=list)
    authentication_results: str = ""
    dkim_signature: str = ""
    spf: str = ""
    dmarc: str = ""


@dataclass
class NormalizedEmail:
    """Canonical email object consumed by all detection modules."""

    message_id: str = field(default_factory=lambda: str(uuid4()))
    subject: str = ""
    sender: EmailAddress = field(default_factory=EmailAddress)
    reply_to: EmailAddress = field(default_factory=EmailAddress)
    return_path: str = ""
    recipients: list[str] = field(default_factory=list)
    date: str = ""
    body: EmailBody = field(default_factory=EmailBody)
    urls: list[EmailUrl] = field(default_factory=list)
    attachments: list[EmailAttachment] = field(default_factory=list)
    headers: EmailHeaders = field(default_factory=EmailHeaders)
    raw_headers: dict[str, Any] = field(default_factory=dict)

    def combined_text(self) -> str:
        """Subject + plain body for ML text features."""
        parts = [self.subject.strip(), self.body.plain.strip()]
        return "\n\n".join(p for p in parts if p)

    def to_dict(self, include_attachment_content: bool = False) -> dict:
        data = asdict(self)
        if not include_attachment_content:
            for att in data.get("attachments", []):
                att["content_base64"] = ""
        return data
