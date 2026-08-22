"""Sender, header, and email metadata feature extraction."""

from __future__ import annotations

import re
from dataclasses import dataclass

import numpy as np
import pandas as pd

EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
)

HEADER_PATTERNS = {
    "from": re.compile(r"^From:\s*(.+)$", re.MULTILINE | re.IGNORECASE),
    "reply_to": re.compile(r"^Reply-To:\s*(.+)$", re.MULTILINE | re.IGNORECASE),
    "return_path": re.compile(r"^Return-Path:\s*(.+)$", re.MULTILINE | re.IGNORECASE),
    "sender": re.compile(r"^Sender:\s*(.+)$", re.MULTILINE | re.IGNORECASE),
}

AUTH_PATTERNS = {
    "spf_fail": re.compile(r"spf\s*=\s*fail", re.IGNORECASE),
    "spf_pass": re.compile(r"spf\s*=\s*pass", re.IGNORECASE),
    "dkim_fail": re.compile(r"dkim\s*=\s*fail", re.IGNORECASE),
    "dkim_pass": re.compile(r"dkim\s*=\s*pass", re.IGNORECASE),
    "dmarc_fail": re.compile(r"dmarc\s*=\s*fail", re.IGNORECASE),
    "dmarc_pass": re.compile(r"dmarc\s*=\s*pass", re.IGNORECASE),
}

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "protonmail.com", "icloud.com", "live.com", "msn.com",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".link", ".tk",
    ".ml", ".ga", ".cf", ".gq",
}

METADATA_FEATURE_NAMES = [
    "subject_length",
    "subject_has_urgency",
    "subject_has_re_fwd",
    "num_email_addresses",
    "from_domain_length",
    "reply_to_domain_length",
    "reply_to_mismatch",
    "return_path_present",
    "sender_header_present",
    "header_line_count",
    "free_email_provider",
    "suspicious_sender_tld",
    "display_name_bracket_mismatch",
    "spf_fail",
    "spf_pass",
    "dkim_fail",
    "dkim_pass",
    "dmarc_fail",
    "dmarc_pass",
]


def _extract_domain(email: str) -> str:
    match = EMAIL_PATTERN.search(email)
    if not match:
        return ""
    return match.group(0).split("@")[-1].lower()


def _extract_header(text: str, name: str) -> str:
    pattern = HEADER_PATTERNS.get(name)
    if not pattern:
        return ""
    match = pattern.search(text)
    return match.group(1).strip() if match else ""


def _count_header_lines(text: str) -> int:
    header_keys = ("From:", "To:", "Subject:", "Date:", "Received:", "Reply-To:", "Return-Path:")
    count = 0
    for line in str(text).splitlines():
        if any(line.strip().lower().startswith(k.lower()) for k in header_keys):
            count += 1
    return count


def _display_name_mismatch(from_header: str) -> int:
    """Detect 'Microsoft Support <fake@domain.com>' style mismatches."""
    if not from_header or "<" not in from_header:
        return 0
    display = from_header.split("<")[0].strip().lower()
    domain = _extract_domain(from_header)
    if not display or not domain:
        return 0
    # Simple heuristic: display mentions a brand word not in domain
    brand_words = ("microsoft", "paypal", "amazon", "apple", "google", "netflix", "bank")
    for brand in brand_words:
        if brand in display and brand not in domain:
            return 1
    return 0


def _extract_metadata_row(text: str, subject: str = "") -> list[float]:
    text = str(text or "")
    subject = str(subject or "")

    from_hdr = _extract_header(text, "from")
    reply_hdr = _extract_header(text, "reply_to")
    return_hdr = _extract_header(text, "return_path")

    from_domain = _extract_domain(from_hdr) if from_hdr else ""
    reply_domain = _extract_domain(reply_hdr) if reply_hdr else ""

    # Fallback: use first email address in body as sender proxy
    if not from_domain:
        emails = EMAIL_PATTERN.findall(text)
        from_domain = emails[0].split("@")[-1].lower() if emails else ""

    emails_in_text = EMAIL_PATTERN.findall(text)

    reply_mismatch = int(
        bool(from_domain and reply_domain and from_domain != reply_domain)
    )

    auth_text = text  # Authentication-Results often embedded in headers

    return [
        float(len(subject)),
        float(bool(re.search(r"\b(urgent|important|action required|verify)\b", subject, re.I))),
        float(bool(re.search(r"^(re|fwd)\s*:", subject, re.I))),
        float(len(emails_in_text)),
        float(len(from_domain)),
        float(len(reply_domain)),
        float(reply_mismatch),
        float(bool(return_hdr)),
        float(bool(_extract_header(text, "sender"))),
        float(_count_header_lines(text)),
        float(from_domain in FREE_EMAIL_PROVIDERS),
        float(any(from_domain.endswith(tld) for tld in SUSPICIOUS_TLDS)),
        float(_display_name_mismatch(from_hdr)),
        float(bool(AUTH_PATTERNS["spf_fail"].search(auth_text))),
        float(bool(AUTH_PATTERNS["spf_pass"].search(auth_text))),
        float(bool(AUTH_PATTERNS["dkim_fail"].search(auth_text))),
        float(bool(AUTH_PATTERNS["dkim_pass"].search(auth_text))),
        float(bool(AUTH_PATTERNS["dmarc_fail"].search(auth_text))),
        float(bool(AUTH_PATTERNS["dmarc_pass"].search(auth_text))),
    ]


@dataclass
class MetadataFeatureExtractor:
    """Extract sender/header/metadata features from email text and subject."""

    def fit(self, texts: pd.Series, subjects: pd.Series | None = None) -> MetadataFeatureExtractor:
        return self

    def transform(
        self,
        texts: pd.Series,
        subjects: pd.Series | None = None,
    ) -> np.ndarray:
        subjects = subjects if subjects is not None else pd.Series([""] * len(texts))
        rows = [
            _extract_metadata_row(text, subj)
            for text, subj in zip(texts.fillna(""), subjects.fillna(""))
        ]
        return np.array(rows, dtype=np.float64)

    def fit_transform(
        self,
        texts: pd.Series,
        subjects: pd.Series | None = None,
    ) -> np.ndarray:
        return self.fit(texts, subjects).transform(texts, subjects)
