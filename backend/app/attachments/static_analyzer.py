"""Static attachment analyzer (Sprint 9) — no file execution."""

from __future__ import annotations

import base64
import hashlib
import io
import re
import zipfile
from pathlib import Path

from backend.app.attachments.file_types import detect_type
from backend.app.email_parser.models import EmailAttachment, NormalizedEmail
from ml.features.url_utils import extract_urls
from paths import HASH_BLOCKLIST

MAX_ATTACH_BYTES = 10 * 1024 * 1024
DANGEROUS_EXTS = {".exe", ".js", ".jse", ".vbs", ".bat", ".cmd", ".scr", ".lnk", ".iso", ".msi", ".ps1", ".com"}
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz"}
DOUBLE_EXT = re.compile(
    r"\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|png|txt)\.(?:exe|js|scr|bat|cmd|vbs|com)$",
    re.I,
)
BLOCKLIST_PATH = HASH_BLOCKLIST


def _load_blocklist() -> set[str]:
    if not BLOCKLIST_PATH.exists():
        return set()
    return {
        line.strip().lower()
        for line in BLOCKLIST_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


def _decode_attachment(att: EmailAttachment) -> bytes:
    if not att.content_base64:
        return b""
    try:
        return base64.b64decode(att.content_base64, validate=False)
    except Exception:
        return b""


def analyze_single_attachment(att: EmailAttachment, blocklist: set[str] | None = None) -> dict:
    """Full static analysis of one attachment."""
    blocklist = blocklist if blocklist is not None else _load_blocklist()
    data = _decode_attachment(att)
    name = att.filename or "attachment"
    issues: list[dict] = []
    score = 0
    embedded_urls: list[str] = []
    archive_entries: list[str] = []
    sha256 = hashlib.sha256(data).hexdigest() if data else ""
    type_info = detect_type(data, name) if data else {
        "detected_mime": att.content_type or "application/octet-stream",
        "detected_ext": Path(name).suffix.lower(),
        "declared_ext": Path(name).suffix.lower(),
        "extension_mismatch": False,
    }

    size = len(data) or att.size_bytes or 0
    if size > MAX_ATTACH_BYTES:
        score += 15
        issues.append({
            "type": "oversized",
            "severity": "warning",
            "filename": name,
            "text": f"Attachment '{name}' exceeds the {MAX_ATTACH_BYTES // (1024*1024)} MB analysis limit.",
        })

    if DOUBLE_EXT.search(name):
        score += 50
        issues.append({
            "type": "extension_mismatch",
            "severity": "critical",
            "contribution": 0.3,
            "filename": name,
            "text": f"Filename '{name}' disguises an executable as a document (double extension).",
        })

    if type_info.get("extension_mismatch"):
        score += 35
        issues.append({
            "type": "magic_mismatch",
            "severity": "critical",
            "contribution": 0.25,
            "filename": name,
            "text": (
                f"Declared extension '{type_info['declared_ext']}' does not match "
                f"detected type '{type_info['detected_ext']}'."
            ),
        })

    lower = name.lower()
    for ext in DANGEROUS_EXTS:
        if lower.endswith(ext) or type_info.get("detected_ext") == ext:
            score += 40
            issues.append({
                "type": "dangerous_type",
                "severity": "critical",
                "contribution": 0.28,
                "filename": name,
                "text": f"Attachment '{name}' is a potentially dangerous file type ({ext}).",
            })
            break

    if sha256 and sha256 in blocklist:
        score += 50
        issues.append({
            "type": "blocklist_hash",
            "severity": "critical",
            "contribution": 0.35,
            "filename": name,
            "text": f"Attachment '{name}' matches a known malicious file hash.",
        })

    # Tiny executable anomaly
    if size and size < 2048 and (
        lower.endswith(".exe") or type_info.get("detected_ext") == ".exe"
    ):
        score += 15
        issues.append({
            "type": "size_anomaly",
            "severity": "warning",
            "filename": name,
            "text": f"Executable '{name}' is unusually small ({size} bytes).",
        })

    # Embedded URLs from text-like content
    if data:
        try:
            text_sample = data[:200_000].decode("utf-8", errors="ignore")
        except Exception:
            text_sample = ""
        if text_sample:
            embedded_urls = extract_urls(text_sample)[:20]
            if embedded_urls:
                score += min(20, 5 * len(embedded_urls))
                issues.append({
                    "type": "embedded_urls",
                    "severity": "warning",
                    "filename": name,
                    "text": f"Found {len(embedded_urls)} URL(s) embedded in '{name}'.",
                })
            if "<script" in text_sample.lower() or "javascript:" in text_sample.lower():
                score += 25
                issues.append({
                    "type": "javascript",
                    "severity": "critical",
                    "filename": name,
                    "text": f"JavaScript content detected inside '{name}'.",
                })
            if "%PDF" in text_sample[:16] or data.startswith(b"%PDF"):
                if "/JavaScript" in text_sample or "/JS" in text_sample:
                    score += 30
                    issues.append({
                        "type": "pdf_javascript",
                        "severity": "critical",
                        "filename": name,
                        "text": f"PDF '{name}' contains JavaScript actions.",
                    })

    # OOXML macro detection + ZIP listing
    if data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()[:100]
                archive_entries = names
                macro_markers = (
                    "vbaproject.bin",
                    "word/vbaData.xml",
                    "xl/vbaProject.bin",
                    "ppt/vbaProject.bin",
                )
                lowered = [n.lower() for n in names]
                if any(any(m in n for m in macro_markers) for n in lowered) or any(
                    n.endswith("vbaproject.bin") for n in lowered
                ):
                    score += 35
                    issues.append({
                        "type": "macro",
                        "severity": "critical",
                        "filename": name,
                        "text": f"Office document '{name}' contains VBA macros.",
                    })
                # Nested dangerous files in archive
                for entry in names:
                    el = entry.lower()
                    if DOUBLE_EXT.search(el) or any(el.endswith(x) for x in DANGEROUS_EXTS):
                        score += 30
                        issues.append({
                            "type": "archive_dangerous_content",
                            "severity": "critical",
                            "filename": name,
                            "text": f"Archive '{name}' contains suspicious file '{entry}'.",
                        })
                        break
                if any(lower.endswith(ext) for ext in ARCHIVE_EXTS) or type_info.get("detected_ext") == ".zip":
                    if not any(i["type"] == "archive" for i in issues):
                        score += 10
                        issues.append({
                            "type": "archive",
                            "severity": "info",
                            "filename": name,
                            "text": f"Archive '{name}' contains {len(names)} entries (static listing only).",
                        })
        except zipfile.BadZipFile:
            pass

    return {
        "filename": name,
        "size_bytes": size,
        "sha256": sha256,
        "score": min(100, score),
        "type": type_info,
        "embedded_urls": embedded_urls,
        "archive_entries": archive_entries[:30],
        "issues": issues,
    }


def analyze_attachments(email: NormalizedEmail) -> dict:
    """Analyse all attachments on a normalized email."""
    attachments = email.attachments
    if not attachments:
        return {"score": 0, "count": 0, "issues": [], "details": []}

    blocklist = _load_blocklist()
    details = []
    issues = []
    score = 0

    for att in attachments:
        detail = analyze_single_attachment(att, blocklist=blocklist)
        details.append({k: v for k, v in detail.items() if k != "issues"})
        issues.extend(detail["issues"])
        score = max(score, detail["score"])
        # Soft accumulate without double-counting too hard
        score = min(100, score + max(0, detail["score"] // 5))

    return {
        "score": min(100, score),
        "count": len(attachments),
        "issues": issues,
        "details": details,
    }
