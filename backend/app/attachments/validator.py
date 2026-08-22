"""Attachment upload validation (Sprint 9)."""

from __future__ import annotations

from backend.app.attachments.static_analyzer import MAX_ATTACH_BYTES


ALLOWED_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".rar", ".html", ".htm", ".js", ".lnk", ".exe", ".iso",
    ".txt", ".eml",
}


def validate_attachment(filename: str, size_bytes: int) -> list[str]:
    """Return a list of validation error messages (empty if OK)."""
    errors: list[str] = []
    name = (filename or "").strip()
    if not name:
        errors.append("Attachment filename is required.")
    if size_bytes < 0:
        errors.append("Invalid attachment size.")
    if size_bytes > MAX_ATTACH_BYTES:
        errors.append(f"Attachment exceeds {MAX_ATTACH_BYTES // (1024 * 1024)} MB limit.")
    return errors
