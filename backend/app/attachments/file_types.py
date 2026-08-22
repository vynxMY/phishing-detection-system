"""Magic-byte / file-type helpers for attachment analysis."""

from __future__ import annotations

from pathlib import Path

# Common signatures (offset 0 unless noted)
SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"MZ", "application/x-msdownload", ".exe"),
    (b"%PDF", "application/pdf", ".pdf"),
    (b"PK\x03\x04", "application/zip", ".zip"),  # also docx/xlsx/pptx
    (b"Rar!\x1a\x07", "application/x-rar-compressed", ".rar"),
    (b"\x7fELF", "application/x-executable", ".elf"),
    (b"<!DOCTYPE html", "text/html", ".html"),
    (b"<html", "text/html", ".html"),
    (b"{\\rtf", "application/rtf", ".rtf"),
]

OOXML_TYPES = {
    "word/": (".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    "xl/": (".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    "ppt/": (".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
}


def detect_type(data: bytes, filename: str = "") -> dict:
    """Detect content type from magic bytes + filename extension."""
    name = (filename or "").lower()
    ext = Path(name).suffix.lower() if name else ""
    detected_mime = "application/octet-stream"
    detected_ext = ext or ""

    for sig, mime, sug_ext in SIGNATURES:
        if data.startswith(sig) or (sig.lower() in data[:64].lower() if sig.startswith(b"<") else False):
            detected_mime = mime
            detected_ext = sug_ext
            break

    # Refine ZIP → OOXML
    if data.startswith(b"PK\x03\x04"):
        head = data[:8192]
        for marker, (ooxml_ext, ooxml_mime) in OOXML_TYPES.items():
            if marker.encode() in head or marker.encode() in data[:65536]:
                detected_mime = ooxml_mime
                detected_ext = ooxml_ext
                break

    # HTML / JS heuristics
    sample = data[:4096].decode("utf-8", errors="ignore").lower()
    if "<script" in sample or "javascript:" in sample:
        if detected_mime == "application/octet-stream":
            detected_mime = "text/html" if "<html" in sample else "application/javascript"
            detected_ext = detected_ext or (".html" if "<html" in sample else ".js")

    return {
        "detected_mime": detected_mime,
        "detected_ext": detected_ext,
        "declared_ext": ext,
        "extension_mismatch": bool(ext and detected_ext and ext != detected_ext and not _compatible(ext, detected_ext)),
    }


def _compatible(declared: str, detected: str) -> bool:
    families = [
        {".zip", ".docx", ".xlsx", ".pptx", ".jar"},
        {".htm", ".html"},
        {".exe", ".dll", ".scr"},
    ]
    for fam in families:
        if declared in fam and detected in fam:
            return True
    return declared == detected
