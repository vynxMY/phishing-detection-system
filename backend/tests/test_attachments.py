"""Tests for Sprint 9 attachment analysis."""

from __future__ import annotations

import base64
import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.app.attachments.static_analyzer import analyze_single_attachment
from backend.app.email_parser.models import EmailAttachment


def _att(filename: str, data: bytes) -> EmailAttachment:
    return EmailAttachment(
        filename=filename,
        content_type="application/octet-stream",
        size_bytes=len(data),
        content_base64=base64.b64encode(data).decode("ascii"),
    )


def test_double_extension_exe():
    result = analyze_single_attachment(_att("invoice.pdf.exe", b"MZ" + b"\x00" * 100))
    types = {i["type"] for i in result["issues"]}
    assert "extension_mismatch" in types or "dangerous_type" in types
    assert result["score"] >= 40


def test_macro_in_docx_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", "<xml></xml>")
        zf.writestr("word/vbaProject.bin", b"macro")
    result = analyze_single_attachment(_att("macro.docx", buf.getvalue()))
    assert any(i["type"] == "macro" for i in result["issues"])


def test_html_javascript_attachment():
    html = b"<html><script>alert(1)</script><a href='http://evil.xyz'>x</a></html>"
    result = analyze_single_attachment(_att("page.html", html))
    assert any(i["type"] == "javascript" for i in result["issues"])
    assert result["embedded_urls"]
