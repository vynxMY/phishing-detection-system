"""Unit tests for Sprints 5–7: parser, risk engine, explainability, pipeline."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.app.detection.pipeline import DetectionPipeline
from backend.app.detection.risk_fusion import classify_score, fuse_risk
from backend.app.email_parser import parse_email
from backend.app.explainability.advice import generate_advice


PHISHING_SAMPLE = """\
From: Microsoft Support <support@micr0soft-security.com>
Reply-To: attacker@evil-domain.xyz
Subject: URGENT: Verify your account immediately
Authentication-Results: spf=fail dkim=fail dmarc=fail
Date: Sat, 22 Aug 2026 10:00:00 +0000

Dear Customer,

We detected unusual activity on your Microsoft account.
Confirm your identity now or your account will be suspended:

http://paypal-login.verify-account.xyz/auth

Do not ignore this message.
"""

SAFE_SAMPLE = """\
From: Jordan Lee <jordan.lee@company.com>
To: team@company.com
Subject: Re: Meeting notes from yesterday

Hi team,

Please find attached the notes from yesterday's standup.
The next session is Friday at 10 AM in Conference Room B.

Thanks,
Jordan
"""

HTML_SAMPLE = """\
<html><body>
<p>Click here to reset your password:</p>
<a href="http://192.168.1.1/login">https://paypal.com/login</a>
</body></html>
"""

EML_DOUBLE_EXT = """\
From: billing@invoices-secure.xyz
Subject: Invoice attached
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND"

--BOUND
Content-Type: text/plain

Please review the attached invoice.

--BOUND
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.pdf.exe"
Content-Transfer-Encoding: base64

AQID
--BOUND--
"""


def test_parse_paste_headers_and_body():
    email = parse_email(text=PHISHING_SAMPLE)
    assert email.subject.lower().startswith("urgent")
    assert email.sender.domain == "micr0soft-security.com"
    assert email.reply_to.domain == "evil-domain.xyz"
    assert email.headers.spf == "fail"
    assert len(email.urls) >= 1
    assert "unusual activity" in email.body.plain.lower()


def test_parse_html_anchor_mismatch():
    email = parse_email(text=HTML_SAMPLE)
    assert email.body.html
    assert any("192.168.1.1" in u.href for u in email.urls)
    assert any("paypal.com" in (u.displayed_text or "") for u in email.urls)


def test_parse_eml_attachment():
    email = parse_email(text=EML_DOUBLE_EXT)
    assert len(email.attachments) >= 1
    assert email.attachments[0].filename == "invoice.pdf.exe"


def test_classify_thresholds():
    assert classify_score(0) == "safe"
    assert classify_score(25) == "low_risk"
    assert classify_score(50) == "suspicious"
    assert classify_score(70) == "high_risk"
    assert classify_score(90) == "phishing"


def test_risk_fusion_dangerous_attachment_floor():
    analyses = {
        "content": {"score": 10},
        "url": {"score": 10, "issues": []},
        "sender": {"score": 10, "issues": []},
        "authentication": {"score": 0, "spf": "none", "issues": []},
        "attachment": {
            "score": 50,
            "issues": [{"type": "extension_mismatch", "severity": "critical", "text": "bad"}],
        },
        "brand": {"score": 0, "issues": []},
    }
    result = fuse_risk(analyses, ml_phishing_probability=0.2)
    assert result.floor_applied == 80
    assert result.risk_score >= 80
    assert result.classification == "phishing"


def test_advice_high_risk():
    advice = generate_advice("phishing", ["url", "sender"])
    assert any("password" in x.lower() for x in advice["do_not"])
    assert any("report" in x.lower() for x in advice["do"])


def test_pipeline_phishing_sample():
    pipeline = DetectionPipeline(model_version="v1.0.0")
    result = pipeline.scan(text=PHISHING_SAMPLE, explanation_level="all")
    assert "risk_score" in result
    assert 0 <= result["risk_score"] <= 100
    assert result["classification"] in {
        "safe", "low_risk", "suspicious", "high_risk", "phishing"
    }
    assert result["breakdown"]
    assert result["explanations"]["simple"]
    assert result["advice"]["do_not"]
    assert result["risk_score"] >= 40  # should not look safe


def test_pipeline_safe_sample():
    pipeline = DetectionPipeline(model_version="v1.0.0")
    result = pipeline.scan(text=SAFE_SAMPLE, explanation_level="simple")
    assert result["risk_score"] < result.get("_unused", 100)
    # Safe sample should score lower than phishing sample
    phish = pipeline.scan(text=PHISHING_SAMPLE, explanation_level="simple")
    assert result["risk_score"] < phish["risk_score"]
