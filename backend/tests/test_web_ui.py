"""Web product routes: scanners, history, reports, auth next URL."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.app import create_app
from backend.app.config import Config


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "test-secret"


def _client():
    app = create_app(TestConfig)
    return app, app.test_client()


def _register(client, email="analyst@example.com"):
    return client.post(
        "/register",
        data={"email": email, "password": "password123", "confirm": "password123"},
        follow_redirects=True,
    )


def test_scan_requires_login_and_preserves_next():
    _, client = _client()
    r = client.get("/scan", follow_redirects=False)
    loc = r.headers.get("Location") or ""
    assert r.status_code == 302
    assert "/login" in loc
    assert "next=" in loc
    assert "/scan" in loc


def test_url_scanner_page_after_login():
    _, client = _client()
    _register(client)
    r = client.get("/scan/url?url=https://example.com")
    assert r.status_code == 200
    assert b"URL phishing scanner" in r.data
    assert b"https://example.com" in r.data


def test_reports_and_history_pages():
    _, client = _client()
    _register(client)
    assert client.get("/history").status_code == 200
    assert client.get("/reports").status_code == 200
    assert client.get("/learn").status_code == 200
    assert b"Explainability" in client.get("/learn").data


def test_login_hidden_next_field():
    _, client = _client()
    r = client.get("/login?next=/scan/url")
    assert r.status_code == 200
    assert b'name="next"' in r.data
    assert b"/scan/url" in r.data


def test_landing_has_no_fake_vanity_counts():
    _, client = _client()
    r = client.get("/")
    assert r.status_code == 200
    assert b"10,000+" not in r.data
    assert b"Detect phishing" in r.data


def test_extension_zip_requires_login():
    _, client = _client()
    r = client.get("/settings/integrations/extension.zip", follow_redirects=False)
    assert r.status_code == 302
    assert "/login" in (r.headers.get("Location") or "")


def test_extension_zip_download_after_login():
    _, client = _client()
    _register(client)
    r = client.get("/settings/integrations/extension.zip")
    assert r.status_code == 200
    assert r.mimetype == "application/zip"
    assert r.data[:2] == b"PK"
