"""Sprint 14 — automated security regression tests."""

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


def test_security_headers_present():
    _, client = _client()
    r = client.get("/")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in r.headers


def test_auth_required_for_scan():
    _, client = _client()
    r = client.get("/scan", follow_redirects=False)
    assert r.status_code in (302, 401)
    assert "/login" in (r.headers.get("Location") or "")


def test_broken_access_control_scan_result():
    app, client = _client()
    # User A
    client.post("/register", data={
        "email": "usera@example.com",
        "password": "password123",
        "confirm": "password123",
    }, follow_redirects=True)
    # Create a scan for A via pipeline save would need login session
    client.post("/scan", data={
        "email_text": "Subject: hello\n\nHi team meeting tomorrow.",
    }, follow_redirects=True)

    with app.app_context():
        from backend.app.database import EmailScan
        scan = EmailScan.query.order_by(EmailScan.id.desc()).first()
        assert scan is not None
        scan_id = scan.id

    client.get("/logout", follow_redirects=True)
    client.post("/register", data={
        "email": "userb@example.com",
        "password": "password123",
        "confirm": "password123",
    }, follow_redirects=True)
    r = client.get(f"/scan/{scan_id}", follow_redirects=False)
    # Should redirect away / not show other user's scan
    assert r.status_code in (302, 403, 404) or b"not found" in r.data.lower()


def test_sql_injection_login_does_not_bypass():
    _, client = _client()
    r = client.post("/login", data={
        "email": "' OR 1=1 --@x.com",
        "password": "' OR '1'='1",
    }, follow_redirects=True)
    assert b"Invalid email or password" in r.data or b"Dashboard" not in r.data


def test_xss_not_executed_in_reflected_flash_path():
    # Registration with weird email rejected; ensure script tags escaped if shown
    _, client = _client()
    r = client.post("/register", data={
        "email": "<script>alert(1)</script>@x.com",
        "password": "password123",
        "confirm": "password123",
    }, follow_redirects=True)
    # Should not register invalid email; page must not contain raw unescaped script from input as executable
    # Flask/Jinja autoescapes by default
    assert b"<script>alert(1)</script>@x.com" not in r.data or b"&lt;script&gt;" in r.data


def test_api_requires_token():
    _, client = _client()
    r = client.post("/api/v1/extension/scan", json={"subject": "x", "body": "y"})
    assert r.status_code == 401


def test_csrf_blocks_authenticated_post_without_token():
    class CsrfOn(TestConfig):
        WTF_CSRF_ENABLED = True

    app = create_app(CsrfOn)
    client = app.test_client()
    # Establish session + csrf via GET
    client.get("/register")
    client.post("/register", data={
        "email": "csrfuser@example.com",
        "password": "password123",
        "confirm": "password123",
    }, follow_redirects=True)
    # Authenticated POST without csrf should fail
    r = client.post("/scan", data={"email_text": "Subject: t\n\nbody"}, follow_redirects=False)
    assert r.status_code == 400
