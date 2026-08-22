"""Security middleware: headers, CSRF, basic rate limiting (Sprint 14)."""

from __future__ import annotations

import secrets
import time
from collections import defaultdict
from functools import wraps

from flask import abort, g, request, session


def generate_csrf_token() -> str:
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf() -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    # API token auth bypasses form CSRF (extension uses Bearer tokens)
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer ") or request.headers.get("X-API-Token"):
        return
    if request.path.startswith("/api/"):
        return
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not token or token != session.get("_csrf_token"):
        abort(400, description="CSRF validation failed")


class RateLimiter:
    """Simple in-memory rate limiter (per-process). Use Redis in production scale-out."""

    def __init__(self):
        self._hits: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.time()
        bucket = self._hits[key]
        self._hits[key] = [t for t in bucket if now - t < window_seconds]
        if len(self._hits[key]) >= limit:
            return False
        self._hits[key].append(now)
        return True


limiter = RateLimiter()


def rate_limit(limit: int, window_seconds: int, key_fn=None):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if key_fn:
                key = key_fn()
            else:
                key = f"{request.endpoint}:{request.remote_addr}"
            if not limiter.allow(key, limit, window_seconds):
                abort(429, description="Rate limit exceeded")
            return view(*args, **kwargs)

        return wrapped

    return decorator


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self'; "
        "frame-ancestors 'none'"
    ),
}


def apply_security_headers(response):
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    # HSTS only when request is HTTPS (Cloudflare / TLS terminator)
    if request.is_secure or request.headers.get("X-Forwarded-Proto") == "https":
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
    return response
