"""Flask application configuration."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure repo root is importable (paths.py, gmail/, ml/)
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from paths import DATA_DIR, INSTANCE_DIR, ML_ARTIFACTS, ROOT as PROJECT_ROOT

INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-me-in-production")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{INSTANCE_DIR / 'phishing.db'}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB
    MODEL_VERSION = os.environ.get("MODEL_VERSION", "v1.0.0")
    PREFERRED_URL_SCHEME = os.environ.get("PREFERRED_URL_SCHEME", "http")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _env_flag("SESSION_COOKIE_SECURE", default=False)
    WTF_CSRF_ENABLED = True
    PROJECT_ROOT = PROJECT_ROOT
    DATA_DIR = DATA_DIR
    ML_ARTIFACTS = ML_ARTIFACTS
