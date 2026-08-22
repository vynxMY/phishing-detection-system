"""Project root path helpers shared by backend and scripts."""

from __future__ import annotations

from pathlib import Path

# Repository root: .../Phishing Detection System
ROOT = Path(__file__).resolve().parent

BACKEND_DIR = ROOT / "backend"
ML_DIR = ROOT / "ml"
DOCS_DIR = ROOT / "docs"
EXTENSION_DIR = ROOT / "extension"
DOCKER_DIR = ROOT / "docker"
SCRIPTS_DIR = ROOT / "scripts"
GMAIL_DIR = ROOT / "gmail"

INSTANCE_DIR = BACKEND_DIR / "instance"
DATA_DIR = BACKEND_DIR / "data"
HASH_BLOCKLIST = DATA_DIR / "hash_blocklist.txt"

ML_ARTIFACTS = ML_DIR / "models" / "artifacts"
ML_RAW = ML_DIR / "datasets" / "raw"
ML_PROCESSED = ML_DIR / "datasets" / "processed"
ML_REPORTS = ML_DIR / "evaluation" / "reports"
