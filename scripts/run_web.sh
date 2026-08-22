#!/usr/bin/env bash
# Start the Flask web application (Sprint 8)
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
export PYTHONPATH=.
export FLASK_APP=backend.wsgi:app
python backend/wsgi.py
