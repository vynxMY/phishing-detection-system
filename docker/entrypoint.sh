#!/bin/sh
set -e
PORT="${PORT:-8000}"
WORKERS="${WEB_WORKERS:-2}"
exec gunicorn \
  -b "0.0.0.0:${PORT}" \
  -w "${WORKERS}" \
  --timeout 120 \
  --access-logfile - \
  "backend.wsgi:app"
