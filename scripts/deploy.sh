#!/usr/bin/env bash
# Sprint 13 — build and start production stack
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example — edit SECRET_KEY before going online."
fi

if [ ! -f ml/models/artifacts/logistic_regression_v1.0.0.joblib ]; then
  echo "Warning: model artifact missing. Train first: python -m ml.training.train train --version v1.0.0"
fi

docker compose up --build -d
echo "Waiting for health..."
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${HTTP_PORT:-80}/api/v1/health" >/dev/null 2>&1; then
    echo "Deployed: http://127.0.0.1:${HTTP_PORT:-80}"
    exit 0
  fi
  sleep 2
done
echo "Health check timed out — see: docker compose logs"
exit 1
