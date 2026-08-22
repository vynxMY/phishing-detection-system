#!/usr/bin/env bash
# One-shot local setup for the Phishing Detection System
set -euo pipefail
cd "$(dirname "$0")/.."

python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
python -m nltk.downloader stopwords || true

mkdir -p \
  backend/instance \
  backend/data \
  ml/datasets/raw \
  ml/datasets/processed \
  ml/models/artifacts \
  ml/evaluation/reports

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

if [ ! -f ml/models/artifacts/logistic_regression_v1.0.0.joblib ]; then
  echo "Training baseline Logistic Regression (v1.0.0)..."
  python -m ml.training.train all --version v1.0.0
fi

echo
echo "Setup complete."
echo "  Web:   PYTHONPATH=. python backend/wsgi.py"
echo "  Tests: PYTHONPATH=. pytest"
echo "  Demo:  PYTHONPATH=. python scripts/demo_scan.py --demo"
