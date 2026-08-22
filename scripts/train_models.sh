#!/usr/bin/env bash
# Run ML pipeline commands
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -d ".venv" ]; then
  python -m venv .venv
fi

source .venv/bin/activate
pip install -q -r requirements.txt

python -m nltk.downloader -q stopwords || true

case "${1:-all}" in
  preprocess) python -m ml.training.train preprocess "${@:2}" ;;
  train)      python -m ml.training.train train "${@:2}" ;;
  enhanced)   python -m ml.training.train enhanced "${@:2}" ;;
  all)        python -m ml.training.train all "${@:2}" ;;
  *)          echo "Usage: $0 {preprocess|train|enhanced|all} [args]"; exit 1 ;;
esac
