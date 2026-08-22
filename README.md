# Machine Learning-Based Phishing Email Detection System

A web-based cybersecurity platform that detects phishing emails using supervised machine learning, multi-signal email analysis, explainable risk scoring, and user-facing security guidance.

## Project Status

**Phase:** All planned sprints (1–16) complete — PSM prototype ready for deployment & evaluation

### Highlights

| Area | Result |
|---|---|
| ML (held-out test, v1.0.0) | Accuracy 98.46% · F1 98.45% · FNR 1.13% |
| Detection pipeline | Parse → Analyse → ML → Risk 0–100 → Explain + Advice |
| Web app | Flask + auth, scanner, history, admin, feedback |
| Extension | Chrome/Edge MV3 Gmail scanner |
| Deployment | Docker Compose + Nginx |
| Security tests | 18 automated tests passing |

## Quick Start (local)

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh

# Or manually:
#   python -m venv .venv && source .venv/bin/activate
#   pip install -r requirements.txt && python -m nltk.downloader stopwords
#   PYTHONPATH=. python -m ml.training.train all --version v1.0.0

PYTHONPATH=. python backend/wsgi.py
# → http://127.0.0.1:5000
# Admin: admin@localhost / admin12345  (change in production)
```

## Repository layout

```text
backend/     Flask app, detection engine, Jinja UI
ml/          Datasets, features, training, evaluation
extension/   Chrome/Edge MV3 Gmail scanner
gmail/       Google OAuth helpers
frontend/    Placeholder for future React SPA
docker/      Dockerfile + Nginx
docs/        Spec, API, deployment, evaluation
scripts/     setup, train, deploy, demo
paths.py     Shared filesystem path constants
```

See [docs/STRUCTURE.md](docs/STRUCTURE.md) and [docs/API.md](docs/API.md).

## Docker deploy (Sprint 13)

```bash
cp .env.example .env   # set a strong SECRET_KEY
./scripts/deploy.sh
# → http://127.0.0.1/
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Evaluation

```bash
# Sprint 15 — ML evaluation report
PYTHONPATH=. python -m ml.evaluation.full_report v1.0.0

# Sprint 14 — security tests
PYTHONPATH=. python -m pytest backend/tests/ -q

# Sprint 16 — score user-study CSV
PYTHONPATH=. python scripts/score_user_eval.py
```

Docs: [STRUCTURE.md](docs/STRUCTURE.md) · [API.md](docs/API.md) · [SECURITY_TESTING.md](docs/SECURITY_TESTING.md) · [USER_EVALUATION.md](docs/USER_EVALUATION.md)

## Extension

Load unpacked from `extension/` — see [extension/README.md](extension/README.md).  
Copy API token from **Integrations** after login.

## Documentation

**[Master Technical Specification](docs/MASTER_TECHNICAL_SPECIFICATION.md)** — single source of truth.

## Roadmap

| Sprint | Focus | Status |
|---|---|---|
| 1 | Requirements & Architecture | done |
| 2 | Dataset & Preprocessing | done |
| 3 | Baseline ML (Logistic Regression) | done |
| 4 | Enhanced Detection | done |
| 5 | Email Parser | done |
| 6 | Risk Engine | done |
| 7 | Explainability | done |
| 8 | Web Application | done |
| 9 | Attachment Analysis | done |
| 10 | Feedback Learning | done |
| 11 | Browser Extension | done |
| 12 | Gmail Integration | done |
| 13 | Deployment (Docker/Nginx) | done |
| 14 | Security Testing | done |
| 15 | ML Evaluation | done |
| 16 | User Evaluation kit | done |

## License

Academic project — All rights reserved.
