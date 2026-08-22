# Explainable Web-Based Phishing Email Detection for User Awareness Using Logistic Regression

A **System Development** PSM: Logistic Regression classifies phishing vs legitimate email, then explains suspicious URLs, sender mismatches, and risky language so users become more aware.

**Authoritative scope:** [docs/SCOPE.md](docs/SCOPE.md) · **Full spec:** [docs/MASTER_TECHNICAL_SPECIFICATION.md](docs/MASTER_TECHNICAL_SPECIFICATION.md)

## What is in scope

| Layer | Contents |
|---|---|
| **PSM Core** | TF-IDF + LR (baseline) vs TF-IDF + URL + metadata + LR (improved); explainability; Flask HTML/CSS/JS web app; MySQL; HTTPS. No live mailbox. |
| **PSM Extension** | Headers, SPF/DKIM/DMARC, attachments, fused 0–100 score, feedback, Chrome/Edge Gmail overlay (same API — model stays on the server) |
| **Post-PSM** | Other providers, extra ML algorithms, threat intel, enterprise |

## Project Status

**Phase:** Prototype implemented — evaluate and write up against the **corrected** proposal (single LR model, three experiments).

### Highlights

| Area | Result |
|---|---|
| Experiment 1 (held-out, LR v1.0.0 TF-IDF) | See `ml/evaluation/reports/` |
| Experiment 2 | Text-only vs text+metadata LR comparison (`python -m ml.training.train enhanced`) |
| Detection | Parse → features → **Logistic Regression** → explain + advice |
| Web app | Flask + auth, scanner, history, admin |
| Extension | Chrome/Edge MV3 — **PSM Extension**, not core |
| Deployment | Docker Compose + Nginx |

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
backend/     Flask app, detection engine, Jinja UI (PSM Core frontend)
ml/          Datasets, TF-IDF / URL / metadata features, LR training
extension/   Chrome/Edge MV3 Gmail scanner (PSM Extension)
gmail/       Google OAuth helpers (PSM Extension)
frontend/    Placeholder for future React SPA
docker/      Dockerfile + Nginx
docs/        SCOPE.md, spec, API, deployment, evaluation
scripts/     setup, train, deploy, demo
paths.py     Shared filesystem path constants
```

See [docs/STRUCTURE.md](docs/STRUCTURE.md) and [docs/API.md](docs/API.md).

## Docker deploy

```bash
cp .env.example .env   # set a strong SECRET_KEY
./scripts/deploy.sh
# → http://127.0.0.1/
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Evaluation (three experiments)

```bash
# Experiments 1–2 — baseline vs improved Logistic Regression
PYTHONPATH=. python -m ml.evaluation.full_report v1.0.0
PYTHONPATH=. python -m ml.training.train enhanced --version v1.1.0

# Security tests
PYTHONPATH=. python -m pytest backend/tests/ -q

# Experiment 3 — score user-study CSV (awareness pre/post)
PYTHONPATH=. python scripts/score_user_eval.py
```

Docs: [SCOPE.md](docs/SCOPE.md) · [STRUCTURE.md](docs/STRUCTURE.md) · [API.md](docs/API.md) · [SECURITY_TESTING.md](docs/SECURITY_TESTING.md) · [USER_EVALUATION.md](docs/USER_EVALUATION.md)

## Extension (PSM Extension)

Load unpacked from `extension/` — see [extension/README.md](extension/README.md).  
Copy API base URL and token from **Integrations** after login. The extension must not contain the ML model.

## Roadmap

| Sprint | Focus | Scope | Status |
|---|---|---|---|
| 1 | Requirements & Architecture | Core | done |
| 2 | Dataset & Preprocessing | Core | done |
| 3 | Baseline TF-IDF + Logistic Regression | Core | done |
| 4 | Improved LR (URL + metadata) | Core | done |
| 5 | Email Parser | Core/Ext | done |
| 6 | Label / optional risk band | Core/Ext | done |
| 7 | Explainability | Core | done |
| 8 | Web Application | Core | done |
| 9 | Attachment Analysis | Ext | done |
| 10 | Feedback Learning | Ext | done |
| 11 | Browser Extension | Ext | done |
| 12 | Gmail Integration | Ext | done |
| 13 | Deployment (Docker/Nginx) | Core | done |
| 14 | Security Testing | Core/Ext | done |
| 15 | ML Evaluation (Exp. 1–2) | Core | done |
| 16 | User awareness evaluation (Exp. 3) | Core | kit ready |

## License

Academic project — All rights reserved.
