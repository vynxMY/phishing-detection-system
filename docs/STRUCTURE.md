# Repository Structure

Canonical layout for **Machine Learning-Based Phishing Email Detection System**.

```text
phishing-detection-system/
├── paths.py                 # Shared root path constants
├── conftest.py / pytest.ini # Test bootstrap
├── requirements.txt
├── docker-compose.yml
├── .env.example
├── README.md
│
├── backend/                 # Flask app + detection engine
│   ├── wsgi.py
│   ├── app/
│   │   ├── api/             # HTTP routes (auth, main, feedback, extension, gmail)
│   │   ├── auth/            # Session helpers
│   │   ├── analyzers/       # Content/URL/sender/auth/attachment/brand/header
│   │   ├── attachments/     # Static attachment analysis
│   │   ├── detection/       # Pipeline, risk fusion, ML inference, rules
│   │   ├── email_parser/    # .eml / HTML / paste → NormalizedEmail
│   │   ├── explainability/  # Explanations, advice, counterfactuals
│   │   ├── services/        # Persistence helpers
│   │   ├── database/        # SQLAlchemy models
│   │   ├── templates/       # Jinja UI (PSM Core frontend)
│   │   ├── static/          # CSS/assets
│   │   ├── config.py
│   │   └── security.py
│   ├── data/                # Local blocklists, etc.
│   ├── instance/            # SQLite DB (gitignored)
│   └── tests/
│
├── ml/                      # Training & evaluation
│   ├── datasets/{raw,processed}/
│   ├── preprocessing/
│   ├── features/
│   ├── models/{artifacts}/
│   ├── training/
│   └── evaluation/{reports}/
│
├── extension/               # Chrome/Edge Manifest V3
├── gmail/oauth/             # Google OAuth + Gmail API helpers
├── frontend/                # Placeholder for future React SPA
├── docker/                  # Dockerfile + Nginx
├── docs/                    # Specs, API, deployment, evaluation
└── scripts/                 # setup, train, deploy, demo, eval helpers
```

## Import rules

- Run from repo root with `PYTHONPATH=.` (or use `pytest` / `scripts/setup.sh`).
- Prefer `from paths import ...` for filesystem locations.
- Prefer `from gmail.oauth import ...` for Google integration helpers.
- Prefer `from backend.app...` / `from ml...` for application code.

## Where the UI lives

PSM Core UI is Jinja under `backend/app/templates/`.  
`frontend/` is reserved for a future React SPA (see `frontend/README.md`).
