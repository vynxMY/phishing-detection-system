# Deployment Guide — Sprint 13

## Architecture

```
Internet → Cloudflare (DNS + TLS) → Nginx → Gunicorn/Flask → SQLite/MySQL
                                              ↓
                                         ML artifacts
```

## Prerequisites

- Docker + Docker Compose
- Trained model artifacts in `ml/models/artifacts/`
- `.env` file (copy from `.env.example`)

## Local / VPS deploy

```bash
cp .env.example .env
# Set a strong SECRET_KEY
# Optionally set DATABASE_URL for MySQL

# Ensure models exist
ls ml/models/artifacts/logistic_regression_v1.0.0.joblib

docker compose up --build -d
curl http://127.0.0.1/api/v1/health
```

Default admin (first boot): `admin@localhost` / `admin12345` — **change immediately**.

## HTTPS

Recommended: put Cloudflare (or another reverse proxy) in front of the VPS and terminate TLS there.

For direct TLS with Nginx, mount certificates and enable the HTTPS server block in `docker/nginx.conf`.

## Environment variables

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Flask session signing |
| `DATABASE_URL` | SQLAlchemy URI |
| `MODEL_VERSION` | Active ML model tag |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Optional Gmail OAuth |
| `HTTP_PORT` | Host port mapped to Nginx (default 80) |

## Health & logs

```bash
docker compose ps
docker compose logs -f backend
curl http://127.0.0.1/api/v1/health
```

## Rollback

```bash
docker compose down
# restore previous image / artifacts
docker compose up -d
```

## PSM demonstration URL

Supervisor should open `https://your-domain.com` (not `localhost`) after Cloudflare + VPS setup.
