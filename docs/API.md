# API Reference (PSM Prototype)

Base URL (local): `http://127.0.0.1:5000`

## Health

| Method | Path | Auth |
|---|---|---|
| GET | `/api/v1/health` | None |

## Extension API

| Method | Path | Auth |
|---|---|---|
| POST | `/api/v1/extension/scan` | Bearer API token |
| GET/PUT | `/api/v1/extension/settings` | Bearer API token |

Header: `Authorization: Bearer <token>`  
Token is issued on the web **Integrations** page.

### POST `/api/v1/extension/scan`

```json
{
  "subject": "...",
  "sender": "...",
  "reply_to": "...",
  "body": "...",
  "headers": {"authentication-results": "spf=fail"},
  "source": "auto"
}
```

Response includes `risk_score`, `classification`, `breakdown`, `explanations`, `advice`.

## Web pages (session auth)

| Path | Description |
|---|---|
| `/` | Landing |
| `/register`, `/login`, `/logout` | Auth |
| `/dashboard` | Overview |
| `/scan`, `/scan/<id>` | Scanner + result |
| `/history` | Scan history |
| `/learn` | Awareness |
| `/profile` | Account |
| `/settings/integrations` | API token, prefs, Gmail OAuth |
| `/admin`, `/admin/feedback` | Admin only |
| `/feedback` | Submit scan feedback (POST) |

## Gmail

| Path | Description |
|---|---|
| `/gmail/connect` | Start Google OAuth |
| `/gmail/callback` | OAuth callback |
| `/gmail/disconnect` | Revoke stored tokens |
| `/api/v1/gmail/messages/<id>/scan` | Fetch + scan via Gmail API |

Requires `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`.
