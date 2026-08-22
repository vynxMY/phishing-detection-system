# Security Testing Checklist — Sprint 14

Automated coverage lives in `backend/tests/test_security.py`.

| Test | Status | Notes |
|---|---|---|
| SQL Injection (login) | Automated | Parameterized ORM queries |
| XSS (output escaping) | Automated | Jinja autoescape |
| CSRF (authenticated POST) | Automated | CSRF tokens on forms |
| Authentication bypass | Automated | `/scan` requires login |
| Broken access control | Automated | User B cannot view User A scan |
| API abuse (no token) | Automated | `/api/v1/extension/scan` → 401 |
| Rate limiting | Implemented | Login 10/min, register 5/min, scan 30/min |
| Security headers | Automated | CSP, XFO, nosniff, Referrer-Policy |
| HSTS | Conditional | Set when HTTPS / X-Forwarded-Proto |
| File upload size | Config | `MAX_CONTENT_LENGTH` = 10 MB |
| Malicious email parsing | Manual | Deep MIME / huge payloads |
| SSRF | Design | URL analyser does not fetch remote URLs in PSM |
| OAuth issues | Manual | Enable when Google credentials configured |
| Extension permissions | Manual | Review `extension/manifest.json` |

## Manual ZAP / browser pass (recommended before PSM demo)

1. Spider authenticated user area
2. Active scan login + scan endpoints
3. Confirm CSRF tokens present on forms
4. Confirm admin routes blocked for normal users
5. Confirm API rejects missing/invalid Bearer tokens

## Commands

```bash
PYTHONPATH=. python -m pytest backend/tests/test_security.py -v
```
