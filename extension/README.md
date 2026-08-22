# PhishGuard Browser Extension

Chrome Manifest V3 extension (also works on Microsoft Edge).

## Install (developer mode)

1. Start the web app: `PYTHONPATH=. python backend/wsgi.py`
2. Log in → **Integrations** → copy your API token
3. Chrome → `chrome://extensions` → Enable Developer mode → Load unpacked → select this `extension/` folder
4. Open extension **Settings**, paste API base (`http://127.0.0.1:5000`) and token
5. Open Gmail — opening a message triggers an automatic scan when auto-scan is ON

## Edge

Use the same package via `edge://extensions` → Load unpacked.
