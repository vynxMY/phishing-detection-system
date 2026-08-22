# PhishGuard Browser Extension

Chrome Manifest V3 extension (also works on Microsoft Edge).

## Install (developer mode)

1. Start the web app: `PYTHONPATH=. python backend/wsgi.py`
2. Log in → **Integrations** → copy your API token
3. Chrome → `chrome://extensions` → Enable Developer mode → Load unpacked → select this `extension/` folder
   (or download the zip from the website **Browser extension** page, unzip, and load `phishguard-extension/`)
4. Open extension **Settings**, paste the API base from **Integrations** (local: `http://127.0.0.1:5000`, Docker: `http://127.0.0.1`, or your https:// hosted URL) and token. Click **Save** and allow site access if Chrome asks, then **Test connection**. Reload the unpacked extension after updates.
5. Open Gmail — opening a message triggers an automatic scan when auto-scan is ON

## Edge

Use the same package via `edge://extensions` → Load unpacked.
