"""Gmail OAuth + connection management (Sprint 12)."""

from __future__ import annotations

import base64
import io
import json
import secrets
import zipfile
from pathlib import Path

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from paths import EXTENSION_DIR

from backend.app.api.feedback_routes import get_or_create_settings
from backend.app.auth.helpers import login_required
from backend.app.database import db
from gmail.oauth import (
    build_auth_url,
    exchange_code_for_tokens,
    fetch_gmail_message,
    fetch_user_email,
    google_configured,
    refresh_access_token,
)

gmail_bp = Blueprint("gmail", __name__)

_ZIP_SKIP_NAMES = {".ds_store", "thumbs.db"}


def extension_version() -> str:
    manifest = EXTENSION_DIR / "manifest.json"
    if not manifest.is_file():
        return "dev"
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
        return str(data.get("version") or "dev")
    except (OSError, json.JSONDecodeError):
        return "dev"


def build_extension_zip() -> bytes:
    """Zip the MV3 package so Chrome/Edge can Load unpacked after unzip."""
    if not (EXTENSION_DIR / "manifest.json").is_file():
        raise FileNotFoundError("extension/manifest.json is missing from this deployment")
    buf = io.BytesIO()
    prefix = Path("phishguard-extension")
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(EXTENSION_DIR.rglob("*")):
            if not path.is_file():
                continue
            if path.name.startswith(".") or path.name.lower() in _ZIP_SKIP_NAMES:
                continue
            if "__pycache__" in path.parts:
                continue
            arcname = prefix / path.relative_to(EXTENSION_DIR)
            zf.write(path, arcname.as_posix())
    return buf.getvalue()


@gmail_bp.route("/settings/integrations")
@login_required
def integrations():
    settings = get_or_create_settings(g.user.id)
    return render_template(
        "integrations.html",
        settings=settings,
        google_configured=google_configured(),
        extension_version=extension_version(),
        extension_available=(EXTENSION_DIR / "manifest.json").is_file(),
    )


@gmail_bp.route("/settings/integrations/extension.zip")
@login_required
def download_extension():
    try:
        payload = build_extension_zip()
    except FileNotFoundError:
        flash("The extension package is not included in this server build.", "error")
        return redirect(url_for("gmail.integrations"))
    filename = f"phishguard-extension-{extension_version()}.zip"
    return send_file(
        io.BytesIO(payload),
        mimetype="application/zip",
        as_attachment=True,
        download_name=filename,
        max_age=0,
    )


@gmail_bp.route("/settings/integrations/token/rotate", methods=["POST"])
@login_required
def rotate_token():
    settings = get_or_create_settings(g.user.id)
    settings.api_token = secrets.token_hex(24)
    db.session.commit()
    flash("API token rotated. Update your browser extension.", "success")
    return redirect(url_for("gmail.integrations"))


@gmail_bp.route("/settings/integrations/prefs", methods=["POST"])
@login_required
def save_prefs():
    settings = get_or_create_settings(g.user.id)
    settings.auto_scan = bool(request.form.get("auto_scan"))
    settings.scan_attachments = bool(request.form.get("scan_attachments"))
    settings.show_warnings = bool(request.form.get("show_warnings"))
    level = request.form.get("explanation_level") or "simple"
    if level in ("simple", "detailed", "technical"):
        settings.explanation_level = level
    db.session.commit()
    flash("Preferences saved.", "success")
    return redirect(url_for("gmail.integrations"))


@gmail_bp.route("/gmail/connect")
@login_required
def connect():
    if not google_configured():
        flash(
            "Google OAuth is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.",
            "warning",
        )
        return redirect(url_for("gmail.integrations"))

    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state
    return redirect(
        build_auth_url(
            redirect_uri=url_for("gmail.callback", _external=True),
            state=state,
        )
    )


@gmail_bp.route("/gmail/callback")
@login_required
def callback():
    if not google_configured():
        flash("Google OAuth is not configured.", "error")
        return redirect(url_for("gmail.integrations"))

    if request.args.get("state") != session.get("oauth_state"):
        flash("Invalid OAuth state.", "error")
        return redirect(url_for("gmail.integrations"))

    code = request.args.get("code")
    if not code:
        flash("OAuth cancelled or failed.", "error")
        return redirect(url_for("gmail.integrations"))

    try:
        tokens = exchange_code_for_tokens(
            code=code,
            redirect_uri=url_for("gmail.callback", _external=True),
        )
    except Exception:
        current_app.logger.exception("Google token exchange failed")
        flash("Failed to obtain Google tokens.", "error")
        return redirect(url_for("gmail.integrations"))

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    email = fetch_user_email(access_token) if access_token else None

    settings = get_or_create_settings(g.user.id)
    settings.gmail_connected = True
    settings.gmail_email = email
    if refresh_token:
        settings.google_refresh_token = refresh_token
    db.session.commit()
    flash(f"Gmail connected{f' as {email}' if email else ''}.", "success")
    return redirect(url_for("gmail.integrations"))


@gmail_bp.route("/gmail/disconnect", methods=["POST"])
@login_required
def disconnect():
    settings = get_or_create_settings(g.user.id)
    settings.gmail_connected = False
    settings.gmail_email = None
    settings.google_refresh_token = None
    db.session.commit()
    flash("Gmail disconnected. Tokens removed.", "success")
    return redirect(url_for("gmail.integrations"))


@gmail_bp.route("/api/v1/gmail/messages/<message_id>/scan", methods=["POST"])
@login_required
def scan_gmail_message(message_id: str):
    from backend.app.api.main_routes import get_pipeline
    from backend.app.services.scans import save_scan_result

    settings = get_or_create_settings(g.user.id)
    if not settings.gmail_connected or not settings.google_refresh_token:
        return {"error": "Gmail not connected"}, 400
    if not google_configured():
        return {"error": "Google OAuth not configured"}, 503

    try:
        access_token = refresh_access_token(settings.google_refresh_token)
        payload = fetch_gmail_message(access_token, message_id)
    except Exception as exc:
        current_app.logger.exception("Gmail API scan failed")
        return {"error": str(exc)}, 400

    text = _gmail_message_to_text(payload)
    pipeline = get_pipeline()
    result = pipeline.scan(text=text, explanation_level="detailed")
    scan_row = save_scan_result(g.user, result, provider="gmail_api")
    return {
        "scan_id": scan_row.id,
        "risk_score": result["risk_score"],
        "classification": result["classification"],
        "explanations": result["explanations"],
    }


def _gmail_message_to_text(payload: dict) -> str:
    headers = {
        h["name"].lower(): h["value"]
        for h in payload.get("payload", {}).get("headers", [])
    }
    lines = []
    for key in ("from", "reply-to", "subject", "date", "authentication-results"):
        if key in headers:
            lines.append(f"{key.title()}: {headers[key]}")
    lines.append("")

    def walk(part):
        texts = []
        mime = part.get("mimeType", "")
        body = part.get("body", {})
        data = body.get("data")
        if data and mime.startswith("text/"):
            raw = base64.urlsafe_b64decode(data + "==")
            texts.append(raw.decode("utf-8", errors="replace"))
        for child in part.get("parts") or []:
            texts.extend(walk(child))
        return texts

    body_parts = walk(payload.get("payload", {}))
    lines.append("\n".join(body_parts) if body_parts else payload.get("snippet", ""))
    return "\n".join(lines)
