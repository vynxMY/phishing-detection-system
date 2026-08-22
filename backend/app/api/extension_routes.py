"""REST API for extension + Gmail integrations (Sprints 11–12)."""

from __future__ import annotations

from functools import wraps

from flask import Blueprint, current_app, g, jsonify, request

from backend.app.api.feedback_routes import get_or_create_settings
from backend.app.api.main_routes import get_pipeline, _normalize_url, run_url_scan
from backend.app.database import User, UserSettings, db
from backend.app.services.scans import save_scan_result

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


def api_token_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = None
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        token = token or request.headers.get("X-API-Token")
        if not token:
            return jsonify({"error": {"code": "UNAUTHORIZED", "message": "API token required"}}), 401
        settings = UserSettings.query.filter_by(api_token=token).first()
        if settings is None:
            return jsonify({"error": {"code": "UNAUTHORIZED", "message": "Invalid API token"}}), 401
        g.api_user = db.session.get(User, settings.user_id)
        g.api_settings = settings
        if g.api_user is None:
            return jsonify({"error": {"code": "UNAUTHORIZED", "message": "User not found"}}), 401
        return view(*args, **kwargs)

    return wrapped


@api_bp.route("/health")
def health():
    return jsonify({"status": "ok", "service": "phishing-detection-api"})


@api_bp.route("/extension/scan", methods=["POST"])
@api_token_required
def extension_scan():
    """Scan email payload from browser extension."""
    settings: UserSettings = g.api_settings
    if not settings.show_warnings and request.json and request.json.get("source") == "auto":
        return jsonify({"skipped": True, "reason": "warnings_disabled"})

    if request.json and request.json.get("source") == "auto" and not settings.auto_scan:
        return jsonify({"skipped": True, "reason": "auto_scan_disabled"})

    data = request.get_json(silent=True) or {}
    subject = data.get("subject") or ""
    sender = data.get("sender") or data.get("from") or ""
    reply_to = data.get("reply_to") or ""
    body = data.get("body") or data.get("text") or ""
    headers = data.get("headers") or {}

    if not body and not subject:
        return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "Email body or subject required"}}), 400

    # Reconstruct a paste-style email for the parser
    lines = []
    if sender:
        lines.append(f"From: {sender}")
    if reply_to:
        lines.append(f"Reply-To: {reply_to}")
    if subject:
        lines.append(f"Subject: {subject}")
    auth = headers.get("authentication-results") or headers.get("Authentication-Results")
    if auth:
        lines.append(f"Authentication-Results: {auth}")
    lines.append("")
    lines.append(body)
    text = "\n".join(lines)

    level = settings.explanation_level or "simple"
    pipeline = get_pipeline()
    result = pipeline.scan(text=text, explanation_level="all" if level == "detailed" else level)
    scan_row = save_scan_result(g.api_user, result, provider="extension")

    return jsonify({
        "scan_id": scan_row.id,
        "analysis_path": f"/scan/{scan_row.id}",
        "risk_score": result["risk_score"],
        "classification": result["classification"],
        "confidence": result["confidence"],
        "breakdown": result["breakdown"],
        "explanations": {
            "simple": result["explanations"].get("simple"),
            "findings": result["explanations"].get("findings", [])[:8],
        },
        "advice": result.get("advice"),
        "model_version": result.get("model_version"),
    })


@api_bp.route("/extension/scan-url", methods=["POST"])
@api_token_required
def extension_scan_url():
    """Scan the current tab URL with the same Logistic Regression pipeline as the web URL scanner."""
    data = request.get_json(silent=True) or {}
    target = _normalize_url(data.get("url") or "")
    if target is None:
        return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "Enter a valid http(s) URL."}}), 400
    scan_row, result = run_url_scan(g.api_user, target)
    findings = (result.get("explanations") or {}).get("findings", [])[:5]
    return jsonify({
        "scan_id": scan_row.id,
        "analysis_path": f"/scan/{scan_row.id}",
        "url": target,
        "risk_score": result["risk_score"],
        "classification": result["classification"],
        "confidence": result["confidence"],
        "explanations": {
            "simple": result["explanations"].get("simple"),
            "findings": findings,
        },
        "advice": result.get("advice"),
        "model_version": result.get("model_version"),
    })


@api_bp.route("/extension/settings", methods=["GET", "PUT"])
@api_token_required
def extension_settings():
    settings: UserSettings = g.api_settings
    if request.method == "GET":
        return jsonify({
            "auto_scan": settings.auto_scan,
            "scan_attachments": settings.scan_attachments,
            "show_warnings": settings.show_warnings,
            "explanation_level": settings.explanation_level,
            "gmail_connected": settings.gmail_connected,
        })

    data = request.get_json(silent=True) or {}
    for field in ("auto_scan", "scan_attachments", "show_warnings"):
        if field in data:
            setattr(settings, field, bool(data[field]))
    if "explanation_level" in data and data["explanation_level"] in ("simple", "detailed", "technical"):
        settings.explanation_level = data["explanation_level"]
    db.session.commit()
    return jsonify({"ok": True})
