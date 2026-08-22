"""Main web routes: landing, dashboard, scan, history, profile, admin."""

from __future__ import annotations

from collections import Counter

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from backend.app.auth.helpers import admin_required, login_required
from backend.app.database import EmailScan, User, db
from backend.app.detection.pipeline import DetectionPipeline
from backend.app.security import rate_limit
from backend.app.services.scans import save_scan_result, scan_to_view

main_bp = Blueprint("main", __name__)

_pipeline: DetectionPipeline | None = None


def get_pipeline() -> DetectionPipeline:
    global _pipeline
    if _pipeline is None:
        version = current_app.config.get("MODEL_VERSION", "v1.0.0")
        _pipeline = DetectionPipeline(model_version=version)
    return _pipeline


@main_bp.route("/")
def landing():
    if g.user:
        return redirect(url_for("main.dashboard"))
    return render_template("landing.html")


@main_bp.route("/dashboard")
@login_required
def dashboard():
    scans = (
        EmailScan.query.filter_by(user_id=g.user.id)
        .order_by(EmailScan.created_at.desc())
        .limit(8)
        .all()
    )
    all_scans = EmailScan.query.filter_by(user_id=g.user.id).all()
    counts = Counter(s.classification for s in all_scans)
    stats = {
        "total": len(all_scans),
        "phishing": counts.get("phishing", 0) + counts.get("high_risk", 0),
        "suspicious": counts.get("suspicious", 0) + counts.get("low_risk", 0),
        "safe": counts.get("safe", 0),
    }
    return render_template(
        "dashboard.html",
        recent_scans=[scan_to_view(s) for s in scans],
        stats=stats,
    )


@main_bp.route("/scan", methods=["GET", "POST"])
@login_required
@rate_limit(30, 60, key_fn=lambda: f"scan:{getattr(g.user, 'id', request.remote_addr)}")
def scan():
    if request.method == "GET":
        return render_template("scan.html")

    text = (request.form.get("email_text") or "").strip()
    eml_file = request.files.get("eml_file")

    if not text and (not eml_file or not eml_file.filename):
        flash("Paste email content or upload a .eml file.", "error")
        return render_template("scan.html")

    try:
        pipeline = get_pipeline()
        if eml_file and eml_file.filename:
            result = pipeline.scan(
                eml_bytes=eml_file.read(),
                explanation_level="all",
            )
        else:
            result = pipeline.scan(text=text, explanation_level="all")
        scan_row = save_scan_result(g.user, result, provider="web")
        flash("Scan complete.", "success")
        return redirect(url_for("main.scan_result", scan_id=scan_row.id))
    except Exception as exc:
        current_app.logger.exception("Scan failed")
        flash(f"Scan failed: {exc}", "error")
        return render_template("scan.html", email_text=text)


@main_bp.route("/scan/<int:scan_id>")
@login_required
def scan_result(scan_id: int):
    scan = db.session.get(EmailScan, scan_id)
    if scan is None or (scan.user_id != g.user.id and not g.user.is_admin):
        flash("Scan not found.", "error")
        return redirect(url_for("main.history"))
    return render_template("result.html", scan=scan_to_view(scan))


@main_bp.route("/history")
@login_required
def history():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 15
    query = (
        EmailScan.query.filter_by(user_id=g.user.id)
        .order_by(EmailScan.created_at.desc())
    )
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template(
        "history.html",
        scans=[scan_to_view(s) for s in pagination.items],
        pagination=pagination,
    )


@main_bp.route("/profile")
@login_required
def profile():
    total = EmailScan.query.filter_by(user_id=g.user.id).count()
    return render_template("profile.html", total_scans=total)


@main_bp.route("/learn")
@login_required
def learn():
    return render_template("learn.html")


@main_bp.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.created_at.desc()).limit(50).all()
    scans = EmailScan.query.order_by(EmailScan.created_at.desc()).limit(20).all()
    all_scans = EmailScan.query.all()
    counts = Counter(s.classification for s in all_scans)
    avg_risk = (
        round(sum(s.risk_score for s in all_scans) / len(all_scans), 1)
        if all_scans
        else 0
    )
    return render_template(
        "admin.html",
        users=users,
        recent_scans=[scan_to_view(s) for s in scans],
        stats={
            "users": User.query.count(),
            "scans": len(all_scans),
            "phishing": counts.get("phishing", 0),
            "high_risk": counts.get("high_risk", 0),
            "suspicious": counts.get("suspicious", 0),
            "safe": counts.get("safe", 0),
            "avg_risk": avg_risk,
        },
    )
