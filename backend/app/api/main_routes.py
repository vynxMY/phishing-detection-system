"""Main web routes: landing, dashboard, scan, history, profile, admin."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

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
from paths import ML_ARTIFACTS

main_bp = Blueprint("main", __name__)

_pipeline: DetectionPipeline | None = None
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)

SIGNAL_LABELS = {
    "content": "Urgent / risky language",
    "url": "Suspicious URL characteristics",
    "sender": "Sender / domain mismatch",
    "authentication": "Email authentication issues",
    "attachment": "Attachment risk",
    "brand": "Brand impersonation",
}


def verdict_for(classification: str) -> dict:
    """Human-first copy. Decision → evidence → action. Probability stays secondary."""
    c = (classification or "").lower()
    if c in ("phishing", "high_risk"):
        return {
            "tone": "phishing",
            "headline": "This email is likely phishing.",
            "verdict": "High risk",
            "risk_label": "High risk",
            "lead": "We found several characteristics that are commonly associated with phishing.",
            "recommendation": "Don't click links or provide personal information.",
        }
    if c == "suspicious":
        return {
            "tone": "suspicious",
            "headline": "This deserves a closer look.",
            "verdict": "Suspicious",
            "risk_label": "Suspicious",
            "lead": "We found unusual characteristics, but there isn't enough evidence to confidently call it phishing.",
            "recommendation": "Avoid entering sensitive information until you verify the sender.",
        }
    return {
        "tone": "safe",
        "headline": "This looks safe.",
        "verdict": "Safe",
        "risk_label": "Safe",
        "lead": "We didn't find strong indicators associated with phishing.",
        "recommendation": "Still be careful: no automated detector can guarantee complete safety.",
    }


def with_verdict(view: dict) -> dict:
    view["verdict"] = verdict_for(view.get("classification") or "")
    expl = view.get("explanations") or {}
    why = expl.get("why_dangerous")
    if why:
        view["verdict"]["lead"] = why
    conf_label = expl.get("confidence_label")
    if not conf_label and view.get("confidence") is not None:
        c = float(view["confidence"])
        conf_label = "High" if c >= 0.65 else ("Low" if c < 0.4 else "Medium")
    view["confidence_label"] = conf_label
    return view


def get_pipeline() -> DetectionPipeline:
    global _pipeline
    if _pipeline is None:
        version = current_app.config.get("MODEL_VERSION", "v1.1.0")
        _pipeline = DetectionPipeline(model_version=version)
    return _pipeline


def load_lab_metrics() -> dict | None:
    """Held-out test metrics from training — never invent dashboard vanity numbers."""
    # Prefer newest summary that exists; fall back to baseline Experiment 1.
    for name in (
        "training_summary_v1.1.0-text_metadata.json",
        "training_summary_v1.1.0.json",
        "training_summary_v1.0.0.json",
    ):
        path = ML_ARTIFACTS / name
        if path.exists():
            break
    else:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    tm = data.get("test_metrics") or {}
    if not tm:
        return None
    return {
        "version": data.get("model_version") or path.stem.replace("training_summary_", ""),
        "algorithm": data.get("algorithm") or "logistic_regression",
        "accuracy": round(float(tm.get("accuracy") or 0) * 100, 2),
        "precision": round(float(tm.get("precision") or 0) * 100, 2),
        "recall": round(float(tm.get("recall") or 0) * 100, 2),
        "f1": round(float(tm.get("f1") or 0) * 100, 2),
        "fnr": (
            round(float(tm.get("false_negative_rate") or tm.get("fnr") or 0) * 100, 2)
            if (tm.get("false_negative_rate") is not None or tm.get("fnr") is not None)
            else None
        ),
        "fpr": (
            round(float(tm.get("false_positive_rate") or tm.get("fpr") or 0) * 100, 2)
            if (tm.get("false_positive_rate") is not None or tm.get("fpr") is not None)
            else None
        ),
    }


def _normalize_url(raw: str) -> str | None:
    value = (raw or "").strip()
    if not value or len(value) > 2048:
        return None
    if value.lower().startswith(("javascript:", "data:", "file:", "vbscript:")):
        return None
    if not _URL_RE.match(value):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    if parsed.netloc in ("localhost", "127.0.0.1") or parsed.netloc.startswith("127."):
        return None
    return value


def url_as_email_text(target: str) -> str:
    """Wrap a URL as a short message so the email LR pipeline can extract URL + text features."""
    return (
        "From: url-check@phishguard.local\n"
        "Subject: URL analysis\n\n"
        f"Please review this link: {target}\n"
    )


def run_url_scan(user, target: str):
    result = get_pipeline().scan(text=url_as_email_text(target), explanation_level="all")
    result.setdefault("email_summary", {})
    result["email_summary"]["subject"] = target[:500]
    result["email_summary"]["sender"] = "url-scanner"
    return save_scan_result(user, result, provider="url"), result


def _user_scans():
    return EmailScan.query.filter_by(user_id=g.user.id)


@main_bp.route("/")
def landing():
    if g.user:
        return redirect(url_for("main.dashboard"))
    return render_template("landing.html", lab=load_lab_metrics())


@main_bp.route("/dashboard")
@login_required
def dashboard():
    query = _user_scans()
    scans = query.order_by(EmailScan.created_at.desc()).limit(8).all()
    all_scans = query.all()
    counts = Counter(s.classification for s in all_scans)
    phishing = counts.get("phishing", 0) + counts.get("high_risk", 0)
    suspicious = counts.get("suspicious", 0)
    safe = counts.get("safe", 0) + counts.get("low_risk", 0)
    stats = {
        "total": len(all_scans),
        "phishing": phishing,
        "suspicious": suspicious,
        "safe": safe,
    }

    cutoff = datetime.now(timezone.utc) - timedelta(days=13)
    buckets: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "phishing": 0})
    for s in all_scans:
        created = s.created_at
        if created is None:
            continue
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if created < cutoff:
            continue
        key = created.date().isoformat()
        buckets[key]["total"] += 1
        if s.classification in ("phishing", "high_risk"):
            buckets[key]["phishing"] += 1
    days = []
    cursor = cutoff.date()
    today = datetime.now(timezone.utc).date()
    max_total = 1
    while cursor <= today:
        key = cursor.isoformat()
        row = buckets[key]
        max_total = max(max_total, row["total"])
        days.append({"label": cursor.strftime("%d %b"), "total": row["total"], "phishing": row["phishing"]})
        cursor += timedelta(days=1)
    for row in days:
        row["pct"] = round(100 * row["total"] / max_total) if max_total else 0
        row["phish_pct"] = round(100 * row["phishing"] / max_total) if max_total else 0
        row["rest_pct"] = max(row["pct"] - row["phish_pct"], 0)

    indicator_counts: Counter[str] = Counter()
    for s in scans:
        view = scan_to_view(s)
        for finding in view.get("findings") or []:
            cat = (finding.get("category") or "other").replace("_", " ")
            indicator_counts[cat] += 1
    top_indicators = indicator_counts.most_common(6)

    hour = datetime.now().hour
    if hour < 12:
        greeting = "Good morning"
    elif hour < 18:
        greeting = "Good afternoon"
    else:
        greeting = "Good evening"
    name = (g.user.email or "there").split("@")[0]

    return render_template(
        "dashboard.html",
        greeting=greeting,
        display_name=name,
        recent_scans=[with_verdict(scan_to_view(s)) for s in scans],
        stats=stats,
        trend=days,
        top_indicators=top_indicators,
        lab=load_lab_metrics(),
        signal_labels=SIGNAL_LABELS,
    )


@main_bp.route("/scan", methods=["GET", "POST"])
@login_required
@rate_limit(30, 60, key_fn=lambda: f"scan:{getattr(g.user, 'id', request.remote_addr)}")
def scan():
    if request.method == "GET":
        return render_template("check.html", mode="email", email_text="", sender="", subject="", body="")

    sender = (request.form.get("sender") or "").strip()
    subject = (request.form.get("subject") or "").strip()
    body = (request.form.get("body") or "").strip()
    text = (request.form.get("email_text") or "").strip()
    eml_file = request.files.get("eml_file")

    if sender or subject or body:
        lines = []
        if sender:
            lines.append(f"From: {sender}")
        if subject:
            lines.append(f"Subject: {subject}")
        lines.append("")
        lines.append(body or text)
        text = "\n".join(lines)

    if not text and (not eml_file or not eml_file.filename):
        flash("Paste the message, fill in the fields, or upload a .eml file.", "error")
        return render_template(
            "check.html",
            mode="email",
            sender=sender,
            subject=subject,
            body=body,
            email_text=text,
        )

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
        return redirect(url_for("main.scan_result", scan_id=scan_row.id))
    except Exception as exc:
        current_app.logger.exception("Scan failed")
        flash(f"Scan failed: {exc}", "error")
        return render_template(
            "check.html",
            mode="email",
            sender=sender,
            subject=subject,
            body=body,
            email_text=text,
        )


@main_bp.route("/scan/url", methods=["GET", "POST"])
@login_required
@rate_limit(30, 60, key_fn=lambda: f"scan-url:{getattr(g.user, 'id', request.remote_addr)}")
def scan_url():
    preset = (request.args.get("url") or "").strip()
    if request.method == "GET":
        return render_template("check.html", mode="url", url_value=preset)

    raw = (request.form.get("url") or "").strip()
    target = _normalize_url(raw)
    if target is None:
        flash("Enter a valid http(s) URL.", "error")
        return render_template("check.html", mode="url", url_value=raw)

    try:
        scan_row, _result = run_url_scan(g.user, target)
        return redirect(url_for("main.scan_result", scan_id=scan_row.id))
    except Exception as exc:
        current_app.logger.exception("URL scan failed")
        flash(f"Scan failed: {exc}", "error")
        return render_template("check.html", mode="url", url_value=raw)


@main_bp.route("/scan/<int:scan_id>")
@login_required
def scan_result(scan_id: int):
    scan = db.session.get(EmailScan, scan_id)
    if scan is None or (scan.user_id != g.user.id and not g.user.is_admin):
        flash("Scan not found.", "error")
        return redirect(url_for("main.history"))
    view = scan_to_view(scan)
    contrib = []
    features = view.get("features") or {}
    max_pts = max(features.values()) if features else 0
    for key, pts in features.items():
        if pts <= 0:
            continue
        contrib.append({
            "key": key,
            "label": SIGNAL_LABELS.get(key, key.replace("_", " ").title()),
            "points": pts,
            "pct": round(100 * pts / max_pts) if max_pts else 0,
        })
    contrib.sort(key=lambda row: row["points"], reverse=True)
    return render_template(
        "result.html",
        scan=with_verdict(view),
        contributions=contrib,
        signal_labels=SIGNAL_LABELS,
    )


@main_bp.route("/scan/<int:scan_id>/report")
@login_required
def scan_report(scan_id: int):
    scan = db.session.get(EmailScan, scan_id)
    if scan is None or (scan.user_id != g.user.id and not g.user.is_admin):
        flash("Scan not found.", "error")
        return redirect(url_for("main.history"))
    return render_template("report.html", scan=with_verdict(scan_to_view(scan)), generated=datetime.now(timezone.utc))


@main_bp.route("/history")
@login_required
def history():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 15
    q = (request.args.get("q") or "").strip()
    classification = (request.args.get("classification") or "").strip()
    provider = (request.args.get("provider") or "").strip()
    query = _user_scans().order_by(EmailScan.created_at.desc())
    if classification:
        query = query.filter(EmailScan.classification == classification)
    if provider:
        query = query.filter(EmailScan.provider == provider)
    if q:
        like = f"%{q}%"
        query = query.filter(
            db.or_(EmailScan.subject.ilike(like), EmailScan.sender.ilike(like))
        )
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    views = [with_verdict(scan_to_view(s)) for s in pagination.items]
    groups = []
    today = datetime.now(timezone.utc).date()
    current_label = None
    bucket = []
    for view in views:
        created = view.get("created_at")
        if created is None:
            label = "Earlier"
        else:
            day = created.date() if hasattr(created, "date") else created
            if day == today:
                label = "Today"
            elif day == today - timedelta(days=1):
                label = "Yesterday"
            else:
                label = created.strftime("%d %b %Y")
        if label != current_label:
            if bucket:
                groups.append({"label": current_label, "scans": bucket})
            current_label = label
            bucket = [view]
        else:
            bucket.append(view)
    if bucket:
        groups.append({"label": current_label, "scans": bucket})
    return render_template(
        "history.html",
        scans=views,
        groups=groups,
        pagination=pagination,
        q=q,
        classification=classification,
        provider=provider,
    )


@main_bp.route("/reports")
@login_required
def reports():
    scans = (
        _user_scans()
        .order_by(EmailScan.created_at.desc())
        .limit(40)
        .all()
    )
    return render_template("reports.html", scans=[with_verdict(scan_to_view(s)) for s in scans])


@main_bp.route("/profile")
@login_required
def profile():
    total = _user_scans().count()
    return render_template("profile.html", total_scans=total)


@main_bp.route("/learn")
def learn():
    return render_template("learn.html")


@main_bp.route("/about")
def about():
    return render_template("about.html", lab=load_lab_metrics())


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
        lab=load_lab_metrics(),
    )
