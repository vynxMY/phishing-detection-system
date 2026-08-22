"""Feedback collection and admin review (Sprint 10)."""

from __future__ import annotations

import json
import secrets

from flask import Blueprint, flash, g, jsonify, redirect, render_template, request, url_for

from backend.app.auth.helpers import admin_required, login_required
from backend.app.database import EmailScan, Feedback, UserSettings, db

feedback_bp = Blueprint("feedback", __name__)


def get_or_create_settings(user_id: int) -> UserSettings:
    settings = UserSettings.query.filter_by(user_id=user_id).first()
    if settings is None:
        settings = UserSettings(user_id=user_id, api_token=secrets.token_hex(24))
        db.session.add(settings)
        db.session.commit()
    elif not settings.api_token:
        settings.api_token = secrets.token_hex(24)
        db.session.commit()
    return settings


@feedback_bp.route("/feedback", methods=["POST"])
@login_required
def submit_feedback():
    scan_id = request.form.get("scan_id", type=int)
    is_correct = request.form.get("is_correct")
    actual_label = (request.form.get("actual_label") or "").strip().lower() or None
    categories = request.form.getlist("error_categories")

    scan = db.session.get(EmailScan, scan_id)
    if scan is None or (scan.user_id != g.user.id and not g.user.is_admin):
        flash("Scan not found.", "error")
        return redirect(url_for("main.history"))

    if is_correct not in ("yes", "no"):
        flash("Please indicate whether the result was correct.", "error")
        return redirect(url_for("main.scan_result", scan_id=scan_id))

    correct = is_correct == "yes"
    if not correct and actual_label not in ("legitimate", "phishing"):
        flash("Select the correct classification.", "error")
        return redirect(url_for("main.scan_result", scan_id=scan_id))

    existing = Feedback.query.filter_by(scan_id=scan_id, user_id=g.user.id).first()
    if existing:
        existing.is_correct = correct
        existing.actual_label = None if correct else actual_label
        existing.error_categories = json.dumps(categories)
        existing.reviewed = False
        existing.approved = False
    else:
        fb = Feedback(
            scan_id=scan_id,
            user_id=g.user.id,
            is_correct=correct,
            actual_label=None if correct else actual_label,
            error_categories=json.dumps(categories),
        )
        db.session.add(fb)
    db.session.commit()
    flash("Thank you — your feedback was saved for review.", "success")
    return redirect(url_for("main.scan_result", scan_id=scan_id))


@feedback_bp.route("/admin/feedback")
@admin_required
def admin_feedback():
    pending = (
        Feedback.query.filter_by(reviewed=False)
        .order_by(Feedback.created_at.desc())
        .limit(100)
        .all()
    )
    reviewed = (
        Feedback.query.filter_by(reviewed=True)
        .order_by(Feedback.created_at.desc())
        .limit(50)
        .all()
    )
    return render_template("admin_feedback.html", pending=pending, reviewed=reviewed)


@feedback_bp.route("/admin/feedback/<int:feedback_id>/review", methods=["POST"])
@admin_required
def review_feedback(feedback_id: int):
    action = request.form.get("action")
    fb = db.session.get(Feedback, feedback_id)
    if fb is None:
        flash("Feedback not found.", "error")
        return redirect(url_for("feedback.admin_feedback"))

    fb.reviewed = True
    fb.approved = action == "approve"
    db.session.commit()
    flash("Feedback marked as approved." if fb.approved else "Feedback rejected.", "success")
    return redirect(url_for("feedback.admin_feedback"))
