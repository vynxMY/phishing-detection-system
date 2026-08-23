"""Auth routes: register / login / logout."""

from __future__ import annotations

import re

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from backend.app.auth.helpers import login_required, login_user, logout_user, safe_next_url
from backend.app.database import User, db
from backend.app.security import rate_limit

auth_bp = Blueprint("auth", __name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@auth_bp.route("/register", methods=["GET", "POST"])
@rate_limit(5, 60, key_fn=lambda: f"register:{request.remote_addr}")
def register():
    if g.user:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""

        if not EMAIL_RE.match(email):
            flash("Enter a valid email address.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
        else:
            user = User(email=email, role="user")
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash("Account created. Welcome.", "success")
            return redirect(url_for("main.dashboard"))

    return render_template("auth/register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
@rate_limit(10, 60, key_fn=lambda: f"login:{request.remote_addr}")
def login():
    if g.user:
        return redirect(safe_next_url(request.args.get("next")))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        user = User.query.filter_by(email=email).first()
        if user is None or not user.check_password(password):
            flash("Invalid email or password.", "error")
        else:
            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(safe_next_url(request.form.get("next") or request.args.get("next")))

    return render_template(
        "auth/login.html",
        next=request.form.get("next") or request.args.get("next") or "",
    )


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("main.landing"))
