"""Authentication helpers."""

from __future__ import annotations

from functools import wraps

from flask import flash, g, redirect, session, url_for

from backend.app.database import User, db


def load_current_user() -> User | None:
    user_id = session.get("user_id")
    if not user_id:
        g.user = None
        return None
    g.user = db.session.get(User, user_id)
    return g.user


def login_user(user: User) -> None:
    session.clear()
    session["user_id"] = user.id
    session.permanent = True


def logout_user() -> None:
    session.clear()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login"))
        if not g.user.is_admin:
            flash("Administrator access required.", "error")
            return redirect(url_for("main.dashboard"))
        return view(*args, **kwargs)

    return wrapped
