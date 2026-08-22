"""SQLAlchemy database models."""

from __future__ import annotations

from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    scans = db.relationship("EmailScan", back_populates="user", lazy="dynamic")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


class EmailScan(db.Model):
    __tablename__ = "email_scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    provider = db.Column(db.String(20), default="web")
    message_hash = db.Column(db.String(64), nullable=True)
    subject = db.Column(db.String(500), nullable=True)  # optional short summary only
    sender = db.Column(db.String(255), nullable=True)
    classification = db.Column(db.String(20), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    confidence = db.Column(db.Float, nullable=True)
    model_version = db.Column(db.String(40), nullable=True)
    breakdown_json = db.Column(db.Text, nullable=True)
    explanations_json = db.Column(db.Text, nullable=True)
    advice_json = db.Column(db.Text, nullable=True)
    findings_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)

    user = db.relationship("User", back_populates="scans")
    features = db.relationship("EmailFeature", back_populates="scan", uselist=False)


class EmailFeature(db.Model):
    __tablename__ = "email_features"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("email_scans.id"), nullable=False, unique=True)
    content_score = db.Column(db.Integer, default=0)
    url_score = db.Column(db.Integer, default=0)
    sender_score = db.Column(db.Integer, default=0)
    auth_score = db.Column(db.Integer, default=0)
    attachment_score = db.Column(db.Integer, default=0)
    brand_score = db.Column(db.Integer, default=0)

    scan = db.relationship("EmailScan", back_populates="features")


class Feedback(db.Model):
    __tablename__ = "feedback"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("email_scans.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    is_correct = db.Column(db.Boolean, nullable=False)
    actual_label = db.Column(db.String(20), nullable=True)  # legitimate | phishing
    error_categories = db.Column(db.Text, nullable=True)  # JSON array
    reviewed = db.Column(db.Boolean, default=False)
    approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=utcnow)

    scan = db.relationship("EmailScan")
    user = db.relationship("User")


class UserSettings(db.Model):
    __tablename__ = "user_settings"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True, nullable=False)
    auto_scan = db.Column(db.Boolean, default=True)
    scan_attachments = db.Column(db.Boolean, default=True)
    show_warnings = db.Column(db.Boolean, default=True)
    explanation_level = db.Column(db.String(20), default="simple")
    api_token = db.Column(db.String(64), unique=True, nullable=True, index=True)
    gmail_connected = db.Column(db.Boolean, default=False)
    gmail_email = db.Column(db.String(255), nullable=True)
    google_refresh_token = db.Column(db.Text, nullable=True)  # encrypted in production
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    user = db.relationship("User")
