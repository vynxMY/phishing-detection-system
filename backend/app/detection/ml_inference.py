"""ML model inference wrapper for the detection pipeline."""

from __future__ import annotations

import joblib
import pandas as pd

from ml.config import ARTIFACTS_DIR, DEFAULT_MODEL_VERSION

from backend.app.email_parser.models import NormalizedEmail


class MLInference:
    """Load trained Logistic Regression + feature extractor for inference."""

    def __init__(
        self,
        version: str = DEFAULT_MODEL_VERSION,
        prefer_text_only: bool = False,
    ):
        self.version = version
        self.model = None
        self.extractor = None
        self.model_label = version
        self._load(prefer_text_only)

    def _load(self, prefer_text_only: bool) -> None:
        # Experiment 2 story: prefer TF-IDF + URL/metadata when available.
        if prefer_text_only:
            labels = [
                f"{self.version}-text_only",
                self.version,
                "v1.1.0-text_only",
                "v1.0.0",
            ]
        else:
            labels = [
                f"{self.version}-text_metadata",
                f"{self.version}-text_only",
                self.version,
                "v1.1.0-text_metadata",
                "v1.1.0-text_only",
                "v1.0.0",
            ]

        model_path = None
        extractor_path = None
        for label in labels:
            m = ARTIFACTS_DIR / f"logistic_regression_{label}.joblib"
            e = ARTIFACTS_DIR / f"feature_extractor_{label}.joblib"
            if m.exists() and e.exists():
                model_path, extractor_path = m, e
                self.model_label = label
                break

        if model_path is None or extractor_path is None:
            raise FileNotFoundError(
                f"No trained model found in {ARTIFACTS_DIR}. Run Sprint 3 training first."
            )

        self.model = joblib.load(model_path)
        self.extractor = joblib.load(extractor_path)

    def predict(self, email: NormalizedEmail) -> dict:
        text = email.combined_text()
        subject = email.subject or ""

        # Support both TextFeatureExtractor and CombinedFeatureExtractor
        if hasattr(self.extractor, "mode"):
            df = pd.DataFrame([{"text": text, "subject": subject}])
            X = self.extractor.transform(df)
        else:
            X = self.extractor.transform(pd.Series([text]))

        proba = self.model.predict_proba(X)[0]
        pred = int(self.model.predict(X)[0])
        phishing_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])

        return {
            "prediction": "phishing" if pred == 1 else "legitimate",
            "phishing_probability": round(phishing_prob, 4),
            "legitimate_probability": round(1.0 - phishing_prob, 4),
            "model_version": self.model_label,
        }
