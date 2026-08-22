"""Text feature extraction: TF-IDF, n-grams, and linguistic features."""

from __future__ import annotations

import re
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer

from ml.config import (
    TFIDF_MAX_DF,
    TFIDF_MAX_FEATURES,
    TFIDF_MIN_DF,
    TFIDF_NGRAM_RANGE,
)

# Linguistic indicator patterns
URGENCY_PATTERN = re.compile(
    r"\b(urgent|immediately|asap|act now|expire|deadline|within 24 hours|"
    r"limited time|hurry|right away|final notice)\b",
    re.IGNORECASE,
)
THREAT_PATTERN = re.compile(
    r"\b(suspend|terminated|closed|locked|unauthorized|illegal|"
    r"legal action|consequences|failure to|will be disabled)\b",
    re.IGNORECASE,
)
CREDENTIAL_PATTERN = re.compile(
    r"\b(password|login|verify your account|confirm your identity|"
    r"update your information|security verification|credentials)\b",
    re.IGNORECASE,
)
FINANCIAL_PATTERN = re.compile(
    r"\b(payment|invoice|refund|wire transfer|bank account|credit card|"
    r"billing|overdue|transaction)\b",
    re.IGNORECASE,
)
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)


def _extract_linguistic_features(texts: pd.Series) -> np.ndarray:
    """Extract numeric linguistic features from email texts."""
    features = []
    for text in texts.fillna(""):
        text_str = str(text)
        features.append(
            [
                len(text_str),
                len(text_str.split()),
                text_str.count("!"),
                text_str.count("?"),
                len(URL_PATTERN.findall(text_str)),
                int(bool(URGENCY_PATTERN.search(text_str))),
                int(bool(THREAT_PATTERN.search(text_str))),
                int(bool(CREDENTIAL_PATTERN.search(text_str))),
                int(bool(FINANCIAL_PATTERN.search(text_str))),
                sum(1 for c in text_str if c.isupper()) / max(len(text_str), 1),
            ]
        )
    return np.array(features, dtype=np.float64)


def build_text_feature_pipeline() -> Pipeline:
    """
    Build a sklearn Pipeline combining TF-IDF (with n-grams) and linguistic features.

    TF-IDF uses unigrams and bigrams (ngram_range 1–2) per spec.
    """
    linguistic_transformer = FunctionTransformer(
        _extract_linguistic_features,
        validate=False,
    )

    return Pipeline(
        [
            (
                "features",
                FeatureUnion(
                    [
                        (
                            "tfidf",
                            TfidfVectorizer(
                                max_features=TFIDF_MAX_FEATURES,
                                ngram_range=TFIDF_NGRAM_RANGE,
                                min_df=TFIDF_MIN_DF,
                                max_df=TFIDF_MAX_DF,
                                sublinear_tf=True,
                                strip_accents="unicode",
                                lowercase=True,
                                stop_words="english",
                            ),
                        ),
                        ("linguistic", linguistic_transformer),
                    ]
                ),
            ),
        ]
    )


@dataclass
class TextFeatureExtractor:
    """Wrapper for fitting and transforming email text features."""

    pipeline: Pipeline | None = None

    def fit(self, texts: pd.Series) -> TextFeatureExtractor:
        self.pipeline = build_text_feature_pipeline()
        self.pipeline.fit(texts)
        return self

    def transform(self, texts: pd.Series) -> np.ndarray:
        if self.pipeline is None:
            raise RuntimeError("Feature extractor not fitted. Call fit() first.")
        return self.pipeline.transform(texts)

    def fit_transform(self, texts: pd.Series) -> np.ndarray:
        return self.fit(texts).transform(texts)

    @property
    def tfidf_vectorizer(self) -> TfidfVectorizer:
        if self.pipeline is None:
            raise RuntimeError("Feature extractor not fitted.")
        union: FeatureUnion = self.pipeline.named_steps["features"]
        return union.transformer_list[0][1]

    def top_tfidf_features(self, n: int = 20) -> list[tuple[str, float]]:
        """Return top TF-IDF terms by mean weight (for explainability)."""
        vectorizer = self.tfidf_vectorizer
        if not hasattr(vectorizer, "vocabulary_"):
            return []
        # Return feature names sorted alphabetically for reference
        names = vectorizer.get_feature_names_out()
        return [(name, 0.0) for name in names[:n]]
