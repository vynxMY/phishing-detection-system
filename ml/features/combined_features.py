"""Combined text + URL + metadata feature pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack, issparse
from sklearn.preprocessing import StandardScaler

from ml.features.metadata_features import MetadataFeatureExtractor
from ml.features.text_features import TextFeatureExtractor
from ml.features.url_features import URLFeatureExtractor


@dataclass
class CombinedFeatureExtractor:
    """
    Feature extractor supporting two modes:
    - text_only: TF-IDF + linguistic features (Sprint 3 baseline)
    - full: text + URL + sender/header metadata (Sprint 4)
    """

    mode: str = "full"
    text_extractor: TextFeatureExtractor = field(default_factory=TextFeatureExtractor)
    url_extractor: URLFeatureExtractor = field(default_factory=URLFeatureExtractor)
    metadata_extractor: MetadataFeatureExtractor = field(default_factory=MetadataFeatureExtractor)
    metadata_scaler: StandardScaler = field(default_factory=StandardScaler)
    _fitted: bool = False

    def fit(self, df: pd.DataFrame) -> CombinedFeatureExtractor:
        texts = df["text"]
        subjects = df["subject"] if "subject" in df.columns else pd.Series([""] * len(df))

        self.text_extractor.fit(texts)

        if self.mode == "full":
            url_feats = self.url_extractor.fit_transform(texts)
            meta_feats = self.metadata_extractor.fit_transform(texts, subjects)
            dense = np.hstack([url_feats, meta_feats])
            self.metadata_scaler.fit(dense)

        self._fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray | csr_matrix:
        if not self._fitted:
            raise RuntimeError("CombinedFeatureExtractor not fitted.")

        texts = df["text"]
        subjects = df["subject"] if "subject" in df.columns else pd.Series([""] * len(df))

        X_text = self.text_extractor.transform(texts)

        if self.mode == "text_only":
            return X_text

        url_feats = self.url_extractor.transform(texts)
        meta_feats = self.metadata_extractor.transform(texts, subjects)
        dense = self.metadata_scaler.transform(np.hstack([url_feats, meta_feats]))

        return hstack([X_text, csr_matrix(dense)])

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray | csr_matrix:
        return self.fit(df).transform(df)

    @property
    def feature_shape_info(self) -> dict:
        return {
            "mode": self.mode,
            "text_features": "tfidf+ngrams+linguistic",
            "metadata_features": "url+sender+header" if self.mode == "full" else None,
        }
