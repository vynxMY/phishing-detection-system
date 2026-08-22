"""URL-based feature extraction for phishing detection."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from ml.features.url_utils import extract_urls, parse_url_parts

URL_FEATURE_NAMES = [
    "url_count",
    "max_url_length",
    "avg_url_length",
    "max_domain_length",
    "max_subdomain_count",
    "max_path_length",
    "has_https_any",
    "has_ip_any",
    "has_port_any",
    "has_shortener_any",
    "has_suspicious_tld_any",
    "has_punycode_any",
    "https_ratio",
]


def _aggregate_url_features(urls: list[str]) -> list[float]:
    """Compute aggregate URL features for one email."""
    if not urls:
        return [0.0] * len(URL_FEATURE_NAMES)

    parsed = [parse_url_parts(u) for u in urls]
    parsed = [p for p in parsed if p]

    if not parsed:
        return [float(len(urls))] + [0.0] * (len(URL_FEATURE_NAMES) - 1)

    lengths = [p["length"] for p in parsed]
    https_flags = [p["has_https"] for p in parsed]

    return [
        float(len(urls)),
        float(max(lengths)),
        float(sum(lengths) / len(lengths)),
        float(max(p["domain_length"] for p in parsed)),
        float(max(p["subdomain_count"] for p in parsed)),
        float(max(p["path_length"] for p in parsed)),
        float(max(p["has_https"] for p in parsed)),
        float(max(p["has_ip"] for p in parsed)),
        float(max(p["has_port"] for p in parsed)),
        float(max(p["has_shortener"] for p in parsed)),
        float(max(p["has_suspicious_tld"] for p in parsed)),
        float(max(p["has_punycode"] for p in parsed)),
        float(sum(https_flags) / len(https_flags)),
    ]


@dataclass
class URLFeatureExtractor:
    """Extract aggregate URL features from email text."""

    def fit(self, texts: pd.Series) -> URLFeatureExtractor:
        return self

    def transform(self, texts: pd.Series) -> np.ndarray:
        rows = [_aggregate_url_features(extract_urls(str(t))) for t in texts.fillna("")]
        return np.array(rows, dtype=np.float64)

    def fit_transform(self, texts: pd.Series) -> np.ndarray:
        return self.fit(texts).transform(texts)
