"""Logistic Regression classifier for phishing email detection."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV, StratifiedKFold

from ml.config import (
    ARTIFACTS_DIR,
    LR_CLASS_WEIGHT,
    LR_DEFAULT_C,
    LR_MAX_ITER,
    LR_SOLVER,
    RANDOM_SEED,
)


@dataclass
class LogisticRegressionModel:
    """Logistic Regression wrapper with training and persistence."""

    version: str = "v1.0.0"
    model: LogisticRegression | None = None
    best_params: dict = field(default_factory=dict)
    trained_at: str | None = None

    def build_estimator(self, **kwargs) -> LogisticRegression:
        params = {
            "C": LR_DEFAULT_C,
            "max_iter": LR_MAX_ITER,
            "class_weight": LR_CLASS_WEIGHT,
            "random_state": RANDOM_SEED,
            "solver": LR_SOLVER,
        }
        params.update(kwargs)
        return LogisticRegression(**params)

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        tune: bool = True,
        fixed_c: float | None = None,
    ) -> LogisticRegressionModel:
        """Train Logistic Regression, optionally with hyperparameter tuning."""
        if fixed_c is not None:
            self.model = self.build_estimator(C=fixed_c)
            self.model.fit(X_train, y_train)
            self.best_params = {"C": fixed_c}
        elif tune:
            self.model = self._tune_hyperparameters(X_train, y_train)
        else:
            self.model = self.build_estimator()
            self.model.fit(X_train, y_train)

        self.trained_at = datetime.now(timezone.utc).isoformat()
        return self

    def _tune_hyperparameters(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
    ) -> LogisticRegression:
        """GridSearchCV over C on 5-fold stratified cross-validation."""
        base = self.build_estimator()
        param_grid = {
            "C": [0.1, 1.0, 10.0, 100.0, 1000.0],
        }
        cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=RANDOM_SEED)
        search = GridSearchCV(
            base,
            param_grid,
            cv=cv,
            scoring="f1",
            n_jobs=-1,
            refit=True,
        )
        search.fit(X_train, y_train)
        self.best_params = search.best_params_
        print(f"Best LR params: {search.best_params_} (CV F1={search.best_score_:.4f})")
        return search.best_estimator_

    def predict(self, X: np.ndarray) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("Model not trained.")
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("Model not trained.")
        return self.model.predict_proba(X)

    def save(self, path: Path | None = None) -> Path:
        """Persist model and metadata."""
        if self.model is None:
            raise RuntimeError("Model not trained.")

        ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        model_path = path or ARTIFACTS_DIR / f"logistic_regression_{self.version}.joblib"
        meta_path = model_path.with_suffix(".json")

        joblib.dump(self.model, model_path)

        metadata = {
            "version": self.version,
            "algorithm": "logistic_regression",
            "best_params": self.best_params,
            "trained_at": self.trained_at,
            "class_weight": LR_CLASS_WEIGHT,
            "model_path": str(model_path.name),
        }
        meta_path.write_text(json.dumps(metadata, indent=2))
        print(f"Model saved: {model_path}")
        return model_path

    @classmethod
    def load(cls, path: Path) -> LogisticRegressionModel:
        """Load a saved model."""
        model = joblib.load(path)
        meta_path = path.with_suffix(".json")
        metadata = json.loads(meta_path.read_text()) if meta_path.exists() else {}

        instance = cls(
            version=metadata.get("version", "unknown"),
            model=model,
            best_params=metadata.get("best_params", {}),
            trained_at=metadata.get("trained_at"),
        )
        return instance
