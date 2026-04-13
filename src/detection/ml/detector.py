# src/detection/ml/detector.py
"""ML-based anomaly detector using pre-trained Isolation Forest.

Loads the serialized model and scaler, then scores new events.
Higher scores mean more anomalous behavior.
"""
import pickle
import numpy as np
from pathlib import Path
from src.detection.feature_extractor import extract
from src.ingestion.schema import NormalizedLog

DEFAULT_MODEL_PATH = Path("data/models/isolation_forest.pkl")


class MLDetector:
    """Load trained IF model and score incoming log events."""

    def __init__(self, model_path: str | Path | None = None) -> None:
        path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        with open(path, "rb") as f:
            saved = pickle.load(f)
        self._model = saved["model"]
        self._scaler = saved["scaler"]

    def score(self, log: NormalizedLog, window: list[NormalizedLog],
              rule_result=None, cve_paths: set[str] | None = None) -> float:
        """Return anomaly score in [0, 1]. Higher means more anomalous.

        IF's decision_function returns negative for anomalies.
        We invert and normalize to align with rule score convention.
        """
        vec = extract(log, window, rule_result, cve_paths).reshape(1, -1)
        X = self._scaler.transform(vec)
        raw = self._model.decision_function(X)[0]

        # Typical IF range ~[-0.5, 0.5]; clip before mapping to [0, 1]
        return float(1.0 - (np.clip(raw, -0.5, 0.5) + 0.5))

    def score_batch(self, vectors: np.ndarray) -> np.ndarray:
        """Score a batch of pre-extracted feature vectors.

        Args:
            vectors: shape (n, 17) feature matrix.

        Returns:
            numpy array shape (n,) with scores in [0, 1].
        """
        X = self._scaler.transform(vectors)
        raw = self._model.decision_function(X)
        return 1.0 - (np.clip(raw, -0.5, 0.5) + 0.5)
