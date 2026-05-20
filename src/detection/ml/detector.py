import pickle
import numpy as np
import warnings
from scipy.sparse import hstack

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

from src.ingestion.schema import NormalizedLog
from src.detection.ml.feature_extractor import build_content_text, extract_behavioral

class MLDetector:
    def __init__(self):
        with open("data/models/lgbm_content.pkl",  "rb") as f:
            c = pickle.load(f)
        with open("data/models/lgbm_behavior.pkl", "rb") as f:
            b = pickle.load(f)

        self._content_model  = c["model"]
        self._vectorizer     = c["vectorizer"]
        self._behavior_model = b["model"]
        self._behavior_scaler = b["scaler"]

    def score(
        self,
        log: NormalizedLog,
        window: list[NormalizedLog],
        rule_max_score: float,
    ) -> tuple[float, float]:
        """Return (content_score, behavior_score), both in [0, 1].

        Content score: probability of attack from URL/path/query text.
        Behavior score: probability of attack from temporal/rate patterns.
        Scores are combined in merger.py with configurable weights.
        """
        # Content score — TF-IDF + LightGBM multiclass
        text = build_content_text(log)
        X_content = self._vectorizer.transform([text])
        # predict_proba returns P(class) for each class; sum non-zero classes
        probs = self._content_model.predict_proba(X_content)[0]
        content_score = float(1.0 - probs[0])  # P(not normal)

        # Behavior score — tabular LightGBM binary
        beh = extract_behavioral(log, window, rule_max_score).reshape(1, -1)
        beh_scaled = self._behavior_scaler.transform(beh)
        behavior_score = float(
            self._behavior_model.predict_proba(beh_scaled)[0][1]  # P(attack)
        )

        return content_score, behavior_score
