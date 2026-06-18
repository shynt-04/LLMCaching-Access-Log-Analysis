import pickle
import warnings

import numpy as np

from src.detection.ml.feature_extractor import build_content_text
from src.ingestion.schema import NormalizedLog

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")


class MLDetector:
    def __init__(self):
        with open("data/models/lgbm_content.pkl", "rb") as f:
            artifact = pickle.load(f)

        self._content_model = artifact["model"]
        self._vectorizer = artifact["vectorizer"]
        self._threshold = float(artifact.get("threshold", 0.5))

    def score(self, log: NormalizedLog) -> float:
        """Return the content-only attack probability for one normalized log."""
        text = build_content_text(log)
        x_content = self._vectorizer.transform([text])
        probs = self._content_model.predict_proba(x_content)[0]

        classes = getattr(self._content_model, "classes_", None)
        if classes is not None:
            classes = list(classes)
            if 1 in classes:
                content_score = float(probs[classes.index(1)])
            elif 0 in classes:
                content_score = float(1.0 - probs[classes.index(0)])
            else:
                content_score = float(np.max(probs))
        elif len(probs) == 2:
            content_score = float(probs[1])
        else:
            content_score = float(1.0 - probs[0])

        return content_score
