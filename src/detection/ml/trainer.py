# src/detection/ml/trainer.py
"""Train Isolation Forest on normal-traffic feature vectors.

The model learns the distribution of benign log behavior. Events that
deviate significantly from this distribution receive high anomaly scores.
"""
import pickle
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from src.config import IF_CONTAMINATION, IF_N_ESTIMATORS, RANDOM_STATE

MODEL_DIR = Path("data/models")
MODEL_PATH = MODEL_DIR / "isolation_forest.pkl"


def train(normal_vectors: np.ndarray, model_path: Path | None = None) -> dict:
    """Fit IF on normal-traffic vectors only, then persist to disk.

    Args:
        normal_vectors: shape (n, 17) — benign events from labeled dataset.
        model_path: Optional override for output path.

    Returns:
        dict with training stats.
    """
    save_path = model_path or MODEL_PATH

    scaler = StandardScaler()
    X = scaler.fit_transform(normal_vectors)

    model = IsolationForest(
        n_estimators=IF_N_ESTIMATORS,
        contamination=IF_CONTAMINATION,
        random_state=RANDOM_STATE,
    )
    model.fit(X)

    save_path.parent.mkdir(parents=True, exist_ok=True)
    with open(save_path, "wb") as f:
        pickle.dump({"model": model, "scaler": scaler}, f)

    return {
        "n_samples": len(normal_vectors),
        "n_features": normal_vectors.shape[1],
        "model_path": str(save_path),
        "contamination": IF_CONTAMINATION,
        "n_estimators": IF_N_ESTIMATORS,
    }
