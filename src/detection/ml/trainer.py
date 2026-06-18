"""Content-only LightGBM trainer.

Behavior-model training was removed from the main thesis pipeline. Use
scripts/import_webattack_cvss.py first, then run this module or
scripts/train_content_webattack.py to produce data/models/lgbm_content.pkl.
"""
from __future__ import annotations

import json
import pickle
from pathlib import Path

import numpy as np
from lightgbm import LGBMClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split


CONTENT_MODEL_PATH = Path("data/models/lgbm_content.pkl")


def _read_jsonl(path: str | Path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def _content_text(entry: dict) -> str:
    return " ".join([
        str(entry.get("method") or ""),
        str(entry.get("path") or ""),
        str(entry.get("query") or entry.get("query_string") or ""),
        str(entry.get("content") or ""),
        str(entry.get("user_agent") or "")[:160],
        str(entry.get("status") or entry.get("status_code") or ""),
    ])


def _best_threshold(y_true: np.ndarray, scores: np.ndarray) -> tuple[float, float]:
    best_t, best_f1 = 0.5, -1.0
    for threshold in np.linspace(0.2, 0.9, 71):
        preds = (scores >= threshold).astype(int)
        f1 = f1_score(y_true, preds, zero_division=0)
        if f1 > best_f1:
            best_t, best_f1 = float(threshold), float(f1)
    return best_t, best_f1


def train_content_model(train_path: str = "data/webattack_cvss/train.jsonl") -> None:
    entries = _read_jsonl(train_path)
    texts = [_content_text(entry) for entry in entries]
    labels = np.array([1 if int(entry.get("label", 0)) > 0 else 0 for entry in entries])

    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(2, 5),
        max_features=50000,
        sublinear_tf=True,
        min_df=2,
    )
    x_all = vectorizer.fit_transform(texts)
    x_train, x_val, y_train, y_val = train_test_split(
        x_all,
        labels,
        test_size=0.15,
        random_state=42,
        stratify=labels,
    )

    model = LGBMClassifier(
        objective="binary",
        n_estimators=500,
        learning_rate=0.05,
        num_leaves=63,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(x_train, y_train)

    scores = model.predict_proba(x_val)[:, 1]
    threshold, val_f1 = _best_threshold(y_val, scores)

    CONTENT_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with CONTENT_MODEL_PATH.open("wb") as f:
        pickle.dump({
            "model": model,
            "vectorizer": vectorizer,
            "threshold": threshold,
            "taxonomy": ["normal", "attack"],
            "source_dataset": "chYassine/WebAttack-CVSSMetrics",
        }, f)

    print(
        f"Content model saved to {CONTENT_MODEL_PATH} "
        f"({x_all.shape[0]} samples, {x_all.shape[1]} features, "
        f"threshold={threshold:.2f}, val_f1={val_f1:.4f})"
    )


if __name__ == "__main__":
    train_content_model()
