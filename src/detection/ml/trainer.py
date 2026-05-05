import pickle, json, random
import numpy as np
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from lightgbm import LGBMClassifier

from src.detection.ml.feature_extractor import build_content_text, extract_behavioral

CONTENT_MODEL_PATH  = Path("data/models/lgbm_content.pkl")
BEHAVIOR_MODEL_PATH = Path("data/models/lgbm_behavior.pkl")
TFIDF_PATH          = Path("data/models/tfidf_vectorizer.pkl")


def train_content_model(train_path: str = "data/synthetic/train.jsonl") -> None:
    """Train TF-IDF + LightGBM on URL/path/query content.

    Character-level n-grams (2,5) are key: they capture substrings like
    'UNION', 'OR 1=1', '../', '<script' without needing word tokenization —
    essential for URL-encoded payloads.
    """
    entries = [json.loads(l) for l in Path(train_path).read_text().splitlines()]

    texts  = [f"{e.get('path', '')} {e.get('query','')} {e.get('user_agent','')[:100]}"
              for e in entries]
    labels = [1 if e.get("label", 0) > 0 else 0 for e in entries]

    # char_wb: char n-grams with word boundaries — handles URL segments well
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(2, 5),       # expanded from (2,4) — captures longer attack patterns
        max_features=80_000,      # increased from 50K — more data supports it
        sublinear_tf=True,        # log(1+tf) dampens high-freq terms
        min_df=2,                 # ignore features appearing only once (noise)
        max_df=0.95,              # ignore features in >95% of docs (stopwords)
    )
    X = vectorizer.fit_transform(texts)

    model = LGBMClassifier(
        n_estimators=500,         # increased from 300 — more data now
        learning_rate=0.03,       # reduced — slower learning, better generalization
        num_leaves=63,
        max_depth=8,
        min_child_samples=20,     # prevents overfitting on rare payloads
        class_weight="balanced",  # handles label imbalance from synthetic gen
        subsample=0.8,            # row sampling — reduces overfitting
        colsample_bytree=0.8,     # column sampling
        reg_alpha=0.1,            # L1 regularization
        reg_lambda=1.0,           # L2 regularization
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X, labels)

    CONTENT_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONTENT_MODEL_PATH, "wb") as f:
        pickle.dump({"model": model, "vectorizer": vectorizer}, f)
    with open(TFIDF_PATH, "wb") as f:
        pickle.dump(vectorizer, f)
    print(f"Content model saved — {X.shape[0]} samples, {X.shape[1]} features")


def train_behavior_model(train_path: str = "data/synthetic/train.jsonl") -> None:
    """Train LightGBM on temporal/behavioral features.

    Uses simulated windows: for each attack entry, build a synthetic 5-min
    window by sampling nearby entries. For production, use real log windows.
    """
    entries = [json.loads(l) for l in Path(train_path).read_text().splitlines()]
    random.shuffle(entries)

    vectors, labels = [], []
    for i, e in enumerate(entries):
        # Simulate a 5-min window from nearby entries (±20 entries same IP)
        window_sample = [entries[j] for j in range(max(0, i-20), min(len(entries), i+20))
                         if entries[j].get("ip") == e.get("ip")][:10]
        rule_max = 0.8 if e.get("label", 0) > 0 else 0.1  # approximate for training

        # Build a mock NormalizedLog for behavioral extraction
        from src.ingestion.schema import NormalizedLog
        from datetime import datetime
        mock_log = NormalizedLog(
            timestamp=datetime.now(), source_ip=e.get("ip","0.0.0.0"),
            method=e.get("method","GET"), path=e.get("path","/"),
            status_code=e.get("status",200), source="apache",
            query_string=e.get("query"), user_agent=e.get("user_agent"),
        )

        beh = np.array([
            float(len(window_sample)),
            sum(1 for w in window_sample if w.get("status",200) >= 400) / max(len(window_sample),1),
            float(len({w.get("path") for w in window_sample})),
            float(sum(1 for w in window_sample if w.get("label",0) > 0)),
            1.0 if e.get("status",200) >= 400 else 0.0,
            1.0 if e.get("method","GET") == "POST" else 0.0,
            0.5,  # hour normalized — use actual timestamp in production
            rule_max,
        ], dtype=np.float32)

        vectors.append(beh)
        labels.append(min(e.get("label", 0), 1))  # binary: 0=normal, 1=any attack

    X = np.array(vectors)
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    model = LGBMClassifier(
        n_estimators=300, learning_rate=0.03,
        num_leaves=31,
        max_depth=6,
        min_child_samples=15,
        class_weight="balanced",
        subsample=0.8,
        reg_alpha=0.1,
        reg_lambda=1.0,
        random_state=42, n_jobs=-1,
    )
    model.fit(X, labels)

    with open(BEHAVIOR_MODEL_PATH, "wb") as f:
        pickle.dump({"model": model, "scaler": scaler}, f)
    print(f"Behavior model saved — {X.shape[0]} samples")