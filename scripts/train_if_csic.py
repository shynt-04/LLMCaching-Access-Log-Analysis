import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
import pickle
from pathlib import Path
import csv

def train():
    csv_path = Path("data/csic2010/csic_database.csv")
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        
    normal_rows = [r for r in rows if r.get("", "").strip() == "Normal"]
    print(f"Training on {len(normal_rows)} CSIC normal requests")
    
    # Use text representation
    X_text = []
    for r in normal_rows:
        url = r.get("URL", "")
        content = r.get("content", "")
        ua = r.get("User-Agent", "")
        X_text.append(f"{url} {content} {ua[:100]}")
        
    # Use TF-IDF with limited features to avoid curse of dimensionality
    vectorizer = TfidfVectorizer(max_features=20, ngram_range=(1, 2))
    
    model = IsolationForest(n_estimators=100, contamination=0.12, random_state=42, n_jobs=-1)
    
    pipeline = Pipeline([
        ('vectorizer', vectorizer),
        ('iforest', model)
    ])
    
    pipeline.fit(X_text)
    
    out_path = Path("data/models/isolation_forest.pkl")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        pickle.dump(pipeline, f)
    print("IF pipeline (TF-IDF + IF) trained on CSIC normal data.")

if __name__ == "__main__":
    train()
