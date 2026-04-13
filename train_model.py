"""
Train Isolation Forest model on normal traffic data.

Usage:
    python train_model.py
    python train_model.py --data data/labeled/normal_traffic.jsonl
"""
import sys
import os
import json
import argparse
import numpy as np

# Add code/ to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ingestion.normalizer import Normalizer
from src.detection.feature_extractor import extract
from src.detection.ml.trainer import train


def load_normal_logs(filepath: str) -> list:
    """Load normal traffic from labeled JSONL, parse into NormalizedLog objects."""
    normalizer = Normalizer()
    logs = []

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if entry.get("is_attack", False):
                continue  # skip attack logs — IF trains on normal only

            raw_line = entry["raw_line"]
            source = entry.get("source", "nginx")
            parsed = normalizer.parse_line(raw_line, source=source)
            if parsed is not None:
                logs.append(parsed)

    return logs


def load_cve_paths(filepath: str = "data/cve_lookup.json") -> set[str]:
    """Load CVE indicator paths from lookup file."""
    import json as _json
    from pathlib import Path
    cve_raw = _json.loads(Path(filepath).read_text())
    return {
        p for entry in cve_raw.values()
        for p in entry.get("indicator_paths", entry.get("paths", []))
    }


def main():
    parser = argparse.ArgumentParser(description="Train Isolation Forest model")
    parser.add_argument(
        "--data",
        default="data/labeled/normal_traffic.jsonl",
        help="Path to normal traffic JSONL file",
    )
    args = parser.parse_args()

    print(f"Loading normal logs from: {args.data}")
    logs = load_normal_logs(args.data)
    print(f"  Parsed: {len(logs)} normal log entries")

    if len(logs) == 0:
        print("ERROR: No normal logs parsed. Check data file.")
        sys.exit(1)

    # Load CVE paths for feature extraction
    cve_paths = load_cve_paths()
    print(f"  CVE paths loaded: {len(cve_paths)}")

    # Extract 17-dim features — rule_result=None during training (no rules applied)
    # This is correct: IF learns structural + temporal patterns of normal traffic.
    # Rule-derived features [5-8] will be zero during training, but active during inference
    # where rule_result is provided. This lets IF detect anomalies that rules miss.
    print("Extracting features (17-dim)...")
    vectors = np.array(
        [extract(log, [log], rule_result=None, cve_paths=cve_paths) for log in logs],
        dtype=np.float32,
    )
    print(f"  Feature matrix shape: {vectors.shape}")

    print("Training Isolation Forest...")
    stats = train(vectors)
    print(f"  Training complete!")
    print(f"  Samples: {stats['n_samples']}")
    print(f"  Features: {stats['n_features']}")
    print(f"  Contamination: {stats['contamination']}")
    print(f"  Model saved to: {stats['model_path']}")


if __name__ == "__main__":
    main()
