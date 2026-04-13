"""
Evaluation runner — measures detection system performance on labeled dataset.

Runs detection through three configurations:
  1. Rule-based only
  2. ML-only
  3. Full system (rule + ML + temporal)

Usage:
    python eval/run_eval.py
    python eval/run_eval.py --config rule_only
    python eval/run_eval.py --config ml_only
    python eval/run_eval.py --config full
    python eval/run_eval.py --all-configs
"""
import sys
import os
import json
import argparse
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from pathlib import Path
from src.ingestion.normalizer import Normalizer
from src.detection.rule_based.detector import RuleDetector
from src.detection.feature_extractor import extract
from src.detection.ml.detector import MLDetector
from src.detection.temporal_buffer import TemporalBuffer
from src.detection.merger import merge, should_flag
from src.config import ALERT_THRESHOLD
from eval.metrics import evaluate


def load_cve_paths(filepath: str = "data/cve_lookup.json") -> set[str]:
    """Load CVE indicator paths from lookup file."""
    cve_raw = json.loads(Path(filepath).read_text())
    return {
        p for entry in cve_raw.values()
        for p in entry.get("indicator_paths", entry.get("paths", []))
    }


def load_labeled_data(
    normal_path: str = "data/labeled/normal_traffic.jsonl",
    attack_path: str = "data/labeled/attack_traffic.jsonl",
) -> tuple[list, list[bool]]:
    """Load labeled data and return (parsed_logs, ground_truth)."""
    normalizer = Normalizer()
    logs = []
    truth = []

    for filepath, is_attack in [(normal_path, False), (attack_path, True)]:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                source = entry.get("source", "nginx")
                parsed = normalizer.parse_line(entry["raw_line"], source=source)
                if parsed is not None:
                    logs.append(parsed)
                    truth.append(is_attack)

    return logs, truth


def eval_rule_only(logs: list, truth: list[bool]) -> dict:
    """Evaluate rule-based detection only."""
    detector = RuleDetector()
    predictions = []

    for log in logs:
        result = detector.detect(log)
        predictions.append(result.score >= ALERT_THRESHOLD)

    return evaluate(predictions, truth)


def eval_ml_only(logs: list, truth: list[bool]) -> dict:
    """Evaluate ML detection only."""
    ml_detector = MLDetector()
    rule_detector = RuleDetector()
    cve_paths = load_cve_paths()
    predictions = []

    for log in logs:
        rule_result = rule_detector.detect(log)
        ml_score = ml_detector.score(log, [log], rule_result, cve_paths)
        predictions.append(ml_score >= ALERT_THRESHOLD)

    return evaluate(predictions, truth)


def eval_full(logs: list, truth: list[bool]) -> dict:
    """Evaluate full system: rule + ML + temporal buffer."""
    rule_detector = RuleDetector()
    ml_detector = MLDetector()
    buffer = TemporalBuffer()
    cve_paths = load_cve_paths()
    predictions = []

    for log in logs:
        # Rule-based scoring
        rule_result = rule_detector.detect(log)
        log.rule_score = rule_result.score

        # Add to temporal buffer
        window = buffer.add(log)

        # ML scoring with rule context
        ml_score = ml_detector.score(log, window, rule_result, cve_paths)

        # Temporal multiplier
        temporal_mult = buffer.multiplier(log.source_ip)

        # Merge scores
        merged = merge(rule_result.score, ml_score, temporal_mult)
        predictions.append(should_flag(merged))

    return evaluate(predictions, truth)


def print_results(config_name: str, results: dict) -> None:
    """Pretty-print evaluation results."""
    print(f"\n{'='*50}")
    print(f"  Config: {config_name}")
    print(f"{'='*50}")
    print(f"  Precision:          {results['precision']:.4f}")
    print(f"  Recall:             {results['recall']:.4f}")
    print(f"  F1:                 {results['f1']:.4f}")
    print(f"  False Positive Rate:{results['false_positive_rate']:.4f}")
    print(f"  TP={results['tp']}  FP={results['fp']}  "
          f"TN={results['tn']}  FN={results['fn']}  Total={results['total']}")
    target_met = results['precision'] >= 0.70 and results['recall'] >= 0.80
    print(f"  Target (P≥0.70, R≥0.80): {'✓ MET' if target_met else 'NOT MET'}")


def main():
    parser = argparse.ArgumentParser(description="Run detection evaluation")
    parser.add_argument(
        "--config",
        choices=["rule_only", "ml_only", "full"],
        default="full",
        help="Detection configuration to evaluate",
    )
    parser.add_argument("--all-configs", action="store_true", help="Run all configs")
    args = parser.parse_args()

    print("Loading labeled dataset...")
    logs, truth = load_labeled_data()
    n_normal = sum(1 for t in truth if not t)
    n_attack = sum(1 for t in truth if t)
    print(f"  Normal: {n_normal}  Attack: {n_attack}  Total: {len(logs)}")

    configs = ["rule_only", "ml_only", "full"] if args.all_configs else [args.config]

    evaluators = {
        "rule_only": ("Rule-Based Only", eval_rule_only),
        "ml_only": ("ML Only (Isolation Forest)", eval_ml_only),
        "full": ("Full System (Rule + ML + Temporal)", eval_full),
    }

    for config in configs:
        name, eval_fn = evaluators[config]
        start = time.time()
        results = eval_fn(logs, truth)
        elapsed = (time.time() - start) * 1000
        results["latency_ms"] = round(elapsed, 1)
        print_results(name, results)
        print(f"  Total time: {elapsed:.1f}ms")


if __name__ == "__main__":
    main()
