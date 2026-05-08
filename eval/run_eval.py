"""
Evaluation runner — measures detection system performance on labeled dataset.

Runs detection through configurations:
  1. Rule-based only
  2. ML-only (LightGBM)
  3. Full system (rule + ML + temporal)

Supports:
  - Validation and test set evaluation
  - Per-attack-type recall breakdown
  - AUC-ROC and AUC-PR metrics
  - Cross-type generalization test

Usage:
    python eval/run_eval.py
    python eval/run_eval.py --config rule_only
    python eval/run_eval.py --config ml_only
    python eval/run_eval.py --config full
    python eval/run_eval.py --all-configs
    python eval/run_eval.py --all-configs --dataset test
    python eval/run_eval.py --cross-type
"""
import sys
import os
import json
import argparse
import time
import warnings
from pathlib import Path
from collections import Counter

warnings.filterwarnings("ignore", category=UserWarning, message="X does not have valid feature names, but LGBMClassifier was fitted with feature names")

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from src.ingestion.normalizer import Normalizer
from src.detection.rule_based.detector import RuleDetector
from src.detection.ml.detector import MLDetector
from src.detection.temporal_buffer import TemporalBuffer
from src.detection.merger import merge, should_flag
from src.config import ALERT_THRESHOLD
from eval.metrics import evaluate, evaluate_with_scores


def load_labeled_data(
    data_path: str = "data/synthetic/validation.jsonl",
) -> tuple[list, list[bool], list[dict]]:
    """Load labeled synthetic data. Returns (logs, truth, raw_entries)."""
    normalizer = Normalizer()
    logs = []
    truth = []
    raw_entries = []

    if not Path(data_path).exists():
        print(f"  ⚠ {data_path} not found")
        return logs, truth, raw_entries

    with open(data_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)

            from datetime import datetime
            from src.ingestion.schema import NormalizedLog

            try:
                if "ip" in entry:
                    timestamp_str = entry.get("timestamp", "")
                    try:
                        ts = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
                    except ValueError:
                        ts = datetime.now()

                    parsed = NormalizedLog(
                        timestamp=ts,
                        source_ip=entry.get("ip", "0.0.0.0"),
                        method=entry.get("method", "GET").upper(),
                        path=entry.get("path", "/"),
                        query_string=entry.get("query", ""),
                        content=entry.get("content", ""),
                        status_code=int(entry.get("status", 200)),
                        response_size=int(entry.get("size", 0)),
                        user_agent=entry.get("user_agent", ""),
                        source="nginx",
                        raw_line=json.dumps(entry)
                    )
                    logs.append(parsed)
                    truth.append(entry.get("label", 0) > 0)
                    raw_entries.append(entry)
                else:
                    source = entry.get("source", "nginx")
                    parsed = normalizer.parse_line(entry["raw_line"], source=source)
                    if parsed is not None:
                        logs.append(parsed)
                        truth.append(False)
                        raw_entries.append(entry)
            except Exception:
                pass

    return logs, truth, raw_entries


def eval_rule_only(logs: list, truth: list[bool]) -> tuple[dict, list[float]]:
    """Evaluate rule-based detection only. Returns (metrics, scores)."""
    detector = RuleDetector()
    predictions = []
    scores = []

    for log in logs:
        result = detector.detect(log)
        scores.append(result.score)
        predictions.append(result.score >= ALERT_THRESHOLD)

    return evaluate(predictions, truth), scores


def eval_ml_only(logs: list, truth: list[bool]) -> tuple[dict, list[float]]:
    """Evaluate ML detection only (LightGBM). Returns (metrics, scores)."""
    ml_detector = MLDetector()
    predictions = []
    scores = []

    for i, log in enumerate(logs):
        window = [l for l in logs[max(0, i-20):i+1] if l.source_ip == log.source_ip]
        content_score, behavior_score = ml_detector.score(log, window, rule_max_score=0.0)
        merged = merge(0.0, content_score, behavior_score, 1.0)
        scores.append(merged)
        predictions.append(should_flag(merged))

    return evaluate(predictions, truth), scores


def eval_full(logs: list, truth: list[bool]) -> tuple[dict, list[float]]:
    """Evaluate full system: rule + ML + temporal buffer. Returns (metrics, scores)."""
    rule_detector = RuleDetector()
    ml_detector = MLDetector()
    buffer = TemporalBuffer()
    predictions = []
    scores = []

    for log in logs:
        rule_result = rule_detector.detect(log)
        log.rule_score = rule_result.score

        window = buffer.add(log)

        content_score, behavior_score = ml_detector.score(log, window, rule_result.score)

        temporal_mult = buffer.multiplier(log.source_ip)
        merged = merge(rule_result.score, content_score, behavior_score, temporal_mult)
        scores.append(merged)
        predictions.append(should_flag(merged))

    return evaluate(predictions, truth), scores


def print_results(config_name: str, results: dict, scores: list[float] = None,
                  truth: list[bool] = None, entries: list[dict] = None) -> None:
    """Pretty-print evaluation results with extended metrics."""
    print(f"\n{'='*55}")
    print(f"  Config: {config_name}")
    print(f"{'='*55}")
    print(f"  Precision:          {results['precision']:.4f}")
    print(f"  Recall:             {results['recall']:.4f}")
    print(f"  F1:                 {results['f1']:.4f}")
    print(f"  False Positive Rate:{results['false_positive_rate']:.4f}")
    print(f"  Confusion Matrix:   TP={results['tp']}  FP={results['fp']}  TN={results['tn']}  FN={results['fn']}")
    print(f"  Total Logs:         {results['total']}")

    # AUC metrics (if scores available)
    if scores and truth:
        from eval.metrics import auc_roc, auc_pr
        roc = auc_roc(scores, truth)
        pr = auc_pr(scores, truth)
        print(f"  AUC-ROC:            {roc:.4f}")
        print(f"  AUC-PR:             {pr:.4f}")

    # Per-type recall (if entries available)
    if entries:
        from eval.metrics import per_type_recall
        predictions = [should_flag(s) for s in scores] if scores else []
        if not predictions:
            predictions = [False] * len(entries)
        ptr = per_type_recall(predictions, entries)
        if ptr:
            print(f"\n  Per-Type Recall:")
            for atype, rec in sorted(ptr.items()):
                flag = "✓" if rec >= 0.75 else "✗"
                print(f"    {atype:>18s}: {rec:.4f}  {flag}")

    target_met = results['precision'] >= 0.70 and results['recall'] >= 0.80
    print(f"\n  Target (P>=0.70, R>=0.80): {'✓ MET' if target_met else '✗ NOT MET'}")


def main():
    parser = argparse.ArgumentParser(description="Run detection evaluation")
    parser.add_argument(
        "--config",
        choices=["rule_only", "ml_only", "full"],
        default="full",
        help="Detection configuration to evaluate",
    )
    parser.add_argument("--all-configs", action="store_true", help="Run all configs")
    parser.add_argument(
        "--dataset",
        choices=["validation", "test"],
        default="validation",
        help="Which dataset split to evaluate on",
    )
    parser.add_argument("--cross-type", action="store_true",
                        help="Run cross-type generalization test (leave-one-type-out)")
    args = parser.parse_args()

    data_path = f"data/synthetic/{args.dataset}.jsonl"
    print(f"Loading synthetic {args.dataset} dataset from {data_path}...")
    logs, truth, raw_entries = load_labeled_data(data_path)

    if not logs:
        print("No validation data found! Generating fallback data loaders...")
        n_path = "data/labeled/normal_traffic.jsonl"
        a_path = "data/labeled/attack_traffic.jsonl"
        norm = Normalizer()

        for path, is_att in [(n_path, False), (a_path, True)]:
            if Path(path).exists():
                with open(path) as f:
                    for line in f:
                        if not line.strip(): continue
                        e = json.loads(line)
                        p = norm.parse_line(e["raw_line"], source=e.get("source", "nginx"))
                        if p:
                            logs.append(p)
                            truth.append(is_att)
                            raw_entries.append(e)

    n_normal = sum(1 for t in truth if not t)
    n_attack = sum(1 for t in truth if t)
    print(f"  Normal: {n_normal}  Attack: {n_attack}  Total: {len(logs)}")

    if n_attack > 0 and raw_entries:
        type_counts = Counter(e.get("attack_type", "unknown") for e in raw_entries if e.get("label", 0) > 0)
        print(f"  Attack types: {dict(type_counts)}")

    if len(logs) == 0:
        print("Dataset is completely empty! Please ensure data exists.")
        return

    configs = ["rule_only", "ml_only", "full"] if args.all_configs else [args.config]

    evaluators = {
        "rule_only": ("Rule-Based Only", eval_rule_only),
        "ml_only": ("ML Only (LightGBM)", eval_ml_only),
        "full": ("Full System (Rule + ML + Temporal)", eval_full),
    }

    for config in configs:
        name, eval_fn = evaluators[config]
        start = time.time()
        results, scores = eval_fn(logs, truth)
        elapsed = (time.time() - start) * 1000
        results["latency_ms"] = round(elapsed, 1)
        print_results(name, results, scores=scores, truth=truth, entries=raw_entries)
        print(f"  Total time: {elapsed:.1f}ms")

    # Cross-type generalization test
    if args.cross_type:
        print(f"\n{'='*55}")
        print(f"  CROSS-TYPE GENERALIZATION TEST")
        print(f"{'='*55}")
        print(f"  (Leave-one-type-out evaluation)")
        print(f"  Note: Requires retraining for each held-out type.")
        print(f"  This is a reporting placeholder — full implementation")
        print(f"  requires re-running trainer.py with filtered data.")

        attack_types = set(e.get("attack_type") for e in raw_entries if e.get("label", 0) > 0)
        for held_out in sorted(attack_types):
            # Filter: keep all normal + all attacks EXCEPT held_out
            test_indices = [
                i for i, e in enumerate(raw_entries)
                if e.get("attack_type") == held_out or e.get("label", 0) == 0
            ]
            test_subset = [raw_entries[i] for i in test_indices]
            n_held = sum(1 for e in test_subset if e.get("attack_type") == held_out)
            print(f"\n  Hold out '{held_out}': {n_held} attack entries in test")


if __name__ == "__main__":
    main()
