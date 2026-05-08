"""
Phase 2 ML Model Evaluation — LightGBM on synthetic dataset.

Evaluates:
1. Content model (TF-IDF + LightGBM) on test set
2. Behavior model on test set
3. Combined pipeline (rule + content + behavior) on test set
4. Per-attack-type breakdown
5. Comparison with Isolation Forest baseline
"""
import json
import pickle
import warnings
import sys
import os
import numpy as np
from pathlib import Path
from collections import Counter
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_score, recall_score, f1_score, accuracy_score
)
import matplotlib.pyplot as plt
import seaborn as sns

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from src.detection.ml.detector import MLDetector
from src.detection.rule_based.detector import RuleDetector
from src.detection.merger import merge, should_flag
from src.ingestion.schema import NormalizedLog
from datetime import datetime


def load_test_set(path: str = "data/synthetic/test.jsonl") -> list[dict]:
    """Load test entries from JSONL."""
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def entry_to_log(e: dict) -> NormalizedLog:
    """Convert a synthetic entry dict to NormalizedLog for pipeline testing."""
    return NormalizedLog(
        timestamp=datetime.now(),
        source_ip=e.get("ip", "0.0.0.0"),
        method=e.get("method", "GET"),
        path=e.get("path", "/"),
        status_code=e.get("status", 200),
        source="synthetic",
        query_string=e.get("query", "") or None,
        content=e.get("content", "") or None,
        user_agent=e.get("user_agent", ""),
    )


def evaluate_content_model(entries: list[dict]) -> dict:
    """Evaluate the content model (TF-IDF + LightGBM) on test data."""
    with open("data/models/lgbm_content.pkl", "rb") as f:
        c = pickle.load(f)

    model = c["model"]
    vectorizer = c["vectorizer"]

    texts = [
        f"{e.get('path', '')} {e.get('query', '')} {e.get('content', '')} {e.get('user_agent', '')[:100]}"
        for e in entries
    ]
    true_labels = [1 if e.get("label", 0) > 0 else 0 for e in entries]

    X = vectorizer.transform(texts)
    pred_probs = model.predict_proba(X)
    # Binary: P(attack) = 1 - P(normal)
    pred_scores = 1.0 - pred_probs[:, 0]
    pred_labels = (pred_scores >= 0.5).astype(int)

    return {
        "true": true_labels,
        "pred": pred_labels.tolist(),
        "scores": pred_scores.tolist(),
    }


def evaluate_full_pipeline(entries: list[dict]) -> dict:
    """Evaluate the full detection pipeline (rules + content + behavior)."""
    ml = MLDetector()
    rules = RuleDetector()

    true_labels = []
    pred_labels = []
    merged_scores = []

    for e in entries:
        log = entry_to_log(e)
        true_label = 1 if e.get("label", 0) > 0 else 0
        true_labels.append(true_label)

        # Rule detection
        r = rules.detect(log)
        log.rule_score = r.max_score

        # ML detection
        cs, bs = ml.score(log, [log], r.max_score)

        # Merge
        m = merge(r.max_score, cs, bs, 1.0)
        merged_scores.append(m)
        pred_labels.append(1 if should_flag(m) else 0)

    return {
        "true": true_labels,
        "pred": pred_labels,
        "scores": merged_scores,
    }


def print_metrics(name: str, true: list, pred: list, attack_types: list[str] = None):
    """Print comprehensive metrics for a model."""
    p = precision_score(true, pred, zero_division=0)
    r = recall_score(true, pred, zero_division=0)
    f1 = f1_score(true, pred, zero_division=0)
    acc = accuracy_score(true, pred)

    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}")
    print(f"  Accuracy:  {acc:.4f}")
    print(f"  Precision: {p:.4f}")
    print(f"  Recall:    {r:.4f}")
    print(f"  F1 Score:  {f1:.4f}")

    # Confusion matrix
    cm = confusion_matrix(true, pred)
    print(f"\n  Confusion Matrix:")
    print(f"                  Predicted")
    print(f"                  Normal  Attack")
    if cm.shape == (2, 2):
        print(f"  Actual Normal   {cm[0][0]:>6d}  {cm[0][1]:>6d}")
        print(f"  Actual Attack   {cm[1][0]:>6d}  {cm[1][1]:>6d}")

    # Per-attack-type breakdown
    if attack_types:
        type_true = {}
        type_pred = {}
        for t, p_val, atype in zip(true, pred, attack_types):
            if t == 1:  # only for actual attacks
                if atype not in type_true:
                    type_true[atype] = []
                    type_pred[atype] = []
                type_true[atype].append(1)
                type_pred[atype].append(p_val)

        print(f"\n  Per-Attack-Type Recall:")
        for atype in sorted(type_true.keys()):
            t_arr = type_true[atype]
            p_arr = type_pred[atype]
            recall = sum(p_arr) / max(len(t_arr), 1)
            print(f"    {atype:>18s}: {recall:.3f} ({sum(p_arr)}/{len(t_arr)})")

    return {"precision": p, "recall": r, "f1": f1, "accuracy": acc}


def evaluate_isolation_forest(entries: list[dict]) -> dict | None:
    """Evaluate Isolation Forest baseline if model exists."""
    if_path = Path("data/models/isolation_forest.pkl")
    if not if_path.exists():
        return None

    with open(if_path, "rb") as f:
        if_model = pickle.load(f)

    # IF expects the old 17-dim feature vector — we can't use it directly
    # with the new TF-IDF features. Skip if incompatible.
    print("\n  [NOTE] Isolation Forest baseline exists but uses different")
    print("  feature space (17-dim vs TF-IDF). Skipping direct comparison.")
    print("  Ablation will be done in Phase 4 with matched features.")
    return None


def main():
    print("="*60)
    print("  PHASE 2: ML MODEL EVALUATION")
    print("="*60)

    # Load test data
    test = load_test_set()
    attack_types = [e.get("attack_type", "normal") for e in test]
    print(f"\n  Test set: {len(test)} entries")
    type_dist = Counter(e.get("attack_type", "normal") for e in test)
    for atype, count in sorted(type_dist.items()):
        print(f"    {atype:>18s}: {count:>4d}")

    # 1. Content model evaluation
    print("\n  Evaluating content model (TF-IDF + LightGBM)...")
    content_result = evaluate_content_model(test)
    content_metrics = print_metrics(
        "Content Model (TF-IDF + LightGBM)",
        content_result["true"], content_result["pred"],
        attack_types=attack_types,
    )

    # 2. Full pipeline evaluation
    print("\n  Evaluating full pipeline (Rules + Content + Behavior)...")
    pipeline_result = evaluate_full_pipeline(test)
    pipeline_metrics = print_metrics(
        "Full Pipeline (Rules + Content + Behavior)",
        pipeline_result["true"], pipeline_result["pred"],
        attack_types=attack_types,
    )

    # 3. Isolation Forest baseline
    evaluate_isolation_forest(test)

    # 4. Summary comparison
    print(f"\n{'='*60}")
    print(f"  SUMMARY COMPARISON")
    print(f"{'='*60}")
    print(f"  {'Model':<35s} {'Prec':>6s} {'Recall':>7s} {'F1':>6s} {'Acc':>6s}")
    print(f"  {'-'*35} {'-'*6} {'-'*7} {'-'*6} {'-'*6}")
    print(f"  {'Content (TF-IDF+LightGBM)':<35s} {content_metrics['precision']:>6.3f} {content_metrics['recall']:>7.3f} {content_metrics['f1']:>6.3f} {content_metrics['accuracy']:>6.3f}")
    print(f"  {'Full Pipeline (Rule+ML)':<35s} {pipeline_metrics['precision']:>6.3f} {pipeline_metrics['recall']:>7.3f} {pipeline_metrics['f1']:>6.3f} {pipeline_metrics['accuracy']:>6.3f}")

    # Target check
    print(f"\n  Target: Precision >= 0.85, Recall >= 0.90")
    prec_ok = content_metrics["precision"] >= 0.85
    rec_ok = content_metrics["recall"] >= 0.90
    print(f"  Content Precision {'>=' if prec_ok else '<'} 0.85: {'PASS' if prec_ok else 'FAIL'}")
    print(f"  Content Recall    {'>=' if rec_ok else '<'} 0.90: {'PASS' if rec_ok else 'FAIL'}")

    print(f"\n{'='*60}")

    # --- Plotting ---
    output_dir = Path("benchmark/results")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Plot Confusion Matrices
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    
    cm_content = confusion_matrix(content_result["true"], content_result["pred"])
    sns.heatmap(cm_content, annot=True, fmt='d', cmap='Blues', ax=axes[0], 
                xticklabels=['Normal', 'Attack'], yticklabels=['Normal', 'Attack'])
    axes[0].set_title('Confusion Matrix: Content Model')
    axes[0].set_xlabel('Predicted')
    axes[0].set_ylabel('Actual')
    
    cm_pipeline = confusion_matrix(pipeline_result["true"], pipeline_result["pred"])
    sns.heatmap(cm_pipeline, annot=True, fmt='d', cmap='Blues', ax=axes[1],
                xticklabels=['Normal', 'Attack'], yticklabels=['Normal', 'Attack'])
    axes[1].set_title('Confusion Matrix: Full Pipeline')
    axes[1].set_xlabel('Predicted')
    axes[1].set_ylabel('Actual')
    
    plt.tight_layout()
    cm_path = output_dir / "confusion_matrices.png"
    plt.savefig(cm_path)
    print(f"  [OK] Saved confusion matrix plot to {cm_path}")
    
    # 2. Plot Metrics Comparison
    metrics_names = ['Precision', 'Recall', 'F1 Score', 'Accuracy']
    content_vals = [content_metrics['precision'], content_metrics['recall'], 
                    content_metrics['f1'], content_metrics['accuracy']]
    pipeline_vals = [pipeline_metrics['precision'], pipeline_metrics['recall'], 
                     pipeline_metrics['f1'], pipeline_metrics['accuracy']]
    
    x = np.arange(len(metrics_names))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(10, 6))
    rects1 = ax.bar(x - width/2, content_vals, width, label='Content Model')
    rects2 = ax.bar(x + width/2, pipeline_vals, width, label='Full Pipeline')
    
    ax.set_ylabel('Scores')
    ax.set_title('Performance Metrics Comparison')
    ax.set_xticks(x)
    ax.set_xticklabels(metrics_names)
    ax.legend()
    ax.set_ylim([0, 1.1])
    
    # Add values on top of bars
    for rects in [rects1, rects2]:
        for rect in rects:
            height = rect.get_height()
            ax.annotate(f'{height:.3f}',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom')
                        
    plt.tight_layout()
    metrics_path = output_dir / "metrics_comparison.png"
    plt.savefig(metrics_path)
    print(f"  [OK] Saved metrics comparison plot to {metrics_path}")


if __name__ == "__main__":
    main()
