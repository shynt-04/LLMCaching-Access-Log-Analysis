# eval/metrics.py
"""Evaluation metrics for detection system performance.

Includes binary classification metrics, AUC-ROC/PR, and per-type recall.
"""
import numpy as np


def precision(tp: int, fp: int) -> float:
    """TP / (TP + FP) — measures false alarm quality."""
    total = tp + fp
    return tp / total if total > 0 else 0.0


def recall(tp: int, fn: int) -> float:
    """TP / (TP + FN) — measures detection completeness (primary for security)."""
    total = tp + fn
    return tp / total if total > 0 else 0.0


def f1_score(prec: float, rec: float) -> float:
    """Harmonic mean of precision and recall."""
    total = prec + rec
    return 2 * (prec * rec) / total if total > 0 else 0.0


def false_positive_rate(fp: int, tn: int) -> float:
    """FP / (FP + TN) — false alarm rate."""
    total = fp + tn
    return fp / total if total > 0 else 0.0


def auc_roc(scores: list[float], ground_truth: list[bool]) -> float:
    """Compute Area Under ROC Curve from continuous scores and binary labels.

    Uses the trapezoidal rule over sorted thresholds.
    Falls back to 0.5 if degenerate input.
    """
    if not scores or not ground_truth:
        return 0.5

    try:
        from sklearn.metrics import roc_auc_score
        y_true = [1 if t else 0 for t in ground_truth]
        return float(roc_auc_score(y_true, scores))
    except (ImportError, ValueError):
        pass

    # Manual implementation as fallback
    paired = sorted(zip(scores, ground_truth), key=lambda x: -x[0])
    tp = fp = 0
    total_pos = sum(1 for t in ground_truth if t)
    total_neg = len(ground_truth) - total_pos
    if total_pos == 0 or total_neg == 0:
        return 0.5

    points = []
    prev_score = None
    for score, truth in paired:
        if truth:
            tp += 1
        else:
            fp += 1
        if score != prev_score:
            tpr = tp / total_pos
            fpr_val = fp / total_neg
            points.append((fpr_val, tpr))
            prev_score = score

    # Trapezoidal integration
    points.sort()
    auc = 0.0
    prev_fpr, prev_tpr = 0.0, 0.0
    for fpr_val, tpr in points:
        auc += (fpr_val - prev_fpr) * (tpr + prev_tpr) / 2
        prev_fpr, prev_tpr = fpr_val, tpr
    auc += (1.0 - prev_fpr) * (1.0 + prev_tpr) / 2

    return round(auc, 4)


def auc_pr(scores: list[float], ground_truth: list[bool]) -> float:
    """Compute Area Under Precision-Recall Curve."""
    if not scores or not ground_truth:
        return 0.0

    try:
        from sklearn.metrics import average_precision_score
        y_true = [1 if t else 0 for t in ground_truth]
        return float(average_precision_score(y_true, scores))
    except (ImportError, ValueError):
        pass

    # Manual fallback — step function approximation
    paired = sorted(zip(scores, ground_truth), key=lambda x: -x[0])
    tp = fp = 0
    total_pos = sum(1 for t in ground_truth if t)
    if total_pos == 0:
        return 0.0

    ap = 0.0
    for score, truth in paired:
        if truth:
            tp += 1
        else:
            fp += 1
        if truth:
            prec = tp / (tp + fp)
            ap += prec / total_pos

    return round(ap, 4)


def per_type_recall(
    predictions: list[bool],
    entries: list[dict],
) -> dict[str, float]:
    """Compute recall per attack type.

    Args:
        predictions: bool list — True if flagged.
        entries: list of dicts with 'label' and 'attack_type' keys.

    Returns:
        Dict mapping attack_type -> recall.
    """
    from collections import defaultdict
    type_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0})

    for pred, entry in zip(predictions, entries):
        if entry.get("label", 0) == 0:
            continue
        atype = entry.get("attack_type", "unknown")
        if pred:
            type_stats[atype]["tp"] += 1
        else:
            type_stats[atype]["fn"] += 1

    return {
        atype: round(s["tp"] / max(s["tp"] + s["fn"], 1), 4)
        for atype, s in type_stats.items()
    }


def evaluate(predictions: list[bool], ground_truth: list[bool]) -> dict:
    """Compute all metrics given predictions and ground truth.

    Args:
        predictions: list of bool — True if detector flagged as attack.
        ground_truth: list of bool — True if actually attack (from label).

    Returns:
        Dict with precision, recall, f1, false_positive_rate, counts.
    """
    tp = fp = tn = fn = 0
    for pred, truth in zip(predictions, ground_truth):
        if pred and truth:
            tp += 1
        elif pred and not truth:
            fp += 1
        elif not pred and truth:
            fn += 1
        else:
            tn += 1

    prec = precision(tp, fp)
    rec = recall(tp, fn)
    f1 = f1_score(prec, rec)
    fpr = false_positive_rate(fp, tn)

    return {
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "total": len(predictions),
    }


def evaluate_with_scores(
    predictions: list[bool],
    scores: list[float],
    ground_truth: list[bool],
    entries: list[dict] | None = None,
) -> dict:
    """Extended evaluation with AUC-ROC, AUC-PR, and per-type recall.

    Args:
        predictions: binary predictions.
        scores: continuous threat scores (for AUC computation).
        ground_truth: binary ground truth.
        entries: optional list of entry dicts for per-type recall.

    Returns:
        Dict with all metrics including AUC and per-type breakdown.
    """
    base = evaluate(predictions, ground_truth)
    base["auc_roc"] = auc_roc(scores, ground_truth)
    base["auc_pr"] = auc_pr(scores, ground_truth)

    if entries:
        base["per_type_recall"] = per_type_recall(predictions, entries)

    return base
