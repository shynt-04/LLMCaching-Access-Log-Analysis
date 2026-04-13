# eval/metrics.py
"""Evaluation metrics for detection system performance."""


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
