# src/detection/merger.py
"""Score merger — combines rule-based and ML scores with temporal amplification.

ML gets higher weight (0.6) because it generalizes to attack variants
that rules miss. Temporal multiplier rewards clusters of suspicious events.
"""
from src.config import RULE_WEIGHT, ML_WEIGHT, TEMPORAL_CAP, ALERT_THRESHOLD


def merge(rule: float, ml: float, temporal_mult: float) -> float:
    """Weighted combination of rule and ML scores with temporal amplification.

    Args:
        rule: Rule-based score in [0, 1].
        ml: ML anomaly score in [0, 1].
        temporal_mult: Temporal multiplier in [1.0, TEMPORAL_CAP].

    Returns:
        Merged score in [0, 1].
    """
    base = RULE_WEIGHT * rule + ML_WEIGHT * ml
    return min(base * temporal_mult, 1.0)


def should_flag(score: float) -> bool:
    """Check if merged score exceeds the alert threshold."""
    return score >= ALERT_THRESHOLD
