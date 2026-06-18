# src/detection/merger.py
from src.config import (
    ALERT_THRESHOLD,
    CONTENT_FLOOR_FACTOR,
    CONTENT_WEIGHT,
    RULE_WEIGHT,
)


def merge(
    rule_score: float,
    content_score: float,
) -> float:
    """Combine rule and content signals into one threat score.

    The current thesis pipeline combines only rule and content signals.
    """
    total_weight = max(CONTENT_WEIGHT + RULE_WEIGHT, 1e-9)
    weighted_avg = (
        CONTENT_WEIGHT * content_score
        + RULE_WEIGHT * rule_score
    ) / total_weight
    content_floor = content_score * CONTENT_FLOOR_FACTOR
    return min(max(weighted_avg, content_floor), 1.0)


def should_flag(score: float) -> bool:
    return score >= ALERT_THRESHOLD
