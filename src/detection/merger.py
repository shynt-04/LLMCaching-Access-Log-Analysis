# src/detection/merger.py
from src.config import CONTENT_WEIGHT, BEHAVIOR_WEIGHT, RULE_WEIGHT, CONTENT_FLOOR_FACTOR, TEMPORAL_CAP, ALERT_THRESHOLD

def merge(
    rule_score: float,
    content_score: float,
    behavior_score: float,
    temporal_mult: float,
) -> float:
    """Combine three detection signals into a single threat score.

    Uses a MAX-based formula: the final score is the higher of:
      1. content_score * CONTENT_FLOOR_FACTOR  — ensures a confident content
         model alone can trigger an alert without being diluted by zero
         behavior/rule scores.
      2. weighted average of all three signals — benefits from complementary
         signals when rule/behavior also fire.

    Temporal multiplier rewards clusters of suspicious events in same window.
    """
    weighted_avg = (CONTENT_WEIGHT  * content_score +
                    BEHAVIOR_WEIGHT * behavior_score +
                    RULE_WEIGHT     * rule_score)
    content_floor = content_score * CONTENT_FLOOR_FACTOR
    base = max(weighted_avg, content_floor)
    return min(base * temporal_mult, 1.0)

def should_flag(score: float) -> bool:
    return score >= ALERT_THRESHOLD