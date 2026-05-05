# src/detection/merger.py
from src.config import CONTENT_WEIGHT, BEHAVIOR_WEIGHT, RULE_WEIGHT, TEMPORAL_CAP, ALERT_THRESHOLD

def merge(
    rule_score: float,
    content_score: float,
    behavior_score: float,
    temporal_mult: float,
) -> float:
    """Combine three detection signals into a single threat score.

    Weight rationale:
    - content (0.5): highest — TF-IDF+LightGBM is most accurate for payload detection
    - behavior (0.3): medium — captures rate/temporal attacks content misses
    - rule (0.2): lowest — rules are subsumed by ML but kept for CVE/known patterns
    Temporal multiplier rewards clusters of suspicious events in same window.
    """
    base = (CONTENT_WEIGHT  * content_score +
            BEHAVIOR_WEIGHT * behavior_score +
            RULE_WEIGHT     * rule_score)
    return min(base * temporal_mult, 1.0)

def should_flag(score: float) -> bool:
    return score >= ALERT_THRESHOLD