import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from src.ingestion.schema import NormalizedLog


def build_content_text(log: NormalizedLog) -> str:
    """Construct the text representation fed to TF-IDF.

    Concatenates path + query + user_agent — all sources where
    attack payloads can hide. Truncate UA to 100 chars to limit noise.
    """
    parts = [log.path or ""]
    if log.query_string:
        parts.append(log.query_string)
    if log.content:
        parts.append(log.content)
    if log.user_agent:
        parts.append(log.user_agent[:100])
    return " ".join(parts)


# Behavioral feature index map — used by behavior model only
# [0] req_per_ip_5min   [1] error_rate_5min   [2] unique_paths_5min
# [3] rule_hits_5min    [4] status_4xx        [5] method_is_post
# [6] hour_of_day       [7] rule_max_score

def extract_behavioral(
    log: NormalizedLog,
    window: list[NormalizedLog],
    rule_max_score: float,
) -> np.ndarray:
    """Extract behavioral (temporal + context) features for the behavior model.

    Deliberately excludes URL content — that is handled by TF-IDF.
    These features capture rate-based and behavioral anomalies that
    content analysis misses (slow scan, off-hours access, etc.).
    """
    n = max(len(window), 1)
    errors = sum(1 for e in window if e.status_code >= 400)
    rule_hits = sum(1 for e in window if e.rule_score > 0.0)

    return np.array([
        float(len(window)),                         # req_per_ip_5min
        errors / n,                                 # error_rate_5min
        float(len({e.path for e in window})),       # unique_paths_5min
        float(rule_hits),                           # rule_hits_5min
        1.0 if 400 <= log.status_code < 500 else 0.0,
        1.0 if log.method == "POST" else 0.0,
        log.timestamp.hour / 23.0,
        float(rule_max_score),                      # strongest rule signal in window
    ], dtype=np.float32)
