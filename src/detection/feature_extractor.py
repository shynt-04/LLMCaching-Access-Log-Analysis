# src/detection/feature_extractor.py
"""Build 17-dim feature vector combining structural, rule-derived, and temporal signals.

Feature index map — must stay in sync with trainer.py:
  Structural:   [0]path_depth  [1]path_length  [2]has_traversal
                [3]special_char_ratio  [4]extension_is_script
  Rule-derived: [5]matches_cve_path  [6]matches_any_rule
                [7]rule_max_score  [8]rule_type_encoded
  Temporal:     [9]req_per_ip_5min  [10]error_rate_5min
                [11]unique_paths_5min  [12]rule_hits_5min
  Context:      [13]status_4xx  [14]hour_of_day
                [15]method_is_post  [16]qs_length
"""
import numpy as np
from src.ingestion.schema import NormalizedLog

FEATURE_NAMES = [
    "path_depth",
    "path_length",
    "has_traversal",
    "special_char_ratio",
    "extension_is_script",
    "matches_cve_path",
    "matches_any_rule",
    "rule_max_score",
    "rule_type_encoded",
    "req_per_ip_5min",
    "error_rate_5min",
    "unique_paths_5min",
    "rule_hits_5min",
    "status_4xx",
    "hour_of_day",
    "method_is_post",
    "qs_length",
]

NUM_FEATURES = len(FEATURE_NAMES)

_SCRIPT_EXTS = {".php", ".asp", ".aspx", ".jsp", ".cgi"}
_SPECIAL = set("<>'\"`;=()")
_TYPE_MAP = {"path_traversal": 1, "sqli": 2, "dir_scan": 3, "cve": 4}


def extract(
    log: NormalizedLog,
    window: list[NormalizedLog],
    rule_result=None,
    cve_paths: set[str] | None = None,
) -> np.ndarray:
    """Build 17-dim feature vector from event, window, and rule output.

    Rule outputs are included so IF can learn correlations between
    signature hits and behavioral anomalies (e.g., CVE path + high error rate).
    CVE detection itself is handled by rules — features [5][6][7] let IF
    amplify and contextualize those detections.

    Args:
        log: The event to featurize.
        window: Recent events from same source_ip (last 5 minutes).
        rule_result: Output from rule detector — passed in to avoid re-running rules.
                     If None, rule-derived features are zeroed.
        cve_paths: Set of known CVE indicator paths loaded from cve_lookup.json.
                   If None, CVE path feature is zeroed.

    Returns:
        numpy array shape (17,), dtype float32.
    """
    path = log.path or ""
    qs = log.query_string or ""
    combined = path + qs
    n = max(len(window), 1)
    errors = sum(1 for e in window if e.status_code >= 400)
    ext = ("." + path.rsplit(".", 1)[-1].lower()) if "." in path else ""

    # Rule-derived values — zero-safe when rule_result not provided
    if rule_result is not None:
        matched = 1.0 if rule_result.matched else 0.0
        max_score = float(rule_result.max_score)
        primary_type = float(_TYPE_MAP.get(rule_result.primary_type, 0))
    else:
        matched = 0.0
        max_score = 0.0
        primary_type = 0.0

    # CVE path check
    cve_match = 0.0
    if cve_paths:
        cve_match = 1.0 if any(p in path for p in cve_paths) else 0.0

    return np.array([
        path.count("/"),                                              # [0] path_depth
        float(len(path)),                                             # [1] path_length
        1.0 if ".." in path else 0.0,                                # [2] has_traversal
        sum(c in _SPECIAL for c in combined) / max(len(combined), 1), # [3] special_char_ratio
        1.0 if ext in _SCRIPT_EXTS else 0.0,                        # [4] extension_is_script
        # Rule-derived features — key for CVE awareness in IF
        cve_match,                                                    # [5] matches_cve_path
        matched,                                                      # [6] matches_any_rule
        max_score,                                                    # [7] rule_max_score
        primary_type,                                                 # [8] rule_type_encoded
        # Temporal behavioral features
        float(len(window)),                                           # [9] req_per_ip_5min
        errors / n,                                                   # [10] error_rate_5min
        float(len({e.path for e in window})),                        # [11] unique_paths_5min
        float(sum(1 for e in window if e.rule_score > 0.0)),         # [12] rule_hits_5min
        # Context
        1.0 if 400 <= log.status_code < 500 else 0.0,               # [13] status_4xx
        log.timestamp.hour / 23.0,                                    # [14] hour_of_day
        1.0 if log.method == "POST" else 0.0,                       # [15] method_is_post
        float(len(qs)),                                               # [16] qs_length
    ], dtype=np.float32)
