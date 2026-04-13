# tests/test_feature_extractor.py
"""Tests for the 17-dim CVE-aware feature extraction module."""
import sys
import os
import pytest
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime, timezone
from src.ingestion.schema import NormalizedLog
from src.detection.feature_extractor import extract, NUM_FEATURES
from src.detection.rule_based.detector import RuleResult


def _make_log(
    path: str = "/index.html",
    query_string: str | None = None,
    status_code: int = 200,
    hour: int = 12,
    method: str = "GET",
    rule_score: float = 0.0,
) -> NormalizedLog:
    return NormalizedLog(
        timestamp=datetime(2024, 3, 13, hour, 0, 0, tzinfo=timezone.utc),
        source_ip="192.168.1.100",
        method=method,
        path=path,
        status_code=status_code,
        source="nginx",
        query_string=query_string,
        rule_score=rule_score,
    )


def _make_rule_result(
    score: float = 0.0,
    matched_rules: list[str] | None = None,
    attack_types: list[str] | None = None,
) -> RuleResult:
    return RuleResult(
        score=score,
        matched_rules=matched_rules or [],
        attack_types=attack_types or [],
    )


CVE_PATHS = {"/Telerik.Web.UI.WebResource.axd", "/api/jsonws"}


class TestFeatureExtraction:
    def test_output_shape(self):
        """17-dim feature vector."""
        log = _make_log()
        vec = extract(log, [log])
        assert vec.shape == (NUM_FEATURES,)
        assert NUM_FEATURES == 17
        assert vec.dtype == np.float32

    def test_path_depth(self):
        log = _make_log(path="/a/b/c/d")
        vec = extract(log, [log])
        assert vec[0] == 4.0  # [0] path_depth

    def test_path_length(self):
        log = _make_log(path="/very/long/path/here")
        vec = extract(log, [log])
        assert vec[1] == float(len("/very/long/path/here"))  # [1] path_length

    def test_has_traversal_positive(self):
        log = _make_log(path="/../../etc/passwd")
        vec = extract(log, [log])
        assert vec[2] == 1.0  # [2] has_traversal

    def test_has_traversal_negative(self):
        log = _make_log(path="/normal/path")
        vec = extract(log, [log])
        assert vec[2] == 0.0

    def test_special_char_ratio(self):
        log = _make_log(path="/search", query_string="id=1' OR '1'='1")
        vec = extract(log, [log])
        assert vec[3] > 0  # [3] special_char_ratio

    def test_extension_is_script(self):
        log_php = _make_log(path="/shell.php")
        vec = extract(log_php, [log_php])
        assert vec[4] == 1.0  # [4] extension_is_script

        log_html = _make_log(path="/index.html")
        vec = extract(log_html, [log_html])
        assert vec[4] == 0.0

    def test_matches_cve_path(self):
        log = _make_log(path="/Telerik.Web.UI.WebResource.axd")
        vec = extract(log, [log], cve_paths=CVE_PATHS)
        assert vec[5] == 1.0  # [5] matches_cve_path

        log_normal = _make_log(path="/index.html")
        vec = extract(log_normal, [log_normal], cve_paths=CVE_PATHS)
        assert vec[5] == 0.0

    def test_rule_derived_features_with_result(self):
        log = _make_log()
        rule_result = _make_rule_result(
            score=0.85,
            matched_rules=["sqli_union_select"],
            attack_types=["sqli"],
        )
        vec = extract(log, [log], rule_result=rule_result, cve_paths=CVE_PATHS)
        assert vec[6] == 1.0   # [6] matches_any_rule
        assert vec[7] == 0.85  # [7] rule_max_score
        assert vec[8] == 2.0   # [8] rule_type_encoded (sqli=2)

    def test_rule_derived_features_without_result(self):
        """When rule_result is None, rule-derived features should be zero."""
        log = _make_log()
        vec = extract(log, [log], rule_result=None)
        assert vec[6] == 0.0  # matches_any_rule
        assert vec[7] == 0.0  # rule_max_score
        assert vec[8] == 0.0  # rule_type_encoded

    def test_req_per_ip(self):
        log = _make_log()
        window = [_make_log() for _ in range(5)]
        vec = extract(log, window)
        assert vec[9] == 5.0  # [9] req_per_ip_5min

    def test_error_rate(self):
        normal = _make_log(status_code=200)
        error = _make_log(status_code=404)
        window = [normal, normal, error, error]
        vec = extract(normal, window)
        assert abs(vec[10] - 0.5) < 0.01  # [10] error_rate_5min

    def test_unique_paths(self):
        logs = [
            _make_log(path="/a"),
            _make_log(path="/b"),
            _make_log(path="/a"),
            _make_log(path="/c"),
        ]
        vec = extract(logs[0], logs)
        assert vec[11] == 3.0  # [11] unique_paths_5min: /a, /b, /c

    def test_rule_hits_5min(self):
        logs = [
            _make_log(rule_score=0.0),
            _make_log(rule_score=0.7),
            _make_log(rule_score=0.85),
            _make_log(rule_score=0.0),
        ]
        vec = extract(logs[0], logs)
        assert vec[12] == 2.0  # [12] rule_hits_5min (2 with rule_score > 0)

    def test_status_4xx(self):
        log_400 = _make_log(status_code=404)
        vec = extract(log_400, [log_400])
        assert vec[13] == 1.0  # [13] status_4xx

        log_200 = _make_log(status_code=200)
        vec = extract(log_200, [log_200])
        assert vec[13] == 0.0

    def test_hour_normalized(self):
        log = _make_log(hour=23)
        vec = extract(log, [log])
        assert abs(vec[14] - 1.0) < 0.01  # [14] hour_of_day

        log = _make_log(hour=0)
        vec = extract(log, [log])
        assert abs(vec[14] - 0.0) < 0.01

    def test_method_is_post(self):
        log_post = _make_log(method="POST")
        vec = extract(log_post, [log_post])
        assert vec[15] == 1.0  # [15] method_is_post

        log_get = _make_log(method="GET")
        vec = extract(log_get, [log_get])
        assert vec[15] == 0.0

    def test_qs_length(self):
        log = _make_log(query_string="id=1&name=test")
        vec = extract(log, [log])
        assert vec[16] == float(len("id=1&name=test"))  # [16] qs_length

    def test_empty_window(self):
        log = _make_log()
        vec = extract(log, [])
        assert vec.shape == (NUM_FEATURES,)
        assert vec[9] == 0.0   # req_per_ip
        assert vec[10] == 0.0  # error_rate (0/1 from max)
