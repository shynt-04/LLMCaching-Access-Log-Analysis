# tests/test_ml_detector.py
"""Tests for ML detector — requires trained model.

Run `python train_model.py` before these tests.
"""
import sys
import os
import pytest
import numpy as np
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime, timezone
from src.ingestion.schema import NormalizedLog
from src.detection.ml.detector import MLDetector
from src.detection.feature_extractor import extract
from src.detection.rule_based.detector import RuleResult


MODEL_PATH = Path("data/models/isolation_forest.pkl")

CVE_PATHS = {"/Telerik.Web.UI.WebResource.axd", "/api/jsonws"}


def _make_log(
    path: str = "/index.html",
    query_string: str | None = None,
    status_code: int = 200,
    source_ip: str = "192.168.1.100",
) -> NormalizedLog:
    return NormalizedLog(
        timestamp=datetime(2024, 3, 13, 14, 23, 45, tzinfo=timezone.utc),
        source_ip=source_ip,
        method="GET",
        path=path,
        status_code=status_code,
        source="nginx",
        query_string=query_string,
    )


def _make_rule_result(score: float = 0.0) -> RuleResult:
    return RuleResult(score=score)


@pytest.fixture
def ml_detector():
    if not MODEL_PATH.exists():
        pytest.skip("Model not trained yet — run `python train_model.py` first")
    return MLDetector(MODEL_PATH)


class TestMLDetector:
    def test_score_range(self, ml_detector):
        """Score should always be in [0, 1]."""
        log = _make_log()
        rule_result = _make_rule_result()
        score = ml_detector.score(log, [log], rule_result, CVE_PATHS)
        assert 0.0 <= score <= 1.0

    def test_normal_traffic_low_score(self, ml_detector):
        """Normal traffic should get low anomaly scores."""
        log = _make_log(path="/image/60844/productModel/200x200")
        rule_result = _make_rule_result()
        score = ml_detector.score(log, [log], rule_result, CVE_PATHS)
        # Normal traffic should generally score below threshold
        assert score < 0.8

    def test_attack_higher_than_normal(self, ml_detector):
        """Attack traffic should score higher than normal on average."""
        rule_result = _make_rule_result()

        normal_scores = []
        for path in ["/index.html", "/image/123/product", "/settings/logo"]:
            log = _make_log(path=path)
            normal_scores.append(ml_detector.score(log, [log], rule_result, CVE_PATHS))

        attack_scores = []
        for path in ["/../../etc/passwd", "/../../etc/shadow"]:
            log = _make_log(path=path, status_code=400)
            attack_scores.append(ml_detector.score(log, [log], rule_result, CVE_PATHS))

        avg_normal = np.mean(normal_scores)
        avg_attack = np.mean(attack_scores)
        # Attack should score higher on average
        assert avg_attack > avg_normal

    def test_batch_scoring(self, ml_detector):
        """Batch scoring should return correct shapes."""
        logs = [_make_log(path=f"/path/{i}") for i in range(5)]
        vectors = np.array([extract(log, [log]) for log in logs])
        scores = ml_detector.score_batch(vectors)
        assert scores.shape == (5,)
        assert all(0.0 <= s <= 1.0 for s in scores)
