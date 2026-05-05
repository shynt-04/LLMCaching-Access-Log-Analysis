import pytest
import numpy as np
from datetime import datetime
from src.ingestion.schema import NormalizedLog
from src.detection.ml.feature_extractor import build_content_text, extract_behavioral

@pytest.fixture
def sample_log():
    return NormalizedLog(
        timestamp=datetime.now(),
        source_ip="192.168.1.1",
        method="GET",
        path="/test.php",
        status_code=200,
        source="nginx",
        user_agent="Mozilla/5.0",
        query_string="id=1 OR 1=1"
    )

def test_build_content_text(sample_log):
    text = build_content_text(sample_log)
    assert "/test.php" in text
    assert "id=1 OR 1=1" in text
    assert "Mozilla/5.0" in text

def test_extract_behavioral(sample_log):
    window = [sample_log, sample_log]
    features = extract_behavioral(sample_log, window, 0.8)
    
    assert features.shape == (8,)
    assert features[0] == 2.0  # len window
    assert features[1] == 0.0  # error rate
    assert features[2] == 1.0  # unique paths
    assert features[7] == 0.8  # rule max score
