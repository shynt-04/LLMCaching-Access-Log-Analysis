import pytest
from unittest.mock import patch, MagicMock
from src.detection.ml.detector import MLDetector
from src.ingestion.schema import NormalizedLog
from datetime import datetime
import numpy as np

@pytest.fixture
def mock_models(tmp_path):
    # MLDetector will be tested by mocking out pickle load
    pass

@patch('src.detection.ml.detector.pickle.load')
@patch('builtins.open')
def test_ml_detector_score(mock_open, mock_pickle_load):
    # Setup mock models
    mock_content_model = MagicMock()
    mock_content_model.predict_proba.return_value = np.array([[0.1, 0.9]])
    
    mock_vectorizer = MagicMock()
    mock_vectorizer.transform.return_value = "mock_sparse_matrix"
    
    mock_behavior_model = MagicMock()
    mock_behavior_model.predict_proba.return_value = np.array([[0.2, 0.8]])
    
    mock_scaler = MagicMock()
    mock_scaler.transform.return_value = np.array([[0.5] * 8])

    # First call returns content dict, second returns behavior dict
    mock_pickle_load.side_effect = [
        {"model": mock_content_model, "vectorizer": mock_vectorizer},
        {"model": mock_behavior_model, "scaler": mock_scaler}
    ]

    detector = MLDetector()
    
    log = NormalizedLog(
        timestamp=datetime.now(),
        source_ip="1.2.3.4",
        method="GET",
        path="/",
        status_code=200,
        source="nginx"
    )
    
    content_score, behavior_score = detector.score(log, [log], 0.0)
    
    assert content_score == pytest.approx(0.9)
    assert behavior_score == pytest.approx(0.8)
