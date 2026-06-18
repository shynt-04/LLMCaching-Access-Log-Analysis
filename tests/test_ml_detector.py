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
    
    mock_pickle_load.return_value = {
        "model": mock_content_model,
        "vectorizer": mock_vectorizer,
        "threshold": 0.5,
    }

    detector = MLDetector()
    
    log = NormalizedLog(
        timestamp=datetime.now(),
        source_ip="1.2.3.4",
        method="GET",
        path="/",
        status_code=200,
        source="nginx"
    )
    
    content_score = detector.score(log)
    
    assert content_score == pytest.approx(0.9)
