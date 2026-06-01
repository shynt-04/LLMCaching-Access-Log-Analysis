# tests/test_cache.py
"""Tests for semantic cache — Phase 3 component.

Requires sentence-transformers package.
"""
import sys
import os
import pytest
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime, timezone
from src.ingestion.schema import NormalizedLog

try:
    from src.llm.cache import SemanticCache
    import ollama as _ollama_check
    HAS_CACHE_DEPS = True
except ImportError:
    HAS_CACHE_DEPS = False


def _make_log(
    path: str = "/index.html",
    method: str = "GET",
    query_string: str | None = None,
) -> NormalizedLog:
    return NormalizedLog(
        timestamp=datetime(2024, 3, 13, 14, 0, 0, tzinfo=timezone.utc),
        source_ip="192.168.1.100",
        method=method,
        path=path,
        status_code=200,
        source="nginx",
        query_string=query_string,
    )


@pytest.mark.skipif(not HAS_CACHE_DEPS,
                    reason="ollama or numpy not installed")
class TestSemanticCache:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.cache = SemanticCache()

    def test_empty_cache_miss(self):
        """Lookup on empty cache should miss."""
        log = _make_log(path="/../../etc/passwd")
        analysis, emb = self.cache.lookup(log)
        assert analysis is None
        assert isinstance(emb, np.ndarray)

    def test_store_and_hit(self):
        """Store entry then look up same event — should hit."""
        log = _make_log(path="/../../etc/passwd")
        _, emb = self.cache.lookup(log)
        mock_analysis = {"attack_type": "path_traversal", "confidence": 0.9}
        self.cache.store(emb, mock_analysis)

        # Same event should hit
        result, _ = self.cache.lookup(log)
        assert result is not None
        assert result["attack_type"] == "path_traversal"

    def test_similar_event_hit(self):
        """Similar attack pattern from different IP should still hit."""
        log1 = _make_log(path="/../../etc/passwd")
        _, emb = self.cache.lookup(log1)
        self.cache.store(emb, {"attack_type": "path_traversal"})

        # Different IP, same pattern — embedding excludes IP
        log2 = NormalizedLog(
            timestamp=datetime(2024, 3, 14, 10, 0, 0, tzinfo=timezone.utc),
            source_ip="10.0.0.99",
            method="GET",
            path="/../../etc/passwd",
            status_code=404,
            source="apache",
        )
        result, _ = self.cache.lookup(log2)
        assert result is not None

    def test_different_event_miss(self):
        """Completely different event should miss."""
        log1 = _make_log(path="/../../etc/passwd")
        _, emb = self.cache.lookup(log1)
        self.cache.store(emb, {"attack_type": "path_traversal"})

        # Totally different path
        log2 = _make_log(path="/api/users")
        result, _ = self.cache.lookup(log2)
        assert result is None

    def test_hit_rate(self):
        """Hit rate should reflect cache performance."""
        log = _make_log(path="/../../etc/passwd")
        _, emb = self.cache.lookup(log)
        self.cache.store(emb, {"attack_type": "test"})

        # One hit
        self.cache.lookup(log)
        rate = self.cache.hit_rate()
        assert rate > 0.0

    def test_cache_size(self):
        """Size property tracks entry count."""
        assert self.cache.size == 0
        log = _make_log(path="/test")
        _, emb = self.cache.lookup(log)
        self.cache.store(emb, {"test": True})
        assert self.cache.size == 1

    def test_clear(self):
        """Clear should reset the cache."""
        log = _make_log(path="/test")
        _, emb = self.cache.lookup(log)
        self.cache.store(emb, {"test": True})
        self.cache.clear()
        assert self.cache.size == 0
