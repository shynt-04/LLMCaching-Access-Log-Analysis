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
    HAS_CACHE_DEPS = True
except ImportError:
    HAS_CACHE_DEPS = False


class DummyNvidiaEmbedder:
    model = "dummy-nvidia-embed"

    def __init__(self, model: str | None = None) -> None:
        if model:
            self.model = model

    def embed(self, text: str, truncate: int = 512) -> np.ndarray:
        if "etc/passwd" in text or "../" in text:
            vec = np.array([1.0, 0.0], dtype=np.float32)
        elif "/home " in text or "/home?" in text:
            vec = np.array([1.0, 0.0], dtype=np.float32)
        elif "/api/users" in text or "/home2" in text:
            vec = np.array([0.0, 1.0], dtype=np.float32)
        else:
            vec = np.array([0.7, 0.7], dtype=np.float32)
        return vec / np.linalg.norm(vec)


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
                    reason="cache dependencies not installed")
class TestSemanticCache:
    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "nvidia")
        monkeypatch.setenv("CACHE_EMBED_PROVIDER", "nvidia")
        monkeypatch.setattr(
            "src.llm.nvidia_client.NvidiaEmbedder",
            DummyNvidiaEmbedder,
        )
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
        self.cache.store(emb, {"attack_type": "sqli", "confidence": 0.9})
        assert self.cache.size == 1

    def test_clear(self):
        """Clear should reset the cache."""
        log = _make_log(path="/test")
        _, emb = self.cache.lookup(log)
        self.cache.store(emb, {"test": True})
        self.cache.clear()
        assert self.cache.size == 0


def _policy_cache(monkeypatch):
    from src.llm.cache import SemanticCache

    cache = SemanticCache.__new__(SemanticCache)
    cache._entries = []
    cache._exact = {}
    cache._embedding_matrix = None
    cache._max_size = 128
    cache._last_key = None
    cache._lookups = 0
    cache._hits = 0
    cache._semantic_rejects = 0
    monkeypatch.setattr(cache, "_embed", lambda key: np.array([1.0, 0.0], dtype=np.float32))
    return cache


def test_attack_type_aware_cache_rejects_cross_type(monkeypatch):
    from src.llm.cache import CacheContext

    cache = _policy_cache(monkeypatch)
    seed_log = _make_log(path="/search", query_string="q=1 union select password")
    cache.lookup(seed_log, CacheContext(attack_types=["sqli"], matched_rules=["sqli_union_or_boolean"]))
    cache.store(
        np.array([1.0, 0.0], dtype=np.float32),
        {"attack_type": "sqli", "confidence": 0.95, "severity": "high"},
        CacheContext(attack_types=["sqli"], matched_rules=["sqli_union_or_boolean"]),
    )

    xss_log = _make_log(path="/search", query_string="q=<script>alert(1)</script>")
    result = cache.lookup(
        xss_log,
        CacheContext(attack_types=["xss"], matched_rules=["xss_script_or_handler"]),
    )

    assert result.analysis is None
    assert result.hit_type == "rejected"
    assert "attack_type_mismatch" in result.decision_reason


def test_normal_verdict_is_exact_only(monkeypatch):
    from src.llm.cache import CacheContext

    cache = _policy_cache(monkeypatch)
    normal_log = _make_log(path="/home")
    cache.lookup(normal_log, CacheContext(attack_types=[]))
    cache.store(
        np.array([1.0, 0.0], dtype=np.float32),
        {"attack_type": "normal", "confidence": 0.95, "label": 0},
        CacheContext(attack_types=[]),
    )

    assert cache.size == 0

    exact = cache.lookup(normal_log, CacheContext(attack_types=[]))
    assert exact.analysis is not None
    assert exact.hit_type == "exact"

    near_neighbor = _make_log(path="/home2")
    semantic = cache.lookup(near_neighbor, CacheContext(attack_types=[]))
    assert semantic.analysis is None
