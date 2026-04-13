# src/llm/cache.py
import os
import numpy as np
import ollama as _ollama
from dataclasses import dataclass
from datetime import datetime
from src.config import CACHE_SIMILARITY, OLLAMA_HOST, OLLAMA_EMBED_MODEL
from src.ingestion.schema import NormalizedLog


@dataclass
class CacheEntry:
    embedding: np.ndarray
    analysis: dict
    created_at: datetime
    hit_count: int = 0


class SemanticCache:
    def __init__(self) -> None:
        host = os.environ.get("OLLAMA_HOST", OLLAMA_HOST)
        self._client = _ollama.Client(host=host)
        self._embed_model = os.environ.get("OLLAMA_EMBED_MODEL", OLLAMA_EMBED_MODEL)
        self._entries: list[CacheEntry] = []
        # Verify embedding model is available
        self._verify_embed_model()

    def _verify_embed_model(self) -> None:
        """Check that the embedding model is pulled in Ollama."""
        try:
            available = [m.model for m in self._client.list().models]
            if (self._embed_model not in available
                    and f"{self._embed_model}:latest" not in available):
                print(
                    f"[Cache] Embedding model '{self._embed_model}' not found. "
                    f"Run: ollama pull {self._embed_model}"
                )
        except Exception as e:
            print(f"[Cache] Could not verify embedding model: {e}")

    def _embed(self, log: NormalizedLog) -> np.ndarray:
        """Create normalized embedding from log event via Ollama embed API.

        Excludes IP and timestamp — maximizes reuse across different sources
        hitting the same attack pattern.
        """
        text = f"{log.method} {log.path}"
        if log.query_string:
            # Cap query string to prevent long payloads from dominating embedding
            text += f"?{log.query_string[:100]}"
        response = self._client.embed(model=self._embed_model, input=text)
        vec = np.array(response.embeddings[0], dtype=np.float32)
        # L2-normalize for cosine similarity via dot product
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm
        return vec

    def lookup(self, log: NormalizedLog) -> tuple[dict | None, np.ndarray]:
        """Return (cached_analysis, embedding). analysis is None on miss.

        Embedding is always returned to avoid recomputing before store().
        """
        emb = self._embed(log)
        best, best_entry = 0.0, None
        for entry in self._entries:
            s = float(np.dot(emb, entry.embedding))  # cosine (normalized vectors)
            if s > best:
                best, best_entry = s, entry

        if best >= CACHE_SIMILARITY:
            best_entry.hit_count += 1
            return best_entry.analysis, emb
        return None, emb

    def store(self, emb: np.ndarray, analysis: dict) -> None:
        """Store a new cache entry after an LLM call."""
        self._entries.append(CacheEntry(emb, analysis, datetime.now()))

    def hit_rate(self) -> float:
        """Overall cache hit rate since initialization."""
        total = sum(e.hit_count for e in self._entries) + len(self._entries)
        return sum(e.hit_count for e in self._entries) / total if total else 0.0

    @property
    def size(self) -> int:
        """Number of entries in the cache."""
        return len(self._entries)

    def clear(self) -> None:
        """Reset the cache."""
        self._entries.clear()
