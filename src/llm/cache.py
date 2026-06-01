import os
import re
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import parse_qsl, unquote

import numpy as np
import ollama as _ollama

from src.config import CACHE_SIMILARITY, CACHE_MAX_SIZE, OLLAMA_EMBED_MODEL, OLLAMA_HOST
from src.ingestion.schema import NormalizedLog


@dataclass
class CacheEntry:
    embedding: np.ndarray
    analysis: dict
    created_at: datetime
    hit_count: int = 0


class SemanticCache:
    """Two-level cache for LLM analyses.

    Level 1 is an exact cache over canonicalized request keys and avoids the
    embedding API entirely. Level 2 is semantic similarity over canonicalized
    request text for near-duplicate attack variants.
    """

    def __init__(self) -> None:
        host = os.environ.get("OLLAMA_HOST", OLLAMA_HOST)
        self._client = _ollama.Client(host=host)
        self._embed_model = os.environ.get("OLLAMA_EMBED_MODEL", OLLAMA_EMBED_MODEL)
        self._entries: list[CacheEntry] = []
        self._exact: dict[str, dict] = {}
        self._embedding_matrix: np.ndarray | None = None
        self._max_size = CACHE_MAX_SIZE
        self._last_key: str | None = None
        self._lookups = 0
        self._hits = 0
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

    @staticmethod
    def _decode(value: str | None) -> str:
        """Decode common nested URL-encoding without failing on malformed text."""
        if not value:
            return ""
        decoded = value
        for _ in range(2):
            next_value = unquote(decoded)
            if next_value == decoded:
                break
            decoded = next_value
        return decoded

    @classmethod
    def _normalize_token(cls, value: str) -> str:
        """Collapse volatile tokens so equivalent attacks share cache keys."""
        value = cls._decode(value).lower().strip()
        value = re.sub(r"\b[0-9a-f]{16,}\b", "{hash}", value)
        value = re.sub(
            r"\b[a-z0-9+/]{18,}={0,2}\b",
            "{encoded}",
            value,
            flags=re.IGNORECASE,
        )
        value = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "{ip}", value)
        value = re.sub(
            r"\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|"
            r"169\.254\.169\.254|metadata\.google\.internal)\b",
            "{internal_host}",
            value,
        )
        value = re.sub(r"\b\d+\b", "{num}", value)

        if re.search(r"(\.\./|etc/passwd|win\.ini|php://|/proc/self|wp-config)", value):
            return "{path_or_lfi}"
        if re.search(
            r"(union\s+select|or\s+{num}\s*=\s*{num}|sleep\(|waitfor|"
            r"benchmark\(|information_schema)",
            value,
        ):
            return "{sqli}"
        if re.search(r"(<script|onerror|onload|javascript:|<svg|document\.cookie)", value):
            return "{xss}"
        if re.search(r"(\$\(|`|&&|\|\||;|whoami|uname|/bin/bash|wget|curl|nc\s)", value):
            return "{cmd}"
        if re.search(r"(gopher://|file://|dict://|{internal_host}|{ip}:\d+)", value):
            return "{ssrf}"
        return value

    @classmethod
    def _canonical_key(cls, log: NormalizedLog) -> str:
        """Build a stable key for exact cache hits before embedding lookup."""
        path = cls._decode(log.path).lower() or "/"
        path = re.sub(r"/+", "/", path)
        path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
        path = re.sub(r"/[0-9a-f]{8,}(?=/|$)", "/{hash}", path)
        path = cls._normalize_token(path) if path != "/" else path

        query = cls._decode(log.query_string)
        pairs = parse_qsl(query, keep_blank_values=True)
        normalized_pairs = []
        for key, value in pairs:
            normalized_pairs.append((key.lower(), cls._normalize_token(value)))
        normalized_pairs.sort()
        query_part = "&".join(f"{key}={value}" for key, value in normalized_pairs)

        ua_family = ""
        ua = cls._decode(log.user_agent).lower()
        if re.search(r"(nikto|sqlmap|nmap|dirbuster|gobuster|masscan|wpscan)", ua):
            ua_family = "scanner"

        return f"{log.method.upper()} {path}?{query_part} ua={ua_family}"

    def _embed(self, key: str) -> np.ndarray:
        """Create normalized embedding from canonical request text."""
        response = self._client.embed(model=self._embed_model, input=key[:512])
        vec = np.array(response.embeddings[0], dtype=np.float32)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm
        return vec

    def lookup(self, log: NormalizedLog) -> tuple[dict | None, np.ndarray | None]:
        """Return (cached_analysis, embedding).

        Exact canonical hits return before embedding, which keeps cache-hit
        latency independent of the embedding API. On miss, the embedding is
        returned so store() can avoid recomputing it.
        """
        self._lookups += 1
        key = self._canonical_key(log)
        self._last_key = key

        exact = self._exact.get(key)
        if exact is not None:
            self._hits += 1
            return exact.copy(), None

        emb = self._embed(key)
        if self._embedding_matrix is None or not self._entries:
            return None, emb

        sims = self._embedding_matrix @ emb
        best_idx = int(np.argmax(sims))
        best = float(sims[best_idx])
        best_entry = self._entries[best_idx]

        if best >= CACHE_SIMILARITY:
            best_entry.hit_count += 1
            self._hits += 1
            return best_entry.analysis.copy(), emb
        return None, emb

    def store(self, emb: np.ndarray | None, analysis: dict) -> None:
        """Store a new cache entry after an LLM call."""
        if self._last_key is not None:
            self._exact[self._last_key] = analysis.copy()
        if emb is None:
            return

        # Evict oldest entry if at capacity (FIFO eviction)
        if len(self._entries) >= self._max_size:
            self._entries.pop(0)
            self._embedding_matrix = np.vstack(
                [e.embedding.reshape(1, -1) for e in self._entries]
            ) if self._entries else None

        self._entries.append(CacheEntry(emb, analysis.copy(), datetime.now()))
        row = emb.reshape(1, -1)
        if self._embedding_matrix is None:
            self._embedding_matrix = row
        else:
            self._embedding_matrix = np.vstack([self._embedding_matrix, row])

    def hit_rate(self) -> float:
        """Overall cache hit rate since initialization."""
        return self._hits / self._lookups if self._lookups else 0.0

    @property
    def size(self) -> int:
        """Number of semantic entries in the cache."""
        return len(self._entries)

    def clear(self) -> None:
        """Reset the cache."""
        self._entries.clear()
        self._exact.clear()
        self._embedding_matrix = None
        self._last_key = None
        self._lookups = 0
        self._hits = 0
