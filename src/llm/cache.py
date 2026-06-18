import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import parse_qsl, unquote

import numpy as np

from src.config import (
    CACHE_ATTACK_THRESHOLDS,
    CACHE_EXACT_ONLY_TYPES,
    CACHE_MAX_SIZE,
    CACHE_MIN_CONFIDENCE,
    CACHE_POLICY_MODE,
    CACHE_SIMILARITY,
)
from src.ingestion.schema import NormalizedLog


@dataclass
class CacheContext:
    attack_types: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    rule_score: float = 0.0
    ml_score: float = 0.0
    merged_score: float = 0.0
    risk_score: float | None = None


@dataclass
class CacheLookupResult:
    analysis: dict | None
    embedding: np.ndarray | None
    hit: bool
    hit_type: str
    similarity: float | None
    cached_attack_type: str | None
    decision_reason: str

    def __iter__(self):
        yield self.analysis
        yield self.embedding


@dataclass
class CacheEntry:
    embedding: np.ndarray
    analysis: dict
    created_at: datetime
    attack_type: str
    rule_family: str
    confidence: float
    risk_score: float
    hit_count: int = 0


class SemanticCache:
    """Exact + semantic cache with attack-type-aware reuse policy."""

    def __init__(self) -> None:
        self._embed_provider = self._resolve_embed_provider()
        self._client = None
        self._embedder = None
        self._embed_model = ""
        self._entries: list[CacheEntry] = []
        self._exact: dict[str, dict] = {}
        self._embedding_matrix: np.ndarray | None = None
        self._max_size = CACHE_MAX_SIZE
        self._last_key: str | None = None
        self._lookups = 0
        self._hits = 0
        self._semantic_rejects = 0
        self._init_embedder()

    @staticmethod
    def _resolve_embed_provider() -> str:
        provider = os.environ.get("CACHE_EMBED_PROVIDER")
        if provider is None:
            provider = os.environ.get("LLM_PROVIDER", "nvidia")
        provider = provider.lower().strip()
        if provider in {"nvidia", "nim"}:
            return "nvidia"
        if provider == "ollama":
            return "ollama"
        raise ValueError(
            f"Unsupported CACHE_EMBED_PROVIDER={provider!r}. "
            "Use 'nvidia' or 'ollama'."
        )

    def _init_embedder(self) -> None:
        if self._embed_provider == "ollama":
            from src.llm.ollama_client import OllamaEmbedder

            self._embedder = OllamaEmbedder(model=os.environ.get("OLLAMA_EMBED_MODEL"))
            self._embed_model = self._embedder.model
            print(f"[Cache] Using Ollama embedding model: {self._embed_model}")
            return

        from src.llm.nvidia_client import NvidiaEmbedder

        self._embedder = NvidiaEmbedder(model=os.environ.get("NVIDIA_EMBED_MODEL"))
        self._embed_model = self._embedder.model
        print(f"[Cache] Using NVIDIA embedding model: {self._embed_model}")

    @staticmethod
    def _decode(value: str | None) -> str:
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
            return "{lfi}"
        if re.search(
            r"(union\s+select|or\s+{num}\s*=\s*{num}|sleep\(|waitfor|"
            r"benchmark\(|information_schema)",
            value,
        ):
            return "{sqli}"
        if re.search(r"(<script|onerror|onload|javascript:|<svg|document\.cookie)", value):
            return "{xss}"
        if re.search(r"(\{\{.*\}\}|\$\{.*\}|<%=|freemarker|velocity|jinja)", value):
            return "{ssti}"
        if re.search(r"(\$\(|`|&&|\|\||;|whoami|uname|/bin/bash|wget|curl|nc\s)", value):
            return "{cmd}"
        if re.search(r"(gopher://|file://|dict://|{internal_host}|{ip}:\d+)", value):
            return "{ssrf}"
        if re.search(r"(\.php|\.jsp|\.aspx|\.phtml|filename=)", value):
            return "{file_upload}"
        return value

    @classmethod
    def _normalize_exact_token(cls, value: str) -> str:
        """Normalize volatile values without collapsing payload families."""
        value = cls._decode(value).lower().strip()
        value = re.sub(r"\b[0-9a-f]{16,}\b", "{hash}", value)
        value = re.sub(
            r"\b[a-z0-9+/]{24,}={0,2}\b",
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
        return value

    @classmethod
    def _canonical_key(cls, log: NormalizedLog) -> str:
        path = cls._decode(log.path).lower() or "/"
        path = re.sub(r"/+", "/", path)
        path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
        path = re.sub(r"/[0-9a-f]{8,}(?=/|$)", "/{hash}", path)
        path = cls._normalize_exact_token(path) if path != "/" else path

        query = cls._decode(log.query_string)
        pairs = parse_qsl(query, keep_blank_values=True)
        normalized_pairs = []
        for key, value in pairs:
            normalized_pairs.append((key.lower(), cls._normalize_exact_token(value)))
        normalized_pairs.sort()
        query_part = "&".join(f"{key}={value}" for key, value in normalized_pairs)

        ua_family = ""
        ua = cls._decode(log.user_agent).lower()
        if re.search(r"(nikto|sqlmap|nmap|dirbuster|gobuster|masscan|wpscan)", ua):
            ua_family = "scanner"

        return f"{log.method.upper()} {path}?{query_part} ua={ua_family}"

    def _embed(self, key: str) -> np.ndarray:
        if self._embedder is None:
            raise RuntimeError(f"{self._embed_provider} embedder is not initialized")
        return self._embedder.embed(key, truncate=512)

    @staticmethod
    def _normalize_attack_type(value: str | None) -> str:
        value = (value or "unknown").lower().strip()
        aliases = {
            "path_traversal": "lfi",
            "path traversal": "lfi",
            "directory_traversal": "lfi",
            "sql injection": "sqli",
            "sql_injection": "sqli",
            "cross_site_scripting": "xss",
            "file upload": "file_upload",
            "none": "normal",
            "benign": "normal",
        }
        return aliases.get(value, value)

    @classmethod
    def _primary_context_type(cls, context: CacheContext | None) -> str:
        if context is None:
            return "unknown"
        for attack_type in context.attack_types:
            normalized = cls._normalize_attack_type(attack_type)
            if normalized not in ("", "unknown", "normal"):
                return normalized
        return "unknown"

    @staticmethod
    def _rule_family(attack_type: str, matched_rules: list[str] | None) -> str:
        for rule in matched_rules or []:
            rule_l = rule.lower()
            for family in (
                "sqli",
                "xss",
                "lfi",
                "ssrf",
                "ssti",
                "file_upload",
                "csrf",
                "cve",
                "dir_scan",
            ):
                if family in rule_l:
                    return family
            if "path_traversal" in rule_l:
                return "lfi"
        return attack_type

    @classmethod
    def _confidence(cls, analysis: dict) -> float:
        try:
            return float(analysis.get("confidence", 1.0))
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _risk_score(analysis: dict, context: CacheContext | None) -> float:
        if context is not None and context.risk_score is not None:
            return float(context.risk_score)
        raw = analysis.get("risk_score")
        if raw is not None:
            try:
                return float(raw)
            except (TypeError, ValueError):
                pass
        severity = str(analysis.get("severity", "")).lower()
        return {
            "critical": 9.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
        }.get(severity, 5.0)

    def _threshold_for(self, attack_type: str) -> float:
        return float(CACHE_ATTACK_THRESHOLDS.get(attack_type, CACHE_SIMILARITY))

    def _analysis_with_cache_meta(
        self,
        analysis: dict,
        hit_type: str,
        similarity: float | None,
        cached_attack_type: str | None,
        reason: str,
    ) -> dict:
        copied = analysis.copy()
        copied.update({
            "cache_hit_type": hit_type,
            "cache_similarity": similarity,
            "cached_attack_type": cached_attack_type,
            "cache_decision_reason": reason,
            "cache_policy_mode": CACHE_POLICY_MODE,
        })
        return copied

    def _semantic_decision(
        self,
        entry: CacheEntry,
        context: CacheContext | None,
        similarity: float,
    ) -> tuple[bool, str]:
        cached_type = entry.attack_type
        context_type = self._primary_context_type(context)
        threshold = self._threshold_for(context_type if context_type != "unknown" else cached_type)

        if cached_type in CACHE_EXACT_ONLY_TYPES:
            return False, f"cached_type_exact_only:{cached_type}"
        if entry.confidence < CACHE_MIN_CONFIDENCE:
            return False, f"cached_confidence_below_{CACHE_MIN_CONFIDENCE}"
        if similarity < threshold:
            return False, f"similarity<{threshold:.2f}"
        if context is None:
            return True, f"legacy_no_context similarity>={threshold:.2f}"
        if context_type == "unknown":
            return False, "unknown_context_no_semantic_reuse"
        if context_type != "unknown" and context_type != cached_type:
            context_family = self._rule_family(context_type, context.matched_rules if context else [])
            if context_family != entry.rule_family:
                return False, f"attack_type_mismatch:{context_type}!={cached_type}"

        if context_type == cached_type:
            return True, f"same_attack_type:{cached_type} similarity>={threshold:.2f}"
        return True, f"same_rule_family:{entry.rule_family} similarity>={threshold:.2f}"

    def lookup(
        self,
        log: NormalizedLog,
        context: CacheContext | None = None,
    ) -> CacheLookupResult:
        self._lookups += 1
        key = self._canonical_key(log)
        self._last_key = key

        exact = self._exact.get(key)
        if exact is not None:
            cached_type = self._normalize_attack_type(exact.get("attack_type"))
            context_type = self._primary_context_type(context)
            if (
                context is not None
                and context_type != "unknown"
                and context_type != cached_type
            ):
                self._semantic_rejects += 1
            elif (
                context is not None
                and context_type == "unknown"
                and cached_type not in {"unknown", "normal"}
            ):
                self._semantic_rejects += 1
            else:
                self._hits += 1
                return CacheLookupResult(
                    analysis=self._analysis_with_cache_meta(
                        exact,
                        "exact",
                        1.0,
                        cached_type,
                        "exact_canonical_key",
                    ),
                    embedding=None,
                    hit=True,
                    hit_type="exact",
                    similarity=1.0,
                    cached_attack_type=cached_type,
                    decision_reason="exact_canonical_key",
                )

        emb = self._embed(key)
        if self._embedding_matrix is None or not self._entries:
            return CacheLookupResult(None, emb, False, "miss", None, None, "empty_cache")

        sims = self._embedding_matrix @ emb
        best_idx = int(np.argmax(sims))
        best = float(sims[best_idx])
        best_entry = self._entries[best_idx]
        accepted, reason = self._semantic_decision(best_entry, context, best)

        if accepted:
            best_entry.hit_count += 1
            self._hits += 1
            analysis = self._analysis_with_cache_meta(
                best_entry.analysis,
                "semantic",
                best,
                best_entry.attack_type,
                reason,
            )
            return CacheLookupResult(
                analysis,
                emb,
                True,
                "semantic",
                best,
                best_entry.attack_type,
                reason,
            )

        self._semantic_rejects += 1
        return CacheLookupResult(
            None,
            emb,
            False,
            "rejected",
            best,
            best_entry.attack_type,
            reason,
        )

    def store(
        self,
        emb: np.ndarray | None,
        analysis: dict,
        context: CacheContext | None = None,
    ) -> None:
        if self._last_key is not None:
            self._exact[self._last_key] = analysis.copy()
        if emb is None:
            return

        attack_type = self._normalize_attack_type(analysis.get("attack_type"))
        confidence = self._confidence(analysis)
        risk_score = self._risk_score(analysis, context)
        rule_family = self._rule_family(attack_type, context.matched_rules if context else [])

        if attack_type in CACHE_EXACT_ONLY_TYPES:
            return
        if confidence < CACHE_MIN_CONFIDENCE:
            return

        if len(self._entries) >= self._max_size:
            self._entries.pop(0)
            self._embedding_matrix = (
                np.vstack([e.embedding.reshape(1, -1) for e in self._entries])
                if self._entries else None
            )

        self._entries.append(CacheEntry(
            embedding=emb,
            analysis=analysis.copy(),
            created_at=datetime.now(),
            attack_type=attack_type,
            rule_family=rule_family,
            confidence=confidence,
            risk_score=risk_score,
        ))
        row = emb.reshape(1, -1)
        if self._embedding_matrix is None:
            self._embedding_matrix = row
        else:
            self._embedding_matrix = np.vstack([self._embedding_matrix, row])

    def hit_rate(self) -> float:
        return self._hits / self._lookups if self._lookups else 0.0

    @property
    def size(self) -> int:
        return len(self._entries)

    @property
    def semantic_rejects(self) -> int:
        return self._semantic_rejects

    def clear(self) -> None:
        self._entries.clear()
        self._exact.clear()
        self._embedding_matrix = None
        self._last_key = None
        self._lookups = 0
        self._hits = 0
        self._semantic_rejects = 0
