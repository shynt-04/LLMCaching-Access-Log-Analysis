"""Pipeline orchestrator - runs the full detection flow with use_cache flag.

use_cache=False: every flagged event -> LLM API -> Alert
use_cache=True:  flagged event -> cache lookup -> hit/miss
"""
import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

from src.alert.models import Alert
from src.alert.reporter import Reporter
from src.detection.merger import merge, should_flag
from src.detection.ml.detector import MLDetector
from src.detection.rule_based.detector import RuleDetector, RuleResult
from src.ingestion.normalizer import Normalizer
from src.ingestion.schema import NormalizedLog
from src.llm.client import LLMClient


@dataclass
class PipelineResult:
    alerts: list[Alert] = field(default_factory=list)
    total_events: int = 0
    processing_ms: list[float] = field(default_factory=list)


class Pipeline:
    """End-to-end detection pipeline with optional semantic cache."""

    def __init__(self, use_cache: bool = True) -> None:
        self._normalizer = Normalizer()
        self._rules = RuleDetector()
        self._ml = MLDetector()
        self._llm = LLMClient()
        self._reporter = Reporter()

        self._cache = None
        if use_cache:
            try:
                from src.llm.cache import SemanticCache
                self._cache = SemanticCache()
            except ImportError:
                pass

        cve_file = Path("data/cve_lookup.json")
        if cve_file.exists():
            cve_raw = json.loads(cve_file.read_text())
            self._cve_paths: set[str] = {
                p for entry in cve_raw.values()
                for p in entry.get("indicator_paths", entry.get("paths", []))
            }
        else:
            self._cve_paths = set()

    def process_line(self, raw: str, source: str | None = None) -> Alert | None:
        """Process one raw log line through detection, cache, and LLM analysis."""
        if source is None:
            source = self._normalizer.detect_source([raw])
        log = self._normalizer.parse_line(raw, source=source)
        if not log:
            return None

        rule_result = self._rules.detect(log)
        log.rule_score = rule_result.max_score

        content_score = self._ml.score(log)
        log.ml_score = content_score

        merged = merge(
            rule_result.max_score,
            content_score,
        )
        if not should_flag(merged):
            return None

        if self._cache is not None:
            from src.llm.cache import CacheContext

            cache_context = CacheContext(
                attack_types=rule_result.attack_types,
                matched_rules=rule_result.matched_rules,
                rule_score=rule_result.max_score,
                ml_score=content_score,
                merged_score=merged,
            )
            cache_result = None
            try:
                cache_result = self._cache.lookup(log, cache_context)
            except Exception as exc:
                print(f"[Cache] lookup failed; continuing without cache: {exc}")

            if cache_result is not None and cache_result.analysis:
                cached_analysis = cache_result.analysis
                cached_analysis["matched_rules"] = rule_result.matched_rules
                cached_analysis["attack_types"] = rule_result.attack_types
                return self._reporter.build(
                    log,
                    cached_analysis,
                    merged,
                    cache_hit=True,
                )

            analysis = self._llm.analyze(
                self._event_summary(log, rule_result, merged),
                self._analysis_context(log, rule_result),
                matched_rules=rule_result.matched_rules,
            )
            analysis["matched_rules"] = rule_result.matched_rules
            analysis["attack_types"] = rule_result.attack_types
            if cache_result is not None:
                try:
                    self._cache.store(cache_result.embedding, analysis, cache_context)
                except Exception as exc:
                    print(f"[Cache] store failed; alert was still generated: {exc}")
        else:
            analysis = self._llm.analyze(
                self._event_summary(log, rule_result, merged),
                self._analysis_context(log, rule_result),
                matched_rules=rule_result.matched_rules,
            )
            analysis["matched_rules"] = rule_result.matched_rules
            analysis["attack_types"] = rule_result.attack_types

        return self._reporter.build(log, analysis, merged, cache_hit=False)

    @staticmethod
    def _decode(value: str | None, limit: int = 180) -> str:
        """Decode compact text for LLM context without sending raw object repr."""
        if not value:
            return ""
        decoded = value
        for _ in range(2):
            next_value = unquote(decoded)
            if next_value == decoded:
                break
            decoded = next_value
        decoded = decoded.replace("\n", " ").replace("\r", " ")
        return decoded[:limit]

    def _event_summary(
        self,
        log: NormalizedLog,
        rule_result: RuleResult,
        merged_score: float,
    ) -> str:
        """Build concise evidence for LLM verification and explanation."""
        parts = [
            f"method={log.method}",
            f"path={self._decode(log.path)}",
            f"status={log.status_code}",
            f"merged_score={merged_score:.3f}",
            f"rule_score={log.rule_score:.3f}",
            f"ml_score={log.ml_score:.3f}",
        ]
        query = self._decode(log.query_string)
        if query:
            parts.append(f"query={query}")
        ua = self._decode(log.user_agent, limit=120)
        if ua:
            parts.append(f"user_agent={ua}")
        if rule_result.attack_types:
            parts.append(f"rule_attack_types={','.join(rule_result.attack_types)}")
        if rule_result.matched_rules:
            parts.append(f"matched_rules={','.join(rule_result.matched_rules[:8])}")
        return "\n".join(parts)

    def _analysis_context(self, log: NormalizedLog, rule_result: RuleResult) -> str:
        """Build non-temporal context for LLM verification."""
        return "\n".join([
            "pipeline_scope=single_request_content_only",
            "behavior_detection=disabled",
            f"source={log.source}",
            f"rule_attack_types={','.join(rule_result.attack_types) if rule_result.attack_types else 'none'}",
            f"matched_rule_count={len(rule_result.matched_rules)}",
        ])
