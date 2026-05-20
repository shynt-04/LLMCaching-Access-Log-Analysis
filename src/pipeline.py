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
from src.detection.temporal_buffer import TemporalBuffer
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
        self._buffer = TemporalBuffer()
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

        window = self._buffer.add(log)
        rule_result = self._rules.detect(log)
        log.rule_score = rule_result.max_score

        content_score, behavior_score = self._ml.score(
            log,
            window,
            rule_result.max_score,
        )
        log.ml_score = max(content_score, behavior_score)

        merged = merge(
            rule_result.max_score,
            content_score,
            behavior_score,
            self._buffer.multiplier(log.source_ip),
        )
        if not should_flag(merged):
            return None

        if self._cache is not None:
            cached_analysis, emb = self._cache.lookup(log)
            if cached_analysis:
                cached_analysis["matched_rules"] = rule_result.matched_rules
                return self._reporter.build(
                    log,
                    window,
                    cached_analysis,
                    merged,
                    cache_hit=True,
                )

            analysis = self._llm.analyze(
                self._event_summary(log, rule_result, merged),
                self._window_summary(window),
                matched_rules=rule_result.matched_rules,
            )
            analysis["matched_rules"] = rule_result.matched_rules
            self._cache.store(emb, analysis)
        else:
            analysis = self._llm.analyze(
                self._event_summary(log, rule_result, merged),
                self._window_summary(window),
                matched_rules=rule_result.matched_rules,
            )
            analysis["matched_rules"] = rule_result.matched_rules

        return self._reporter.build(log, window, analysis, merged, cache_hit=False)

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

    def _window_summary(self, window: list[NormalizedLog]) -> str:
        """Summarize temporal context without listing raw events."""
        if not window:
            return "same_ip_window_count=0"
        statuses_4xx = sum(1 for e in window if 400 <= e.status_code < 500)
        statuses_5xx = sum(1 for e in window if e.status_code >= 500)
        posts = sum(1 for e in window if e.method == "POST")
        rule_hits = sum(1 for e in window if e.rule_score > 0.3)
        unique_paths = len({e.path for e in window})
        recent_paths = ", ".join(self._decode(e.path, limit=40) for e in window[-5:])
        return "\n".join([
            f"same_ip_window_count={len(window)}",
            f"unique_paths={unique_paths}",
            f"post_count={posts}",
            f"4xx_count={statuses_4xx}",
            f"5xx_count={statuses_5xx}",
            f"rule_hit_count={rule_hits}",
            f"recent_paths={recent_paths}",
        ])
