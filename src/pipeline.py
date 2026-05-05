# src/pipeline.py
"""Pipeline orchestrator — runs the full detection flow with use_cache flag.

use_cache=False (Phase 2 baseline): Every flagged event → LLM API → Alert
use_cache=True  (Phase 3+):         Flagged event → cache lookup → hit/miss
"""
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from src.ingestion.normalizer import Normalizer
from src.detection.temporal_buffer import TemporalBuffer
from src.detection.rule_based.detector import RuleDetector
from src.detection.ml.detector import MLDetector
from src.detection.merger import merge, should_flag
from src.llm.client import LLMClient
from src.alert.models import Alert
from src.alert.reporter import Reporter


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

        # Cache is only instantiated when enabled — makes the flag meaningful
        self._cache = None
        if use_cache:
            try:
                from src.llm.cache import SemanticCache
                self._cache = SemanticCache()
            except ImportError:
                pass  # sentence-transformers not installed

        # Flatten all CVE indicator_paths into a set for O(1) lookup
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
        """Process a single raw log line through the full pipeline.

        Args:
            raw: Raw log line string.
            source: Log source type for parsing. Auto-detected if None.

        Returns:
            Alert if event was flagged, None otherwise.
        """
        if source is None:
            source = self._normalizer.detect_source([raw])
        log = self._normalizer.parse_line(raw, source=source)
        if not log:
            return None

        window = self._buffer.add(log)
        rule_result = self._rules.detect(log)
        log.rule_score = rule_result.max_score

        content_score, behavior_score = self._ml.score(log, window, rule_result.max_score)
        log.ml_score = max(content_score, behavior_score)

        merged = merge(rule_result.max_score, content_score, behavior_score,
                       self._buffer.multiplier(log.source_ip))
        if not should_flag(merged):
            return None

        # Binary Classification Only: No LLM calls.
        # analysis = {
        #     "attack_type": rule_result.primary_type if rule_result.primary_type else "unknown",
        #     "confidence": merged,
        #     "explanation": "Flagged by local detection model.",
        #     "recommended_actions": ["monitor"],
        #     "cve_refs": [],
        #     "attack_stage": "unknown",
        #     "ttft_ms": 0,
        #     "input_tokens": 0,
        #     "output_tokens": 0,
        #     "matched_rules": rule_result.matched_rules if hasattr(rule_result, 'matched_rules') else [],
        #     "attack_types": rule_result.attack_types if hasattr(rule_result, 'attack_types') else []
        # }

        # Cache lookup logic removed/ignored as LLM is prohibited

        if self._cache is not None:
            cached_analysis, emb = self._cache.lookup(log)
            if cached_analysis:
                cached_analysis["matched_rules"] = rule_result.matched_rules
                return self._reporter.build(log, window, cached_analysis,
                                             merged, cache_hit=True)
            analysis = self._llm.analyze(str(log), self._window_summary(window), matched_rules=rule_result.matched_rules)
            analysis["matched_rules"] = rule_result.matched_rules
            self._cache.store(emb, analysis)
        else:
            # No cache — always call LLM
            analysis = self._llm.analyze(str(log), self._window_summary(window), matched_rules=rule_result.matched_rules)
            analysis["matched_rules"] = rule_result.matched_rules

        return self._reporter.build(log, window, analysis, merged, cache_hit=False)

    def _window_summary(self, window: list) -> str:
        """Format recent window events for LLM context."""
        return "\n".join(f"{e.timestamp} {e.method} {e.path} {e.status_code}"
                         for e in window[-10:])  # last 10 events max
