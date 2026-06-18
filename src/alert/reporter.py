# src/alert/reporter.py
"""Build Alert objects from detection pipeline results."""
from src.alert.models import Alert
from src.ingestion.schema import NormalizedLog


_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
_SEVERITY_ALIASES = {
    "crit": "critical",
    "med": "medium",
    "warn": "medium",
    "warning": "medium",
    "info": "low",
    "informational": "low",
}


def _normalize_severity(value: object) -> str | None:
    text = str(value or "").strip().lower()
    text = _SEVERITY_ALIASES.get(text, text)
    if text in _VALID_SEVERITIES:
        return text
    return None


def _score_fallback_severity(score: float) -> str:
    """Fallback only when LLM analysis did not provide a usable severity."""
    if score >= 0.85:
        return "critical"
    if score >= 0.70:
        return "high"
    if score >= 0.50:
        return "medium"
    return "low"


class Reporter:
    """Construct finalized Alert from detection results + LLM analysis."""

    def build(
        self,
        log: NormalizedLog,
        analysis: dict,
        merged_score: float,
        cache_hit: bool = False,
    ) -> Alert:
        """Create an Alert with all metadata for streaming and benchmarks.

        Args:
            log: The flagged event.
            analysis: LLM analysis dict (contains token counts and TTFT).
            merged_score: Combined detection score.
            cache_hit: Whether the analysis came from semantic cache.
        """
        # Cache hits don't incur LLM cost — zero out token counts and TTFT
        if cache_hit:
            input_tokens = 0
            output_tokens = 0
            ttft_ms = None
        else:
            input_tokens = analysis.get("input_tokens", 0)
            output_tokens = analysis.get("output_tokens", 0)
            ttft_ms = analysis.get("ttft_ms")  # None when LLM unavailable
        severity = (
            _normalize_severity(analysis.get("severity"))
            or _score_fallback_severity(merged_score)
        )

        return Alert(
            log=log,
            timestamp=log.timestamp,
            merged_score=merged_score,
            rule_score=log.rule_score,
            ml_score=log.ml_score,
            severity=severity,
            analysis=analysis,
            cache_hit=cache_hit,
            cache_hit_type=analysis.get("cache_hit_type"),
            cache_similarity=analysis.get("cache_similarity"),
            cached_attack_type=analysis.get("cached_attack_type"),
            cache_decision_reason=analysis.get("cache_decision_reason"),
            cache_policy_mode=analysis.get("cache_policy_mode"),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            ttft_ms=ttft_ms,
            matched_rules=analysis.get("matched_rules", []),
            attack_types=analysis.get("attack_types", []),
        )
