# src/alert/reporter.py
"""Build Alert objects from detection pipeline results."""
from src.alert.models import Alert
from src.ingestion.schema import NormalizedLog


class Reporter:
    """Construct finalized Alert from detection results + LLM analysis."""

    def build(
        self,
        log: NormalizedLog,
        window: list[NormalizedLog],
        analysis: dict,
        merged_score: float,
        cache_hit: bool = False,
    ) -> Alert:
        """Create an Alert with all metadata for streaming and benchmarks.

        Args:
            log: The flagged event.
            window: Temporal context window.
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

        return Alert(
            log=log,
            timestamp=log.timestamp,
            merged_score=merged_score,
            rule_score=log.rule_score,
            ml_score=log.ml_score,
            analysis=analysis,
            cache_hit=cache_hit,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            ttft_ms=ttft_ms,
            window_size=len(window),
            matched_rules=analysis.get("matched_rules", []),
            attack_types=analysis.get("attack_types", []),
        )

