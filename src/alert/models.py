# src/alert/models.py
"""Alert data model — output of the detection pipeline."""
from dataclasses import dataclass, field
from datetime import datetime
from src.ingestion.schema import NormalizedLog


@dataclass
class Alert:
    """A finalized alert produced when a log event is flagged."""
    # Source event
    log: NormalizedLog
    timestamp: datetime

    # Scores
    merged_score: float
    rule_score: float
    ml_score: float
    severity: str

    # LLM analysis
    analysis: dict = field(default_factory=dict)
    cache_hit: bool = False
    cache_hit_type: str | None = None
    cache_similarity: float | None = None
    cached_attack_type: str | None = None
    cache_decision_reason: str | None = None
    cache_policy_mode: str | None = None

    # Token usage — for benchmark metrics
    input_tokens: int = 0
    output_tokens: int = 0
    ttft_ms: float | None = None

    # Detection metadata
    matched_rules: list[str] = field(default_factory=list)
    attack_types: list[str] = field(default_factory=list)

    def model_dump_json(self) -> str:
        """Serialize to JSON for WebSocket streaming."""
        import json
        return json.dumps({
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.log.source_ip,
            "method": self.log.method,
            "path": self.log.path,
            "query_string": self.log.query_string,
            "status_code": self.log.status_code,
            "user_agent": self.log.user_agent,
            "raw_line": self.log.raw_line,
            "merged_score": round(self.merged_score, 4),
            "rule_score": round(self.rule_score, 4),
            "ml_score": round(self.ml_score, 4),
            "severity": self.severity,
            "cache_hit": self.cache_hit,
            "cache_hit_type": self.cache_hit_type,
            "cache_similarity": (
                round(self.cache_similarity, 4)
                if self.cache_similarity is not None else None
            ),
            "cached_attack_type": self.cached_attack_type,
            "cache_decision_reason": self.cache_decision_reason,
            "cache_policy_mode": self.cache_policy_mode,
            "analysis": self.analysis,
            "matched_rules": self.matched_rules,
            "attack_types": self.attack_types,
        })
