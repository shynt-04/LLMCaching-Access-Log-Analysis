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

    # LLM analysis
    analysis: dict = field(default_factory=dict)
    cache_hit: bool = False

    # Token usage — for benchmark metrics
    input_tokens: int = 0
    output_tokens: int = 0
    ttft_ms: float | None = None

    # Context
    window_size: int = 0
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
            "cache_hit": self.cache_hit,
            "analysis": self.analysis,
            "matched_rules": self.matched_rules,
            "attack_types": self.attack_types,
            "window_size": self.window_size,
        })
