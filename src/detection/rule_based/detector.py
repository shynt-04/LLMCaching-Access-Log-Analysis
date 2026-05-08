# src/detection/rule_based/detector.py
"""Rule-based attack detector.

Applies all defined rules against a NormalizedLog event and returns
the aggregated result with the highest matching score.
"""
from dataclasses import dataclass, field
from src.detection.rule_based.rules import RULES, Rule
from src.ingestion.schema import NormalizedLog


@dataclass
class RuleResult:
    """Output of rule-based detection for a single event."""
    score: float = 0.0                      # max score among matched rules
    matched_rules: list[str] = field(default_factory=list)
    attack_types: list[str] = field(default_factory=list)

    @property
    def max_score(self) -> float:
        """Alias for score — used by feature extractor and pipeline."""
        return self.score

    @property
    def matched(self) -> bool:
        """True if any rule fired."""
        return len(self.matched_rules) > 0

    @property
    def primary_type(self) -> str:
        """First (highest-priority) attack type detected, or empty string."""
        return self.attack_types[0] if self.attack_types else ""


class RuleDetector:
    """Stateless rule engine — apply all rules to a log event."""

    def __init__(self, rules: list[Rule] | None = None):
        self._rules = rules if rules is not None else RULES

    def detect(self, log: NormalizedLog) -> RuleResult:
        """Evaluate all rules against a single log event.

        Returns RuleResult with the max score among all matching rules
        and the list of rule names that fired.
        """
        result = RuleResult()

        for rule in self._rules:
            value = self._get_field(log, rule.field)
            if value is None:
                continue

            if rule.pattern.search(value):
                result.matched_rules.append(rule.name)
                if rule.attack_type not in result.attack_types:
                    result.attack_types.append(rule.attack_type)
                # Keep max score — a single high-confidence match dominates
                if rule.score > result.score:
                    result.score = rule.score

        return result

    def score(self, log: NormalizedLog) -> RuleResult:
        """Backward-compatible alias for detect()."""
        return self.detect(log)

    @staticmethod
    def _get_field(log: NormalizedLog, field_name: str) -> str | None:
        """Extract the target field from a NormalizedLog."""
        if field_name == "path":
            return log.path
        elif field_name == "query_string":
            return log.query_string
        elif field_name == "content":
            return log.content
        elif field_name == "user_agent":
            return log.user_agent
        elif field_name == "any":
            parts = [log.path or ""]
            if log.query_string:
                parts.append(log.query_string)
            if log.content:
                parts.append(log.content)
            if log.user_agent:
                parts.append(log.user_agent)
            return " ".join(parts)
        return None
