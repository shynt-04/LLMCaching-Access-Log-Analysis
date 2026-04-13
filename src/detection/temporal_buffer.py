# src/detection/temporal_buffer.py
"""Sliding window state manager per source IP.

Maintains a per-IP buffer of recent log events within a configurable
time window. Used for:
  1. Providing temporal context to the feature extractor
  2. Computing temporal multiplier for score amplification
"""
from collections import defaultdict
from datetime import datetime, timedelta
from src.ingestion.schema import NormalizedLog
from src.config import WINDOW_MINUTES, TEMPORAL_CAP


class TemporalBuffer:
    """Manages sliding window of events per source IP."""

    def __init__(self) -> None:
        self._window = timedelta(minutes=WINDOW_MINUTES)
        self._data: dict[str, list[NormalizedLog]] = defaultdict(list)

    def add(self, log: NormalizedLog) -> list[NormalizedLog]:
        """Append event to IP's window, evict expired entries, return current window."""
        ip = log.source_ip
        self._data[ip].append(log)
        self._evict(ip, log.timestamp)
        return self._data[ip].copy()

    def _evict(self, ip: str, now: datetime) -> None:
        """Remove entries older than window_size from the buffer."""
        cutoff = now - self._window
        self._data[ip] = [e for e in self._data[ip] if e.timestamp >= cutoff]

    def multiplier(self, ip: str) -> float:
        """Return temporal amplification factor based on recent suspicious activity.

        Counts events with rule_score > 0.3 in the current window.
        Each suspicious event adds 0.1 to the multiplier, capped at TEMPORAL_CAP.
        """
        suspicious = sum(1 for e in self._data.get(ip, []) if e.rule_score > 0.3)
        return min(1.0 + 0.1 * suspicious, TEMPORAL_CAP)

    def get_window(self, ip: str) -> list[NormalizedLog]:
        """Return current window for an IP without modification."""
        return self._data.get(ip, []).copy()

    def clear(self) -> None:
        """Reset all buffers."""
        self._data.clear()
