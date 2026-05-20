from dataclasses import dataclass, field


@dataclass
class BenchmarkMetrics:
    latencies_ms: list[float] = field(default_factory=list)
    non_alert_latencies_ms: list[float] = field(default_factory=list)
    stage2_latencies_ms: list[float] = field(default_factory=list)
    cache_hit_latencies_ms: list[float] = field(default_factory=list)
    cache_miss_latencies_ms: list[float] = field(default_factory=list)
    input_tokens: list[int] = field(default_factory=list)
    output_tokens: list[int] = field(default_factory=list)
    ttft_ms: list[float] = field(default_factory=list)
    gpu_util_pct: list[float] = field(default_factory=list)
    cache_hits: int = 0
    cache_misses: int = 0
    total_events: int = 0
    elapsed_wall_s: float = 0.0

    def record_event(self, latency_ms: float) -> None:
        self.latencies_ms.append(latency_ms)
        self.total_events += 1

    def record_non_alert_event(self, latency_ms: float) -> None:
        """Record a line that was not escalated to Stage 2."""
        self.non_alert_latencies_ms.append(latency_ms)

    def record_llm_call(
        self,
        input_tok: int,
        output_tok: int,
        ttft_ms: float,
        gpu_util: float,
        cache_hit: bool,
        latency_ms: float | None = None,
    ) -> None:
        """Record a Stage 2 event, either cache hit or LLM miss."""
        if latency_ms is not None:
            self.stage2_latencies_ms.append(latency_ms)
            if cache_hit:
                self.cache_hit_latencies_ms.append(latency_ms)
            else:
                self.cache_miss_latencies_ms.append(latency_ms)

        self.input_tokens.append(input_tok)
        self.output_tokens.append(output_tok)
        self.ttft_ms.append(ttft_ms)
        self.gpu_util_pct.append(gpu_util)
        if cache_hit:
            self.cache_hits += 1
        else:
            self.cache_misses += 1

    def summary(self) -> dict:
        import numpy as np

        lats = np.array(self.latencies_ms)
        llm_n = max(len(self.input_tokens), 1)
        toks_in = sum(self.input_tokens)
        toks_out = sum(self.output_tokens)
        stage2_total = self.cache_hits + self.cache_misses

        def pct(values: list[float], percentile: int) -> float | None:
            if not values:
                return None
            return round(float(np.percentile(np.array(values), percentile)), 2)

        return {
            # End-to-end latency over all log lines.
            "latency_p50_ms": pct(self.latencies_ms, 50),
            "latency_p95_ms": pct(self.latencies_ms, 95),
            "latency_p99_ms": pct(self.latencies_ms, 99),

            # Local-only vs Stage 2 latency. These are the main cache metrics.
            "non_alert_latency_p50_ms": pct(self.non_alert_latencies_ms, 50),
            "non_alert_latency_p95_ms": pct(self.non_alert_latencies_ms, 95),
            "stage2_latency_p50_ms": pct(self.stage2_latencies_ms, 50),
            "stage2_latency_p95_ms": pct(self.stage2_latencies_ms, 95),
            "stage2_latency_p99_ms": pct(self.stage2_latencies_ms, 99),
            "cache_hit_latency_p50_ms": pct(self.cache_hit_latencies_ms, 50),
            "cache_hit_latency_p95_ms": pct(self.cache_hit_latencies_ms, 95),
            "cache_miss_latency_p50_ms": pct(self.cache_miss_latencies_ms, 50),
            "cache_miss_latency_p95_ms": pct(self.cache_miss_latencies_ms, 95),

            # Counts and throughput.
            "throughput_eps": round(self.total_events / self.elapsed_wall_s, 1),
            "stage2_events": stage2_total,
            "non_alert_events": len(self.non_alert_latencies_ms),
            "cache_hit_events": self.cache_hits,
            "cache_miss_events": self.cache_misses,

            # Data transfer: payload size to Ollama, not dollars.
            "avg_input_tokens": round(toks_in / llm_n, 1),
            "avg_output_tokens": round(toks_out / llm_n, 1),
            "avg_payload_kb": round((toks_in + toks_out) * 4 / 1024 / llm_n, 2),

            # TTFT is meaningful for Stage 2; cache hits are recorded as 0.
            "ttft_p50_ms": pct(self.ttft_ms, 50),
            "ttft_p95_ms": pct(self.ttft_ms, 95),

            # GPU utilization: 0% on cache hit, nonzero on local LLM miss.
            "avg_gpu_util_pct": round(float(np.mean(self.gpu_util_pct)), 1)
            if self.gpu_util_pct else None,

            # Cost: local model = $0 always.
            "cost_per_llm_call_usd": 0.0,
            "total_cost_usd": 0.0,

            # Cache.
            "cache_hit_rate": round(
                self.cache_hits / max(stage2_total, 1),
                3,
            ),
            "llm_calls_saved": self.cache_hits,
        }
