from dataclasses import dataclass, field
import time

@dataclass
class BenchmarkMetrics:
    latencies_ms:   list[float] = field(default_factory=list)
    input_tokens:   list[int]   = field(default_factory=list)
    output_tokens:  list[int]   = field(default_factory=list)
    ttft_ms:        list[float] = field(default_factory=list)
    gpu_util_pct:   list[float] = field(default_factory=list)  # new for local model
    cache_hits:     int = 0
    cache_misses:   int = 0
    total_events:   int = 0
    elapsed_wall_s: float = 0.0

    def record_event(self, latency_ms: float) -> None:
        self.latencies_ms.append(latency_ms)
        self.total_events += 1

    def record_llm_call(self, input_tok: int, output_tok: int,
                        ttft_ms: float, gpu_util: float, cache_hit: bool) -> None:
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
        lats     = np.array(self.latencies_ms)
        llm_n    = max(len(self.input_tokens), 1)
        toks_in  = sum(self.input_tokens)
        toks_out = sum(self.output_tokens)

        return {
            # Latency
            "latency_p50_ms": round(float(np.percentile(lats, 50)), 2),
            "latency_p95_ms": round(float(np.percentile(lats, 95)), 2),
            "latency_p99_ms": round(float(np.percentile(lats, 99)), 2),
            # Throughput
            "throughput_eps": round(self.total_events / self.elapsed_wall_s, 1),
            # Data transfer — payload size to Ollama, not $
            "avg_input_tokens":  round(toks_in  / llm_n, 1),
            "avg_output_tokens": round(toks_out / llm_n, 1),
            "avg_payload_kb":    round((toks_in + toks_out) * 4 / 1024 / llm_n, 2),
            # TTFT
            "ttft_p50_ms": round(float(np.percentile(self.ttft_ms, 50)), 2)
                           if self.ttft_ms else None,
            "ttft_p95_ms": round(float(np.percentile(self.ttft_ms, 95)), 2)
                           if self.ttft_ms else None,
            # GPU utilization — 0% on cache hit, ~80% on cache miss
            "avg_gpu_util_pct": round(float(np.mean(self.gpu_util_pct)), 1)
                                if self.gpu_util_pct else None,
            # Cost: local model = $0 always
            "cost_per_llm_call_usd": 0.0,
            "total_cost_usd": 0.0,
            # Cache
            "cache_hit_rate": round(
                self.cache_hits / max(self.cache_hits + self.cache_misses, 1), 3),
            "llm_calls_saved": self.cache_hits,
        }
