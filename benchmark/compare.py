# benchmark/compare.py
"""Compare benchmark results from Phase 2 (baseline) and Phase 3 (with cache).

Usage:
    python benchmark/compare.py --baseline benchmark/results/baseline_no_cache.json \\
                               --cache benchmark/results/with_cache.json
"""
import json
import argparse
from pathlib import Path

def compare(baseline_path: str, cache_path: str):
    try:
        b = json.loads(Path(baseline_path).read_text())
        c = json.loads(Path(cache_path).read_text())
    except FileNotFoundError as e:
        print(f"Error: Could not find results file - {e}")
        return

    keys = [
        ("latency_p95_ms",      "P95 Latency (ms)",       True),
        ("throughput_eps",      "Throughput (ev/s)",       False),
        ("avg_payload_kb",      "Avg payload (KB)",        True),
        ("ttft_p50_ms",         "TTFT P50 (ms)",           True),
        ("avg_gpu_util_pct",    "GPU utilization (%)",     True),
        ("cost_per_llm_call_usd","Cost/call ($)",          True),
        ("cache_hit_rate",      "Cache hit rate",          False),
        ("llm_calls_saved",     "LLM calls saved",         False),
    ]

    print(f"\n{'Metric':<28} {'No cache':>12} {'With cache':>12} {'Delta':>10}")
    print("─" * 66)

    for k, label, lower_better in keys:
        bv = b.get(k) or 0
        cv = c.get(k) or 0
        if bv:
            pct = (cv - bv) / abs(bv) * 100
            sign = "+" if pct > 0 else ""
            delta = f"{sign}{pct:.1f}%"
            # Mark improvements: negative delta if lower is better, or positive if higher is better
            better = (pct < 0 and lower_better) or (pct > 0 and not lower_better)
            marker = " ✓" if better else "  "
        else:
            delta = "N/A"
            marker = ""
        print(f"{label:<28} {str(bv):>12} {str(cv):>12} {delta:>10}{marker}")

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Compare baseline vs cache performance")
    p.add_argument("--baseline", default="benchmark/results/baseline_no_cache.json")
    p.add_argument("--cache",    default="benchmark/results/with_cache.json")
    args = p.parse_args()
    compare(args.baseline, args.cache)
