# benchmark/runner.py
import sys
import os
import time
import json
import threading
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from src.pipeline import Pipeline
from benchmark.metrics import BenchmarkMetrics
from benchmark.gpu_sampler import sample_gpu_util


def run(log_path: str, use_cache: bool, output_path: str) -> dict:
    """Run the full pipeline on a log file and record all benchmark metrics.

    Args:
        log_path: Path to log file.
        use_cache: False = Phase 2 baseline, True = Phase 3 with cache.
        output_path: JSON output path.
    """
    pipeline = Pipeline(use_cache=use_cache)
    m = BenchmarkMetrics()
    lines = Path(log_path).read_text().splitlines()
    wall_start = time.perf_counter()

    for line in lines:
        t0 = time.perf_counter()

        # Sample GPU util concurrently with the LLM call
        gpu_util = 0.0
        alert = None

        def _run():
            nonlocal alert
            alert = pipeline.process_line(line)

        t = threading.Thread(target=_run)
        t.start()
        # Poll GPU while the call runs
        import time as _t
        samples = []
        while t.is_alive():
            samples.append(sample_gpu_util(0.05))
        t.join()
        gpu_util = sum(samples) / len(samples) if samples else 0.0

        latency = (time.perf_counter() - t0) * 1000
        m.record_event(latency)

        if alert:
            m.record_llm_call(
                alert.input_tokens, alert.output_tokens,
                alert.ttft_ms or 0.0, gpu_util, alert.cache_hit,
            )

    m.elapsed_wall_s = time.perf_counter() - wall_start
    summary = m.summary()
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Benchmark pipeline performance")
    p.add_argument("--log",   default="data/benchmark/load_10k.log")
    p.add_argument("--cache", action="store_true")
    p.add_argument("--out",   default="benchmark/results/run.json")
    args = p.parse_args()
    result = run(args.log, args.cache, args.out)
    print(f"\nBenchmark Results ({'with cache' if args.cache else 'no cache'}):")
    for k, v in result.items():
        print(f"  {k}: {v}")
