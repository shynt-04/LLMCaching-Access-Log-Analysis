import time, json
from pathlib import Path
from src.pipeline import Pipeline
from benchmark.metrics import BenchmarkMetrics
from benchmark.gpu_sampler import sample_gpu_util
import threading
import argparse

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
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True, help="Path to log file")
    parser.add_argument("--out", required=True, help="Output JSON path")
    parser.add_argument("--cache", action="store_true", help="Enable cache")
    args = parser.parse_args()
    print(f"Running benchmark on {args.log} (cache={args.cache})")
    run(args.log, args.cache, args.out)
    print(f"Results saved to {args.out}")
