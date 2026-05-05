import threading
import time
from typing import Callable

def sample_gpu_util(duration_s: float) -> float:
    """Sample average GPU utilization over a call duration.

    Uses pynvml (NVIDIA) or falls back to 0.0 if unavailable (CPU-only machine).
    """
    try:
        import pynvml
        pynvml.nvmlInit()
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        samples, t_end = [], time.perf_counter() + duration_s
        while time.perf_counter() < t_end:
            util = pynvml.nvmlDeviceGetUtilizationRates(handle)
            samples.append(float(util.gpu))
            time.sleep(0.05)
        return sum(samples) / len(samples) if samples else 0.0
    except Exception:
        # pynvml unavailable (no NVIDIA GPU or not installed) — return 0
        return 0.0
