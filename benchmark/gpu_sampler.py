import time

# Module-level GPU availability check — done once at import
_HAS_GPU = False
try:
    import pynvml
    pynvml.nvmlInit()
    pynvml.nvmlDeviceGetHandleByIndex(0)
    _HAS_GPU = True
    pynvml.nvmlShutdown()
except Exception:
    pass


def sample_gpu_util(duration_s: float) -> float:
    """Sample average GPU utilization over a call duration.

    Uses pynvml (NVIDIA) or falls back to 0.0 if unavailable (CPU-only machine).
    """
    if not _HAS_GPU:
        return 0.0
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
        return 0.0
