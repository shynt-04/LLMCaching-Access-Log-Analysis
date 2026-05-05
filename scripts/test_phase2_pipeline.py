"""Quick end-to-end test for Phase 2 detection pipeline."""
import warnings
warnings.filterwarnings("ignore")
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from src.detection.rule_based.detector import RuleDetector
from src.detection.ml.detector import MLDetector
from src.ingestion.normalizer import Normalizer
from src.detection.merger import merge, should_flag
from src.detection.temporal_buffer import TemporalBuffer

# Test logs — mix of benign and malicious
lines = [
    ('192.168.1.10 - admin [10/Oct/2024:13:55:36 +0700] '
     '"GET /index.html HTTP/1.1" 200 5432 "-" "Mozilla/5.0"'),
    ('192.168.1.50 - - [10/Oct/2024:14:00:00 +0700] '
     '"GET /../../etc/passwd HTTP/1.1" 400 512 "-" "curl/7.68.0"'),
    ('192.168.1.50 - - [10/Oct/2024:14:00:10 +0700] '
     '"GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1" 400 512 "-" "python-requests/2.25.1"'),
    ('10.0.0.5 - - [10/Oct/2024:14:05:00 +0700] '
     '"GET /api/v1/users?id=1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'),
]

normalizer = Normalizer()
rules = RuleDetector()
ml = MLDetector()
buffer = TemporalBuffer()

print("=" * 90)
print("Phase 2 Pipeline Test — Detection Engine")
print("=" * 90)

for i, line in enumerate(lines):
    log = normalizer.parse_line(line, source="apache")
    if not log:
        print(f"[{i+1}] PARSE FAILED: {line[:60]}")
        continue

    window = buffer.add(log)
    r = rules.detect(log)
    log.rule_score = r.max_score

    cs, bs = ml.score(log, window, r.max_score)
    log.ml_score = max(cs, bs)

    temporal_mult = buffer.multiplier(log.source_ip)
    m = merge(r.max_score, cs, bs, temporal_mult)
    flag = should_flag(m)

    status = "FLAGGED" if flag else "BENIGN"
    print(f"\n[{i+1}] {log.method} {log.path[:50]}")
    print(f"    Rule:     {r.max_score:.3f} | Rules matched: {r.matched_rules}")
    print(f"    Content:  {cs:.3f}")
    print(f"    Behavior: {bs:.3f}")
    print(f"    Temporal:  x{temporal_mult:.2f}")
    print(f"    Merged:   {m:.3f} -> {status}")

print("\n" + "=" * 90)
print("Phase 2 Pipeline Test PASSED")
print("=" * 90)
