import sys
import os
import time
import warnings
warnings.filterwarnings("ignore")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.pipeline import Pipeline

LOG_LINES = [
    '192.168.1.10 - admin [10/Oct/2024:13:55:36 +0700] "GET /index.html HTTP/1.1" 200 5432 "https://www.example.com/" "Mozilla/5.0"',
    '192.168.1.50 - - [10/Oct/2024:14:00:00 +0700] "GET /../../etc/passwd HTTP/1.1" 400 512 "-" "curl/7.68.0"',
    '192.168.1.50 - - [10/Oct/2024:14:00:10 +0700] "GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1" 400 512 "-" "python-requests/2.25.1"',
    '2026-03-04 08:24:30 103.106.221.104 POST /Telerik.Web.UI.WebResource.axd type=rau 443 - 45.80.186.43 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:54.0)+Gecko/20100101+Firefox/54.0 - - 200 0 0 1206 237738 639'
]

def run_demo(use_cache: bool):
    print(f"\n{'=' * 50}")
    print(f"--- RUNNING PIPELINE (use_cache={use_cache}) ---")
    print(f"{'=' * 50}")
    
    start_init = time.perf_counter()
    pipeline = Pipeline(use_cache=use_cache)
    print(f"Pipeline initialized in {(time.perf_counter() - start_init) * 1000:.2f} ms")
    
    total_processing_time = 0
    
    for i, line in enumerate(LOG_LINES):
        parts = line.split('"')
        summary = parts[1] if len(parts) >= 2 else line[:80]
        print(f"\n[Event {i+1}] Input: {summary}")
        start_time = time.perf_counter()
        
        alert = pipeline.process_line(line)
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        total_processing_time += elapsed_ms
        
        if alert:
            print(f"  -> Status: FLAGGED (Malicious 1)")
            print(f"  -> Merged Score: {alert.merged_score:.4f}")
            print(f"  -> Phase 1 (Rules): Score: {alert.rule_score:.4f}, Matched: {alert.matched_rules}")
            print(f"  -> Phase 2 (ML): Score: {alert.ml_score:.4f}")
            print(f"  -> Phase 3/4 (LLM): Cache Hit: {alert.cache_hit}")
            print(f"     - Attack Type: {alert.analysis.get('attack_type', 'unknown')}")
            print(f"     - Explanation: {alert.analysis.get('explanation', 'unknown')}")
            print(f"     - Confidence: {alert.analysis.get('confidence', 'unknown')}")
            print(f"     - CVE refs: {alert.analysis.get('cve_refs', 'unknown')}")
            print(f"  -> Latency: {elapsed_ms:.2f} ms")
        else:
            print(f"  -> Status: PASSED (Benign 0)")
            print(f"  -> Latency: {elapsed_ms:.2f} ms")
            
    print(f"\n=> Total Pipeline Processing Time: {total_processing_time:.2f} ms")

if __name__ == "__main__":
    print("PHASE 5: END-TO-END DEMONSTRATION")
    print("Showcasing: Log ingestion -> Processing steps -> Final output")
    
    # Run WITHOUT Cache
    # run_demo(use_cache=False)
    
    # Run WITH Cache
    run_demo(use_cache=True)
