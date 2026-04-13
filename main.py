"""
python main.py                                    
python main.py data/raw/sample_apache.log apache 
python main.py data/raw/sample_iis.log iis       
"""

import sys
import os

# Add code/ to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ingestion.normalizer import Normalizer


def main():
    log_file = "data/raw/sample_nginx.log"
    source = None  

    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    if len(sys.argv) > 2:
        source = sys.argv[2]

    print(f"Parsing: {log_file}")
    if source:
        print(f"Source: {source}")
    else:
        print(f"Source: auto-detect")

    normalizer = Normalizer()
    results = normalizer.parse_file(log_file, source=source)

    print(f"\nParsed: {len(results)} log entries")
    print(f"{'=' * 60}")

    for i, log in enumerate(results[:10]):
        print(
            f"  [{i+1}] {log.timestamp.isoformat()} | "
            f"{log.source_ip:>15} | {log.method:>6} | "
            f"{log.status_code} | {log.path[:50]} | {log.user_agent}"
        )

    # if len(results) > 10:
    #     print(f"  ... and {len(results) - 10} more entries")

    # print(f"\nStatistics:")
    # print(f"  Source:       {results[0].source if results else 'N/A'}")
    # print(f"  Total:        {len(results)}")

    # methods = {}
    # for r in results:
    #     methods[r.method] = methods.get(r.method, 0) + 1
    # print(f"  Methods:      {dict(sorted(methods.items()))}")

    # statuses = {}
    # for r in results:
    #     statuses[r.status_code] = statuses.get(r.status_code, 0) + 1
    # print(f"  Status codes: {dict(sorted(statuses.items()))}")


if __name__ == "__main__":
    main()