# benchmark/load_generator.py
"""Generate synthetic Apache log lines with mixed normal/attack traffic.

Usage:
    python benchmark/load_generator.py
    # Generates data/benchmark/load_1k.log, load_10k.log, load_100k.log
"""
import sys
import os
import random
import datetime
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

NORMAL_PATHS = ["/index.html", "/about", "/api/users", "/static/main.js", "/favicon.ico"]
ATTACK_PATHS = [
    "/../../etc/passwd", "/admin", "/.git/config",
    "/Telerik.Web.UI.WebResource.axd", "/api/jsonws",
    "/login?id=1 OR 1=1", "/wp-admin", "/backup.zip",
]


def generate(n: int, attack_ratio: float = 0.15) -> list[str]:
    """Generate synthetic Apache log lines with mixed normal/attack traffic."""
    lines = []
    base_time = datetime.datetime(2024, 3, 13, 8, 0, 0)
    ip_pool = [f"192.168.1.{i}" for i in range(1, 20)]
    attack_ips = ["10.0.0.99", "172.16.0.50"]  # dedicated attacker IPs

    for i in range(n):
        ts = base_time + datetime.timedelta(seconds=i * 0.1)
        is_attack = random.random() < attack_ratio
        ip = random.choice(attack_ips if is_attack else ip_pool)
        path = random.choice(ATTACK_PATHS if is_attack else NORMAL_PATHS)
        status = random.choice([400, 403, 404]) if is_attack else 200
        ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(f'{ip} - - [{ts_str}] "GET {path} HTTP/1.1" {status} 512 "-" "Mozilla/5.0"')

    return lines


if __name__ == "__main__":
    for n in [1_000, 10_000, 100_000]:
        lines = generate(n)
        out = Path(f"data/benchmark/load_{n // 1000}k.log")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(lines))
        print(f"Generated {out} ({n} lines)")
