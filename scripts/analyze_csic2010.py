"""
Task 2.0 — CSIC 2010 Distribution Analysis

Analyze the CSIC 2010 dataset to:
1. Classify anomalous entries by attack type using payload pattern matching
2. Compute attack type distribution ratios → used as generation blueprint
3. Export attack_type_ratios.json → data/synthetic/attack_type_ratios.json
4. Export csic_test_sample.jsonl → data/csic2010/csic_test_sample.jsonl
"""

import csv
import json
import random
import re
from collections import Counter
from pathlib import Path


# Pattern banks for attack type classification
ATTACK_PATTERNS = {
    "sqli": [
        r"union\s+select", r"or\s+1\s*=\s*1", r"'\s+or\s+'", r"drop\s+table",
        r"insert\s+into", r"update\s+\w+\s+set", r"delete\s+from", r"--\s*$",
        r";\s*select", r"exec\s*\(", r"execute\s+", r"xp_cmdshell",
        r"waitfor\s+delay", r"benchmark\s*\(", r"sleep\s*\(",
        r"'\s*;\s*", r"1\s*=\s*1", r"having\s+1\s*=\s*1",
        r"char\s*\(\d+\)", r"concat\s*\(", r"group\s+by",
        r"information_schema", r"sysobjects", r"syscolumns",
    ],
    "xss": [
        r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
        r"alert\s*\(", r"eval\s*\(", r"document\.cookie",
        r"<img\s+", r"<svg\s+", r"<iframe", r"<body\s+onload",
        r"expression\s*\(", r"url\s*\(",
    ],
    "path_traversal": [
        r"\.\./", r"\.\.\\", r"%2e%2e", r"%252e",
        r"\.\.%2f", r"\.\.%5c",
    ],
    "lfi": [
        r"/etc/passwd", r"/etc/shadow", r"/proc/self",
        r"php://", r"file://", r"expect://",
        r"input://", r"data://",
    ],
    "dir_scan": [
        r"/admin", r"/\.git", r"/\.env", r"/backup",
        r"/config", r"/phpmyadmin", r"/wp-admin",
        r"/\.htaccess", r"/\.htpasswd",
    ],
}

# Compile patterns
COMPILED_PATTERNS = {
    atype: [re.compile(p, re.IGNORECASE) for p in patterns]
    for atype, patterns in ATTACK_PATTERNS.items()
}


def classify_attack(url: str, content: str) -> str:
    """Classify an anomalous request by attack type using pattern matching.

    Returns the attack type with the most pattern matches, or 'other'
    if no patterns match. Priority order resolves ties.
    """
    text = f"{url} {content}"
    scores = {}
    for atype, patterns in COMPILED_PATTERNS.items():
        matches = sum(1 for p in patterns if p.search(text))
        if matches > 0:
            scores[atype] = matches

    if not scores:
        return "other"

    # Return the type with most matches
    return max(scores, key=scores.get)


def main():
    csv_path = Path("data/csic2010/csic_database.csv")
    if not csv_path.exists():
        print(f"ERROR: {csv_path} not found")
        return

    print("=" * 60)
    print("  CSIC 2010 Distribution Analysis")
    print("=" * 60)

    # Read CSV — detect label column (may be unnamed or have BOM prefix)
    with open(csv_path, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        label_col = None
        for col in reader.fieldnames or []:
            stripped = col.lstrip("\ufeff").strip()
            if stripped == "" or stripped.lower() in ("label", "class", "classification"):
                label_col = col
                break
        rows = list(reader)

    if label_col is None:
        print(f"WARNING: No label column found in CSV headers: {reader.fieldnames}")
        print("Falling back to first column.")
        label_col = (reader.fieldnames or [""])[0]

    normal = [r for r in rows if r.get(label_col, "").strip() == "Normal"]
    anomalous = [r for r in rows if r.get(label_col, "").strip() == "Anomalous"]

    print(f"\nTotal entries: {len(rows)}")
    print(f"  Normal:    {len(normal)}")
    print(f"  Anomalous: {len(anomalous)}")

    # Classify anomalous entries
    attack_counts = Counter()
    classified_entries = []

    for r in anomalous:
        url = r.get("URL", "") or ""
        content = r.get("content", "") or ""
        method = r.get("Method", "GET") or "GET"
        atype = classify_attack(url, content)
        attack_counts[atype] += 1

        classified_entries.append({
            "method": method,
            "url": url,
            "content": content,
            "attack_type": atype,
            "user_agent": r.get("User-Agent", ""),
        })

    # Print distribution
    print(f"\nAttack Type Distribution (anomalous entries):")
    total_anomalous = len(anomalous)
    for atype, count in sorted(attack_counts.items(), key=lambda x: -x[1]):
        pct = count / total_anomalous * 100
        print(f"  {atype:>18s}: {count:>5d} ({pct:.1f}%)")

    # Method distribution
    method_counts = Counter(r.get("Method", "GET") for r in anomalous)
    print(f"\nMethod Distribution (anomalous):")
    for method, count in sorted(method_counts.items(), key=lambda x: -x[1]):
        print(f"  {method:>6s}: {count:>5d}")

    # Compute attack type ratios (excluding 'other' from target ratios)
    known_attacks = {k: v for k, v in attack_counts.items() if k != "other"}
    known_total = sum(known_attacks.values())

    if known_total == 0:
        # If no known attacks classified, use uniform distribution
        attack_ratios = {
            "sqli": 0.25, "xss": 0.15,
            "path_traversal": 0.22, "lfi": 0.18, "dir_scan": 0.20,
        }
    else:
        attack_ratios = {
            atype: round(count / known_total, 3)
            for atype, count in known_attacks.items()
        }

    # Ensure all expected types are present
    for expected in ["sqli", "xss", "path_traversal", "lfi", "dir_scan"]:
        if expected not in attack_ratios:
            attack_ratios[expected] = 0.05  # minimum baseline

    # Normalize
    total_ratio = sum(attack_ratios.values())
    attack_ratios = {k: round(v / total_ratio, 3) for k, v in attack_ratios.items()}

    print(f"\nGeneration Blueprint (attack_type_ratios):")
    for atype, ratio in sorted(attack_ratios.items(), key=lambda x: -x[1]):
        print(f"  {atype:>18s}: {ratio:.3f}")

    # Save attack_type_ratios.json
    ratios_path = Path("data/synthetic/attack_type_ratios.json")
    ratios_path.parent.mkdir(parents=True, exist_ok=True)
    ratios_path.write_text(json.dumps(attack_ratios, indent=2))
    print(f"\n[OK] Saved {ratios_path}")

    # Export csic_test_sample.jsonl — balanced subset for evaluation
    random.seed(42)
    export_entries = []

    # Sample normal entries
    normal_sample = random.sample(normal, min(250, len(normal)))
    for r in normal_sample:
        url = r.get("URL", "") or ""
        # Extract path from URL (remove http://localhost:8080 prefix)
        path = re.sub(r"^https?://[^/]+", "", url.split(" HTTP")[0])
        query = ""
        if "?" in path:
            path, query = path.split("?", 1)

        export_entries.append({
            "method": r.get("Method", "GET"),
            "path": path or "/",
            "query": query,
            "user_agent": r.get("User-Agent", ""),
            "attack_type": "normal",
            "label": 0,
            "source": "csic2010",
        })

    # Sample anomalous entries (stratified by attack type)
    for atype in ["sqli", "xss", "path_traversal", "lfi", "dir_scan"]:
        type_entries = [e for e in classified_entries if e["attack_type"] == atype]
        sample_size = min(50, len(type_entries))
        if sample_size > 0:
            sample = random.sample(type_entries, sample_size)
            for e in sample:
                url = e["url"]
                path = re.sub(r"^https?://[^/]+", "", url.split(" HTTP")[0])
                query = ""
                if "?" in path:
                    path, query = path.split("?", 1)

                export_entries.append({
                    "method": e["method"],
                    "path": path or "/",
                    "query": query,
                    "content": e["content"],
                    "user_agent": e["user_agent"],
                    "attack_type": atype,
                    "label": 1,
                    "source": "csic2010",
                })

    random.shuffle(export_entries)

    csic_test_path = Path("data/csic2010/csic_test_sample.jsonl")
    csic_test_path.write_text(
        "\n".join(json.dumps(e, ensure_ascii=False) for e in export_entries)
    )
    print(f"[OK] Saved {csic_test_path} ({len(export_entries)} entries)")

    # Summary
    test_counts = Counter(e["attack_type"] for e in export_entries)
    print(f"\nTest sample distribution:")
    for atype, count in sorted(test_counts.items(), key=lambda x: -x[1]):
        print(f"  {atype:>18s}: {count:>4d}")

    print(f"\n[OK] Task 2.0 complete!")


if __name__ == "__main__":
    main()
