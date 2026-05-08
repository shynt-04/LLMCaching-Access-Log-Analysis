"""
Diagnose why full pipeline recall drops vs content-only model.
Analyzes score distribution through each pipeline stage.
"""
import json, pickle, sys, os
import numpy as np
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from src.ingestion.schema import NormalizedLog
from src.detection.rule_based.detector import RuleDetector
from src.detection.ml.detector import MLDetector
from src.detection.temporal_buffer import TemporalBuffer
from src.detection.merger import merge, should_flag
from src.config import CONTENT_WEIGHT, BEHAVIOR_WEIGHT, RULE_WEIGHT, ALERT_THRESHOLD


def load_test(path="data/synthetic/test.jsonl"):
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def entry_to_log(e):
    return NormalizedLog(
        timestamp=datetime.now(),
        source_ip=e.get("ip", "0.0.0.0"),
        method=e.get("method", "GET"),
        path=e.get("path", "/"),
        status_code=e.get("status", 200),
        source="synthetic",
        query_string=e.get("query", "") or None,
        user_agent=e.get("user_agent", ""),
    )


def main():
    entries = load_test()
    print(f"Total entries: {len(entries)}")

    # Load content model for standalone scoring
    with open("data/models/lgbm_content.pkl", "rb") as f:
        c = pickle.load(f)
    content_model = c["model"]
    vectorizer = c["vectorizer"]

    ml = MLDetector()
    rules = RuleDetector()
    buffer = TemporalBuffer()

    # Track per-entry scores
    results = []

    for e in entries:
        log = entry_to_log(e)
        true_label = 1 if e.get("label", 0) > 0 else 0
        attack_type = e.get("attack_type", "normal")

        # 1. Content-only score (standalone)
        text = f"{e.get('path', '')} {e.get('query', '')} {e.get('user_agent', '')[:100]}"
        X = vectorizer.transform([text])
        probs = content_model.predict_proba(X)[0]
        content_standalone = float(1.0 - probs[0])

        # 2. Rule score
        r = rules.detect(log)
        rule_score = r.max_score
        log.rule_score = rule_score

        # 3. ML scores through pipeline
        window = buffer.add(log)
        cs, bs = ml.score(log, window, rule_score)
        temporal_mult = buffer.multiplier(log.source_ip)
        merged = merge(rule_score, cs, bs, temporal_mult)

        # Content-only decision (standalone, threshold 0.5)
        content_pred = 1 if content_standalone >= 0.5 else 0
        pipeline_pred = 1 if should_flag(merged) else 0

        results.append({
            "true": true_label,
            "type": attack_type,
            "content_standalone": content_standalone,
            "content_pred": content_pred,
            "rule_score": rule_score,
            "content_score_pipeline": cs,
            "behavior_score": bs,
            "temporal_mult": temporal_mult,
            "merged": merged,
            "pipeline_pred": pipeline_pred,
            "path": e.get("path", ""),
            "query": e.get("query", "")[:80],
        })

    # === Analysis ===
    print("\n" + "=" * 70)
    print("  DIAGNOSIS: Why Pipeline Recall < Content-Only Recall")
    print("=" * 70)

    # Find entries that content-only gets right but pipeline gets wrong
    content_right_pipeline_wrong = [
        r for r in results
        if r["true"] == 1 and r["content_pred"] == 1 and r["pipeline_pred"] == 0
    ]
    content_wrong = [
        r for r in results
        if r["true"] == 1 and r["content_pred"] == 0
    ]
    pipeline_wrong = [
        r for r in results
        if r["true"] == 1 and r["pipeline_pred"] == 0
    ]

    print(f"\n  Attacks missed by content-only:   {len(content_wrong)}")
    print(f"  Attacks missed by pipeline:       {len(pipeline_wrong)}")
    print(f"  Content catches but pipeline drops: {len(content_right_pipeline_wrong)}")

    # Analyze WHY pipeline drops them
    if content_right_pipeline_wrong:
        print(f"\n  --- Analysis of {len(content_right_pipeline_wrong)} entries pipeline drops ---")
        
        # Score statistics
        cs_scores = [r["content_standalone"] for r in content_right_pipeline_wrong]
        cs_pipe = [r["content_score_pipeline"] for r in content_right_pipeline_wrong]
        bs_scores = [r["behavior_score"] for r in content_right_pipeline_wrong]
        rs_scores = [r["rule_score"] for r in content_right_pipeline_wrong]
        ms = [r["merged"] for r in content_right_pipeline_wrong]
        tm = [r["temporal_mult"] for r in content_right_pipeline_wrong]

        print(f"\n  Content standalone score: mean={np.mean(cs_scores):.4f}, min={np.min(cs_scores):.4f}")
        print(f"  Content pipeline score:  mean={np.mean(cs_pipe):.4f}, min={np.min(cs_pipe):.4f}")
        print(f"  Behavior score:          mean={np.mean(bs_scores):.4f}, min={np.min(bs_scores):.4f}")
        print(f"  Rule score:              mean={np.mean(rs_scores):.4f}, min={np.min(rs_scores):.4f}")
        print(f"  Temporal multiplier:     mean={np.mean(tm):.4f}, min={np.min(tm):.4f}")
        print(f"  Merged score:            mean={np.mean(ms):.4f}, max={np.max(ms):.4f}")
        print(f"  Alert threshold:         {ALERT_THRESHOLD}")

        # Show how merging dilutes the score
        print(f"\n  --- Score dilution analysis ---")
        print(f"  Weights: content={CONTENT_WEIGHT}, behavior={BEHAVIOR_WEIGHT}, rule={RULE_WEIGHT}")
        print(f"  Threshold: {ALERT_THRESHOLD}")
        print(f"  For merged to reach {ALERT_THRESHOLD} with temporal_mult=1.0:")
        print(f"    If rule=0, behavior=0: content needs >= {ALERT_THRESHOLD / CONTENT_WEIGHT:.4f}")
        print(f"    If rule=0, behavior=0.5: content needs >= {(ALERT_THRESHOLD - BEHAVIOR_WEIGHT * 0.5) / CONTENT_WEIGHT:.4f}")

        # Per-attack-type breakdown
        type_counts = Counter(r["type"] for r in content_right_pipeline_wrong)
        print(f"\n  Per-type breakdown (content catches, pipeline drops):")
        for atype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            subset = [r for r in content_right_pipeline_wrong if r["type"] == atype]
            avg_cs = np.mean([r["content_standalone"] for r in subset])
            avg_bs = np.mean([r["behavior_score"] for r in subset])
            avg_rs = np.mean([r["rule_score"] for r in subset])
            avg_ms = np.mean([r["merged"] for r in subset])
            print(f"    {atype:>18s}: {count:>3d} lost | cs={avg_cs:.3f} bs={avg_bs:.3f} rs={avg_rs:.3f} merged={avg_ms:.3f}")

    # Check for content model overfitting signals
    print(f"\n{'=' * 70}")
    print(f"  OVERFITTING ANALYSIS")
    print(f"{'=' * 70}")

    # Content model score distribution on attacks
    attack_results = [r for r in results if r["true"] == 1]
    normal_results = [r for r in results if r["true"] == 0]

    attack_cs = [r["content_standalone"] for r in attack_results]
    normal_cs = [r["content_standalone"] for r in normal_results]

    print(f"\n  Content standalone score distribution:")
    print(f"    Attacks:  mean={np.mean(attack_cs):.4f}, std={np.std(attack_cs):.4f}, min={np.min(attack_cs):.4f}")
    print(f"    Normals:  mean={np.mean(normal_cs):.4f}, std={np.std(normal_cs):.4f}, max={np.max(normal_cs):.4f}")

    # Check for suspiciously high confidence
    extreme_high = sum(1 for s in attack_cs if s > 0.99)
    extreme_low = sum(1 for s in normal_cs if s < 0.01)
    print(f"\n  Suspiciously extreme confidence:")
    print(f"    Attacks with P(attack) > 0.99:  {extreme_high}/{len(attack_cs)} ({extreme_high/len(attack_cs):.1%})")
    print(f"    Normals with P(attack) < 0.01:  {extreme_low}/{len(normal_cs)} ({extreme_low/len(normal_cs):.1%})")

    # Check content score vs pipeline content score difference
    print(f"\n  Content standalone vs pipeline content score (for attacks):")
    diffs = [abs(r["content_standalone"] - r["content_score_pipeline"]) for r in attack_results]
    print(f"    Max diff: {max(diffs):.6f}")
    print(f"    Mean diff: {np.mean(diffs):.6f}")
    if max(diffs) < 0.0001:
        print(f"    ==> Content scores are IDENTICAL through both paths.")

    # Show some example FN from pipeline
    print(f"\n  --- Example False Negatives (pipeline misses, content catches) ---")
    for r in content_right_pipeline_wrong[:10]:
        print(f"    [{r['type']:>15s}] cs={r['content_standalone']:.3f} bs={r['behavior_score']:.3f} rs={r['rule_score']:.3f} merged={r['merged']:.3f} | {r['path'][:50]}")


if __name__ == "__main__":
    main()
