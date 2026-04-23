#!/usr/bin/env python3
"""
SyscallGuard — Cosine Similarity Engine
=========================================
Computes cosine similarity on syscall frequency vectors to detect
magnitude-based behavioral changes that Jaccard misses.
"""

import json
import math
import sys
import os
from datetime import datetime, timezone
from pathlib import Path


def cosine_similarity(vec_a: list, vec_b: list) -> float:
    """Compute cosine similarity between two vectors. Returns [0.0, 1.0]."""
    if not vec_a or not vec_b:
        return 1.0 if (not vec_a and not vec_b) else 0.0
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    mag_a = math.sqrt(sum(a**2 for a in vec_a))
    mag_b = math.sqrt(sum(b**2 for b in vec_b))
    if mag_a == 0 and mag_b == 0:
        return 1.0
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


def build_frequency_vectors(current_counts: dict, baseline_counts: dict) -> tuple:
    """Build aligned frequency vectors over the union of all syscalls."""
    all_sc = sorted(set(current_counts.keys()) | set(baseline_counts.keys()))
    cur = [current_counts.get(s, 0) for s in all_sc]
    base = [baseline_counts.get(s, 0) for s in all_sc]
    return cur, base, all_sc


def compute_profile_cosine(current_profile: dict, baseline_profile: dict) -> dict:
    """Full cosine similarity analysis between two profiles."""
    cur_counts = current_profile.get("syscall_counts", {})
    base_counts = baseline_profile.get("syscall_counts", {})
    cur_vec, base_vec, labels = build_frequency_vectors(cur_counts, base_counts)

    overall = cosine_similarity(cur_vec, base_vec)
    log_cur = [math.log1p(v) for v in cur_vec]
    log_base = [math.log1p(v) for v in base_vec]
    log_cos = cosine_similarity(log_cur, log_base)

    divergence = []
    for i, sc in enumerate(labels):
        if cur_vec[i] != base_vec[i]:
            divergence.append({"syscall": sc, "current": cur_vec[i],
                               "baseline": base_vec[i],
                               "abs_diff": abs(cur_vec[i] - base_vec[i])})
    divergence.sort(key=lambda d: d["abs_diff"], reverse=True)

    return {
        "version": "1.0",
        "generator": "syscallguard-cosine-engine",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cosine_similarity": round(overall, 6),
        "cosine_percentage": f"{overall * 100:.2f}%",
        "log_cosine_similarity": round(log_cos, 6),
        "log_cosine_percentage": f"{log_cos * 100:.2f}%",
        "vector_dimensions": len(labels),
        "top_divergence_contributors": divergence[:10],
    }


def format_cosine_summary(report: dict) -> str:
    """Format human-readable cosine similarity report."""
    lines = []
    cosine = report["cosine_similarity"]
    if cosine >= 0.99:
        emoji, label = "🟢", "NEAR IDENTICAL"
    elif cosine >= 0.95:
        emoji, label = "🟡", "MINOR VARIATION"
    elif cosine >= 0.85:
        emoji, label = "🟠", "SIGNIFICANT VARIATION"
    else:
        emoji, label = "🔴", "MAJOR DIVERGENCE"

    lines.append(f"{'='*60}")
    lines.append(f"  SyscallGuard — Cosine Similarity Analysis")
    lines.append(f"{'='*60}")
    lines.append(f"  {emoji} Cosine Similarity: {report['cosine_percentage']} ({label})")
    lines.append(f"     Log-scaled Cosine:  {report['log_cosine_percentage']}")
    lines.append(f"     Vector dimensions:  {report['vector_dimensions']} syscalls")
    lines.append("")
    if report["top_divergence_contributors"]:
        lines.append(f"  📊 Top Divergence Contributors:")
        for d in report["top_divergence_contributors"][:5]:
            lines.append(f"    {d['syscall']:25s} {d['baseline']:>8,} → {d['current']:>8,} (Δ {d['abs_diff']:>+,})")
    lines.append(f"{'='*60}")
    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SyscallGuard: Cosine similarity engine")
    parser.add_argument("current", help="Current profile JSON")
    parser.add_argument("baseline", help="Baseline profile JSON")
    parser.add_argument("--output", default=None, help="Output JSON report path")
    args = parser.parse_args()

    with open(args.current) as f:
        current = json.load(f)
    with open(args.baseline) as f:
        baseline = json.load(f)

    report = compute_profile_cosine(current, baseline)
    print(format_cosine_summary(report))

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n📄 Cosine report written to: {args.output}")


if __name__ == "__main__":
    main()
