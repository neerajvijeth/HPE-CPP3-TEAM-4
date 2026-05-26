#!/usr/bin/env python3
"""
SyscallGuard — Frequency Anomaly Detector
==========================================
Detects frequency-based anomalies that set-based Jaccard analysis misses.

A compromised dependency might not add NEW syscalls — it could abuse
EXISTING ones. For example:
  - socket: 45 → 45,000 calls  (data exfiltration)
  - openat: 3,456 → 50,000     (reading sensitive files)
  - write: 8,721 → 200,000     (writing malware payload)

This module catches those attacks by computing z-score-like ratios
between current and baseline frequency vectors.

Usage:
    python frequency_analyzer.py <current_profile.json> <baseline_profile.json> [--z-threshold 3.0]
"""

import json
import math
import sys
import os
from datetime import datetime, timezone
from pathlib import Path


def load_taxonomy(taxonomy_path: str = None) -> dict:
    """Load the syscall danger tier taxonomy."""
    if taxonomy_path is None:
        taxonomy_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "syscall_taxonomy.json"
        )
    with open(taxonomy_path, 'r') as f:
        return json.load(f)


def classify_syscall_tier(syscall: str, taxonomy: dict) -> int:
    """Return the danger tier (1, 2, 3, or 0 for unknown) of a syscall."""
    tier1 = set(taxonomy.get("tier1_critical", {}).get("syscalls", []))
    tier2 = set(taxonomy.get("tier2_suspicious", {}).get("syscalls", []))
    tier3 = set(taxonomy.get("tier3_benign", {}).get("syscalls", []))

    if syscall in tier1:
        return 1
    elif syscall in tier2:
        return 2
    elif syscall in tier3:
        return 3
    return 0


def detect_frequency_anomalies(
    current_counts: dict,
    baseline_counts: dict,
    z_threshold: float = 3.0,
    taxonomy: dict = None
) -> list:
    """
    Detect syscalls whose invocation frequency deviates significantly
    between the current and baseline profiles.

    A spike ratio > z_threshold or < 1/z_threshold is flagged.

    Args:
        current_counts: dict of {syscall: count} for current run
        baseline_counts: dict of {syscall: count} for baseline
        z_threshold: multiplier threshold for flagging (default 3.0)
        taxonomy: optional taxonomy for tier classification

    Returns:
        list of anomaly dicts sorted by absolute ratio (most extreme first)
    """
    anomalies = []

    for syscall, current_count in current_counts.items():
        baseline_count = baseline_counts.get(syscall, 0)

        # Skip syscalls not in baseline (those are handled by Jaccard novel detection)
        if baseline_count == 0:
            continue

        ratio = current_count / baseline_count

        if ratio > z_threshold or ratio < (1 / z_threshold):
            anomaly = {
                "syscall": syscall,
                "baseline_count": baseline_count,
                "current_count": current_count,
                "ratio": round(ratio, 2),
                "direction": "SPIKE" if ratio > 1 else "DROP",
                "severity": _classify_severity(ratio, z_threshold),
            }

            # Add tier info if taxonomy provided
            if taxonomy:
                anomaly["tier"] = classify_syscall_tier(syscall, taxonomy)

            anomalies.append(anomaly)

    # Sort by absolute ratio magnitude (most extreme first)
    anomalies.sort(key=lambda a: abs(a["ratio"] - 1), reverse=True)
    return anomalies


def _classify_severity(ratio: float, z_threshold: float) -> str:
    """Classify the severity of a frequency anomaly."""
    magnitude = max(ratio, 1 / ratio) if ratio > 0 else float('inf')

    if magnitude >= z_threshold * 10:
        return "CRITICAL"
    elif magnitude >= z_threshold * 3:
        return "HIGH"
    elif magnitude >= z_threshold:
        return "MEDIUM"
    return "LOW"


def compute_frequency_risk_score(anomalies: list) -> int:
    """
    Compute a weighted risk score from frequency anomalies.

    Scoring:
      - CRITICAL severity: +15 per anomaly
      - HIGH severity: +8
      - MEDIUM severity: +3
      - Tier 1 syscall bonus: +10
      - SPIKE direction bonus: +2 (spikes are more dangerous than drops)
    """
    severity_weights = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 3, "LOW": 1}
    score = 0

    for anomaly in anomalies:
        score += severity_weights.get(anomaly["severity"], 1)

        # Tier 1 syscalls get extra weight
        if anomaly.get("tier") == 1:
            score += 10

        # Spikes are more concerning than drops
        if anomaly["direction"] == "SPIKE":
            score += 2

    return score


def analyze_frequencies(
    current_profile: dict,
    baseline_profile: dict,
    z_threshold: float = 3.0,
    taxonomy: dict = None
) -> dict:
    """
    Full frequency analysis between current and baseline profiles.

    Returns:
        dict: Full frequency anomaly report
    """
    current_counts = current_profile.get("syscall_counts", {})
    baseline_counts = baseline_profile.get("syscall_counts", {})

    anomalies = detect_frequency_anomalies(
        current_counts, baseline_counts, z_threshold, taxonomy
    )

    freq_risk_score = compute_frequency_risk_score(anomalies)

    # Compute overall frequency correlation
    common_syscalls = set(current_counts.keys()) & set(baseline_counts.keys())
    total_deviation = 0
    for sc in common_syscalls:
        if baseline_counts[sc] > 0:
            total_deviation += abs(current_counts[sc] / baseline_counts[sc] - 1)
    avg_deviation = total_deviation / len(common_syscalls) if common_syscalls else 0

    report = {
        "version": "1.0",
        "generator": "syscallguard-frequency-analyzer",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "z_threshold": z_threshold,
        "total_common_syscalls": len(common_syscalls),
        "anomalies_detected": len(anomalies),
        "frequency_risk_score": freq_risk_score,
        "average_deviation": round(avg_deviation, 4),
        "spike_count": sum(1 for a in anomalies if a["direction"] == "SPIKE"),
        "drop_count": sum(1 for a in anomalies if a["direction"] == "DROP"),
        "anomalies": anomalies,
    }

    return report


def format_frequency_summary(report: dict) -> str:
    """Format a human-readable frequency anomaly report."""
    lines = []

    lines.append(f"{'='*60}")
    lines.append(f"  SyscallGuard — Frequency Anomaly Analysis")
    lines.append(f"{'='*60}")
    lines.append("")

    count = report["anomalies_detected"]
    if count == 0:
        lines.append(f"  ✅ No frequency anomalies detected (z_threshold={report['z_threshold']})")
    else:
        emoji = "🚨" if report["frequency_risk_score"] > 10 else "⚠️"
        lines.append(f"  {emoji} {count} frequency anomalies detected!")
        lines.append(f"     Spikes: {report['spike_count']} | Drops: {report['drop_count']}")
        lines.append(f"     Frequency Risk Score: {report['frequency_risk_score']}")
        lines.append("")

        lines.append(f"  📋 Anomaly Details:")
        lines.append(f"  {'─'*50}")
        for a in report["anomalies"]:
            icon = "📈" if a["direction"] == "SPIKE" else "📉"
            tier_str = f" [Tier {a['tier']}]" if "tier" in a else ""
            lines.append(
                f"    {icon} {a['syscall']:25s} "
                f"{a['baseline_count']:>8,} → {a['current_count']:>8,} "
                f"({a['ratio']:.1f}× {a['direction']}) "
                f"[{a['severity']}]{tier_str}"
            )

    lines.append("")
    lines.append(f"  ℹ️  Average deviation across all common syscalls: "
                 f"{report['average_deviation']:.2%}")
    lines.append(f"{'='*60}")

    return "\n".join(lines)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="SyscallGuard: Detect frequency anomalies in syscall profiles"
    )
    parser.add_argument("current", help="Path to current syscall profile JSON")
    parser.add_argument("baseline", help="Path to baseline syscall profile JSON")
    parser.add_argument("--z-threshold", type=float, default=3.0,
                        help="Z-score multiplier threshold (default: 3.0)")
    parser.add_argument("--taxonomy", default=None,
                        help="Path to syscall taxonomy JSON")
    parser.add_argument("--output", default=None,
                        help="Path to write JSON frequency report")

    args = parser.parse_args()

    with open(args.current, 'r') as f:
        current = json.load(f)
    with open(args.baseline, 'r') as f:
        baseline = json.load(f)

    taxonomy = None
    if args.taxonomy:
        with open(args.taxonomy, 'r') as f:
            taxonomy = json.load(f)
    else:
        taxonomy = load_taxonomy()

    report = analyze_frequencies(current, baseline, args.z_threshold, taxonomy)

    print(format_frequency_summary(report))

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n📄 Frequency report written to: {args.output}")


if __name__ == "__main__":
    main()
