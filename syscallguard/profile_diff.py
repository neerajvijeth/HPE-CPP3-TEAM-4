#!/usr/bin/env python3
"""
SyscallGuard — Jaccard Similarity Diff Engine
===============================================
Compares two syscall profiles and computes:
  1. Jaccard similarity score (set overlap metric)
  2. Novel syscalls (present in current but not baseline)
  3. Removed syscalls (present in baseline but not current)
  4. Danger-tier classification of novel syscalls
  5. Weighted risk score with configurable threshold

This is the CORE NOVELTY of the SyscallGuard research — treating
syscall profile deltas as a first-class supply chain attack signal.

Usage:
    python profile_diff.py <current_profile.json> <baseline_profile.json> [--threshold 10] [--output report.json]
"""

import json
import sys
import os
from pathlib import Path
from datetime import datetime, timezone


def load_taxonomy(taxonomy_path: str = None) -> dict:
    """Load the syscall danger tier taxonomy."""
    if taxonomy_path is None:
        taxonomy_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "syscall_taxonomy.json"
        )

    with open(taxonomy_path, 'r') as f:
        taxonomy = json.load(f)

    return taxonomy


def classify_syscall(syscall: str, taxonomy: dict) -> dict:
    """
    Classify a syscall into its danger tier.

    Returns:
        dict with keys: tier (1/2/3/0), tier_name, weight, description
    """
    tier1 = set(taxonomy.get("tier1_critical", {}).get("syscalls", []))
    tier2 = set(taxonomy.get("tier2_suspicious", {}).get("syscalls", []))
    tier3 = set(taxonomy.get("tier3_benign", {}).get("syscalls", []))

    if syscall in tier1:
        return {
            "tier": 1,
            "tier_name": "CRITICAL",
            "weight": 10,
            "description": taxonomy["tier1_critical"]["description"]
        }
    elif syscall in tier2:
        return {
            "tier": 2,
            "tier_name": "SUSPICIOUS",
            "weight": 3,
            "description": taxonomy["tier2_suspicious"]["description"]
        }
    elif syscall in tier3:
        return {
            "tier": 3,
            "tier_name": "BENIGN",
            "weight": 1,
            "description": taxonomy["tier3_benign"]["description"]
        }
    else:
        return {
            "tier": 0,
            "tier_name": "UNKNOWN",
            "weight": 5,
            "description": "Syscall not in taxonomy — treated as suspicious by default"
        }


def compute_jaccard(set_a: set, set_b: set) -> float:
    """
    Compute Jaccard similarity coefficient between two sets.

    J(A,B) = |A ∩ B| / |A ∪ B|

    Returns:
        float: Jaccard similarity [0.0, 1.0]. Returns 1.0 if both sets are empty.
    """
    if not set_a and not set_b:
        return 1.0

    intersection = set_a & set_b
    union = set_a | set_b

    return len(intersection) / len(union)


def diff_profiles(
    current_profile: dict,
    baseline_profile: dict,
    taxonomy: dict,
    threshold: int = 10
) -> dict:
    """
    Compare current and baseline syscall profiles.

    Args:
        current_profile: Current run's syscall profile dict
        baseline_profile: Previous baseline syscall profile dict
        taxonomy: Syscall danger tier taxonomy dict
        threshold: Risk score threshold to flag as FAIL

    Returns:
        dict: Full diff report including Jaccard score, novel syscalls,
              risk assessment, and pass/fail verdict
    """
    current_syscalls = set(current_profile.get("syscalls", []))
    baseline_syscalls = set(baseline_profile.get("syscalls", []))

    # Core metrics
    jaccard_score = compute_jaccard(current_syscalls, baseline_syscalls)
    novel_syscalls = current_syscalls - baseline_syscalls
    removed_syscalls = baseline_syscalls - current_syscalls
    common_syscalls = current_syscalls & baseline_syscalls

    # Classify novel syscalls by danger tier
    novel_classified = []
    tier_counts = {"tier1": 0, "tier2": 0, "tier3": 0, "unknown": 0}
    risk_score = 0

    for syscall in sorted(novel_syscalls):
        classification = classify_syscall(syscall, taxonomy)
        entry = {
            "syscall": syscall,
            **classification
        }
        novel_classified.append(entry)
        risk_score += classification["weight"]

        if classification["tier"] == 1:
            tier_counts["tier1"] += 1
        elif classification["tier"] == 2:
            tier_counts["tier2"] += 1
        elif classification["tier"] == 3:
            tier_counts["tier3"] += 1
        else:
            tier_counts["unknown"] += 1

    # Determine verdict
    verdict = "PASS" if risk_score <= threshold else "FAIL"

    report = {
        "version": "1.0",
        "generator": "syscallguard-diff",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "comparison": {
            "current_source": current_profile.get("source", "unknown"),
            "current_version": current_profile.get("app_version", "unknown"),
            "current_req_hash": current_profile.get("requirements_hash", "unknown"),
            "baseline_version": baseline_profile.get("app_version", "unknown"),
            "baseline_req_hash": baseline_profile.get("requirements_hash", "unknown"),
        },
        "metrics": {
            "jaccard_similarity": round(jaccard_score, 6),
            "jaccard_percentage": f"{jaccard_score * 100:.2f}%",
            "current_unique_count": len(current_syscalls),
            "baseline_unique_count": len(baseline_syscalls),
            "common_count": len(common_syscalls),
            "novel_count": len(novel_syscalls),
            "removed_count": len(removed_syscalls),
        },
        "novel_syscalls": novel_classified,
        "removed_syscalls": sorted(removed_syscalls),
        "tier_summary": tier_counts,
        "risk_assessment": {
            "risk_score": risk_score,
            "threshold": threshold,
            "formula": "tier1×10 + tier2×3 + tier3×1 + unknown×5",
            "verdict": verdict,
        }
    }

    return report


def format_summary(report: dict) -> str:
    """
    Format a human-readable summary of the diff report.
    Suitable for terminal output and GitHub Step Summary.
    """
    lines = []
    metrics = report["metrics"]
    risk = report["risk_assessment"]
    tiers = report["tier_summary"]

    # Header
    verdict_emoji = "✅" if risk["verdict"] == "PASS" else "🚨"
    lines.append(f"{'='*60}")
    lines.append(f"  SyscallGuard — Behavioral Fingerprint Analysis")
    lines.append(f"{'='*60}")
    lines.append("")

    # Jaccard Score
    jaccard = metrics["jaccard_similarity"]
    if jaccard >= 0.95:
        jaccard_emoji = "🟢"
        jaccard_label = "STABLE"
    elif jaccard >= 0.80:
        jaccard_emoji = "🟡"
        jaccard_label = "MINOR DRIFT"
    else:
        jaccard_emoji = "🔴"
        jaccard_label = "SIGNIFICANT DRIFT"

    lines.append(f"  {jaccard_emoji} Jaccard Similarity: {metrics['jaccard_percentage']} ({jaccard_label})")
    lines.append(f"     Current profile:  {metrics['current_unique_count']} unique syscalls")
    lines.append(f"     Baseline profile: {metrics['baseline_unique_count']} unique syscalls")
    lines.append(f"     Common:           {metrics['common_count']} syscalls")
    lines.append(f"     Novel:            {metrics['novel_count']} syscalls")
    lines.append(f"     Removed:          {metrics['removed_count']} syscalls")
    lines.append("")

    # Novel syscalls breakdown
    if report["novel_syscalls"]:
        lines.append(f"  📋 Novel Syscalls Detected:")
        lines.append(f"  {'─'*50}")

        for entry in report["novel_syscalls"]:
            tier = entry["tier"]
            if tier == 1:
                icon = "🔴"
            elif tier == 2:
                icon = "🟡"
            elif tier == 3:
                icon = "🟢"
            else:
                icon = "⚪"

            lines.append(
                f"    {icon} {entry['syscall']:25s} "
                f"Tier {entry['tier']} ({entry['tier_name']}) "
                f"[+{entry['weight']} risk]"
            )
        lines.append("")

    # Tier summary
    lines.append(f"  📊 Tier Summary:")
    lines.append(f"     🔴 Tier 1 (CRITICAL):   {tiers['tier1']}")
    lines.append(f"     🟡 Tier 2 (SUSPICIOUS): {tiers['tier2']}")
    lines.append(f"     🟢 Tier 3 (BENIGN):     {tiers['tier3']}")
    lines.append(f"     ⚪ Unknown:              {tiers['unknown']}")
    lines.append("")

    # Risk verdict
    lines.append(f"  {verdict_emoji} Risk Score: {risk['risk_score']} / threshold {risk['threshold']}")
    lines.append(f"     Formula: {risk['formula']}")
    lines.append(f"     Verdict: {risk['verdict']}")
    lines.append("")

    if risk["verdict"] == "FAIL":
        lines.append(f"  🚨 SUPPLY CHAIN ANOMALY DETECTED!")
        lines.append(f"     The current profile contains novel syscalls that exceed")
        lines.append(f"     the risk threshold. This may indicate:")
        lines.append(f"       • A compromised dependency (supply chain attack)")
        lines.append(f"       • A dependency update with new capabilities")
        lines.append(f"       • A legitimate feature addition (review required)")
        lines.append("")

    lines.append(f"{'='*60}")

    return "\n".join(lines)


def format_github_summary(report: dict, blast_report: dict = None) -> str:
    """
    Format a GitHub Actions Step Summary (markdown) for the diff report.
    """
    lines = []
    metrics = report["metrics"]
    risk = report["risk_assessment"]
    tiers = report["tier_summary"]

    verdict_emoji = "✅" if risk["verdict"] == "PASS" else "🚨"

    lines.append(f"## 🛡️ SyscallGuard — Behavioral Fingerprint Analysis")
    lines.append("")

    # Jaccard
    jaccard = metrics["jaccard_similarity"]
    if jaccard >= 0.95:
        badge = "🟢 STABLE"
    elif jaccard >= 0.80:
        badge = "🟡 MINOR DRIFT"
    else:
        badge = "🔴 SIGNIFICANT DRIFT"

    lines.append(f"### Jaccard Similarity: `{metrics['jaccard_percentage']}` {badge}")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Current profile syscalls | {metrics['current_unique_count']} |")
    lines.append(f"| Baseline profile syscalls | {metrics['baseline_unique_count']} |")
    lines.append(f"| Common | {metrics['common_count']} |")
    lines.append(f"| **Novel (added)** | **{metrics['novel_count']}** |")
    lines.append(f"| Removed | {metrics['removed_count']} |")
    lines.append("")

    # Novel syscalls table
    if report["novel_syscalls"]:
        lines.append(f"### 📋 Novel Syscalls")
        lines.append("")
        lines.append(f"| Syscall | Tier | Classification | Risk Points |")
        lines.append(f"|---------|------|----------------|-------------|")
        for entry in report["novel_syscalls"]:
            tier = entry["tier"]
            icon = {"1": "🔴", "2": "🟡", "3": "🟢"}.get(str(tier), "⚪")
            lines.append(
                f"| `{entry['syscall']}` | {icon} Tier {tier} | "
                f"{entry['tier_name']} | +{entry['weight']} |"
            )
        lines.append("")

    # Risk verdict
    lines.append(f"### {verdict_emoji} Verdict: **{risk['verdict']}**")
    lines.append(f"- Risk Score: **{risk['risk_score']}** (threshold: {risk['threshold']})")
    lines.append(f"- Tier 1 (Critical): {tiers['tier1']} | Tier 2 (Suspicious): {tiers['tier2']} | Tier 3 (Benign): {tiers['tier3']}")
    lines.append("")

    # Blast radius section
    if blast_report:
        br = blast_report
        score = br.get("containment_score", 0)
        if score >= 85:
            br_badge = "🟢"
        elif score >= 60:
            br_badge = "🟡"
        else:
            br_badge = "🔴"

        lines.append(f"### 🛡️ Blast Radius Containment: `{score:.1f}%` {br_badge}")
        lines.append(f"- Exploit techniques blocked: {br.get('techniques_fully_blocked', 0)}/{br.get('total_techniques', 0)}")
        lines.append(f"- Exploit syscalls absent from profile: {br.get('blocked_exploit_syscalls', 0)}/{br.get('total_exploit_syscalls', 0)}")
        lines.append("")

    return "\n".join(lines)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="SyscallGuard: Compare syscall profiles for supply chain anomalies"
    )
    parser.add_argument("current", help="Path to current syscall profile JSON")
    parser.add_argument("baseline", help="Path to baseline syscall profile JSON")
    parser.add_argument("--threshold", type=int, default=10,
                        help="Risk score threshold for FAIL verdict (default: 10)")
    parser.add_argument("--output", default=None,
                        help="Path to write JSON diff report")
    parser.add_argument("--taxonomy", default=None,
                        help="Path to syscall taxonomy JSON")
    parser.add_argument("--github-summary", default=None,
                        help="Path to write GitHub Step Summary markdown")

    args = parser.parse_args()

    # Load profiles
    with open(args.current, 'r') as f:
        current_profile = json.load(f)
    with open(args.baseline, 'r') as f:
        baseline_profile = json.load(f)

    # Load taxonomy
    taxonomy = load_taxonomy(args.taxonomy)

    # Run diff
    report = diff_profiles(current_profile, baseline_profile, taxonomy, args.threshold)

    # Print human-readable summary
    print(format_summary(report))

    # Write JSON report
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n📄 JSON report written to: {args.output}")

    # Write GitHub summary
    if args.github_summary:
        with open(args.github_summary, 'w') as f:
            f.write(format_github_summary(report))
        print(f"📄 GitHub summary written to: {args.github_summary}")

    # Exit with appropriate code
    if report["risk_assessment"]["verdict"] == "FAIL":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
