#!/usr/bin/env python3
"""
SyscallGuard — Cross-Profile Correlator
=========================================
Correlates pytest (app test) profile with dependency-exercise profile
to identify syscalls introduced by dependencies that tests don't cover.

This reveals UNTESTED ATTACK SURFACE — dependencies making syscalls
your test suite never exercises.

Usage:
    python cross_correlator.py <pytest_profile.json> <dep_profile.json> [--output report.json]
"""

import json
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


def classify_tier(syscall: str, taxonomy: dict) -> int:
    """Return danger tier for a syscall."""
    t1 = set(taxonomy.get("tier1_critical", {}).get("syscalls", []))
    t2 = set(taxonomy.get("tier2_suspicious", {}).get("syscalls", []))
    t3 = set(taxonomy.get("tier3_benign", {}).get("syscalls", []))
    if syscall in t1: return 1
    if syscall in t2: return 2
    if syscall in t3: return 3
    return 0


def cross_correlate(
    pytest_profile: dict,
    dep_profile: dict,
    taxonomy: dict = None
) -> dict:
    """
    Cross-correlate two profiles to find:
    1. dep_only: syscalls in dependency profile but NOT in pytest profile
       (untested attack surface)
    2. pytest_only: syscalls in pytest but NOT in dep profile
       (app-specific behavior)
    3. common: syscalls in both profiles
    """
    pytest_sc = set(pytest_profile.get("syscalls", []))
    dep_sc = set(dep_profile.get("syscalls", []))

    dep_only = dep_sc - pytest_sc
    pytest_only = pytest_sc - dep_sc
    common = pytest_sc & dep_sc

    # Classify dep-only syscalls by tier
    dep_only_classified = []
    untested_risk = 0
    for sc in sorted(dep_only):
        tier = classify_tier(sc, taxonomy) if taxonomy else 0
        weight = {1: 10, 2: 3, 3: 1, 0: 5}.get(tier, 5)
        dep_only_classified.append({
            "syscall": sc,
            "tier": tier,
            "risk_weight": weight,
        })
        untested_risk += weight

    # Classify pytest-only syscalls
    pytest_only_classified = []
    for sc in sorted(pytest_only):
        tier = classify_tier(sc, taxonomy) if taxonomy else 0
        pytest_only_classified.append({
            "syscall": sc,
            "tier": tier,
        })

    # Coverage metric: what % of dependency syscalls are tested?
    total_dep = len(dep_sc) if dep_sc else 0
    coverage = len(common) / total_dep * 100 if total_dep > 0 else 100.0

    report = {
        "version": "1.0",
        "generator": "syscallguard-cross-correlator",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pytest_unique_syscalls": len(pytest_sc),
        "dep_unique_syscalls": len(dep_sc),
        "common_syscalls": len(common),
        "dep_only_count": len(dep_only),
        "pytest_only_count": len(pytest_only),
        "dependency_coverage": round(coverage, 2),
        "untested_risk_score": untested_risk,
        "dep_only_syscalls": dep_only_classified,
        "pytest_only_syscalls": pytest_only_classified,
        "common_syscall_list": sorted(common),
    }

    return report


def format_correlation_summary(report: dict) -> str:
    """Format human-readable cross-correlation report."""
    lines = []
    lines.append(f"{'='*60}")
    lines.append(f"  SyscallGuard — Cross-Profile Correlation")
    lines.append(f"{'='*60}")
    lines.append("")

    cov = report["dependency_coverage"]
    if cov >= 90:
        emoji = "🟢"
    elif cov >= 70:
        emoji = "🟡"
    else:
        emoji = "🔴"

    lines.append(f"  {emoji} Dependency Coverage: {cov:.1f}%")
    lines.append(f"     Pytest profile:  {report['pytest_unique_syscalls']} syscalls")
    lines.append(f"     Dep profile:     {report['dep_unique_syscalls']} syscalls")
    lines.append(f"     Common:          {report['common_syscalls']} syscalls")
    lines.append("")

    if report["dep_only_syscalls"]:
        lines.append(f"  ⚠️  UNTESTED Dependency Syscalls ({report['dep_only_count']}):")
        lines.append(f"  {'─'*50}")
        for s in report["dep_only_syscalls"]:
            tier_icon = {1: "🔴", 2: "🟡", 3: "🟢"}.get(s["tier"], "⚪")
            lines.append(f"    {tier_icon} {s['syscall']:25s} Tier {s['tier']} [+{s['risk_weight']} risk]")
        lines.append("")
        lines.append(f"  Untested Risk Score: {report['untested_risk_score']}")
    else:
        lines.append(f"  ✅ All dependency syscalls are covered by tests")

    lines.append(f"{'='*60}")
    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="SyscallGuard: Cross-correlate pytest and dependency profiles"
    )
    parser.add_argument("pytest_profile", help="Path to pytest profile JSON")
    parser.add_argument("dep_profile", help="Path to dependency profile JSON")
    parser.add_argument("--taxonomy", default=None, help="Path to taxonomy JSON")
    parser.add_argument("--output", default=None, help="Output JSON path")
    args = parser.parse_args()

    with open(args.pytest_profile) as f:
        pytest_prof = json.load(f)
    with open(args.dep_profile) as f:
        dep_prof = json.load(f)

    taxonomy = load_taxonomy(args.taxonomy)
    report = cross_correlate(pytest_prof, dep_prof, taxonomy)
    print(format_correlation_summary(report))

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n📄 Correlation report written to: {args.output}")


if __name__ == "__main__":
    main()
