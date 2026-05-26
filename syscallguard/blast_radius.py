#!/usr/bin/env python3
"""
SyscallGuard — Blast Radius Containment Score Calculator
=========================================================
Computes what percentage of known exploit techniques are blocked
by the application's syscall profile.

The idea: if your app only uses 42 out of ~300 syscalls, most exploit
techniques that require dangerous syscalls (ptrace, execve, socket, etc.)
are inherently blocked. This metric quantifies that protection.

Usage:
    python blast_radius.py <profile.json> [--taxonomy syscall_taxonomy.json] [--output blast_report.json]
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
        return json.load(f)


def compute_blast_radius(profile: dict, taxonomy: dict) -> dict:
    """
    Compute the blast radius containment score.

    For each exploit technique in the taxonomy, check if ANY of its
    required syscalls are present in the application profile. If ALL
    required syscalls for a technique are absent, that technique is
    fully blocked.

    The containment score is:
        (blocked_exploit_syscalls / total_exploit_syscalls) × 100

    Args:
        profile: Application syscall profile dict
        taxonomy: Syscall taxonomy dict with exploit_techniques

    Returns:
        dict: Blast radius report with per-technique breakdown
    """
    app_syscalls = set(profile.get("syscalls", []))
    techniques = taxonomy.get("exploit_techniques", {}).get("techniques", {})

    # Collect all unique exploit-critical syscalls
    all_exploit_syscalls = set()
    technique_results = []

    for tech_name, tech_data in techniques.items():
        required = set(tech_data.get("required_syscalls", []))
        all_exploit_syscalls.update(required)

        # Which required syscalls are present in the app?
        present = required & app_syscalls
        absent = required - app_syscalls

        # A technique is "blocked" if NONE of its required syscalls are available
        # A technique is "partially exposed" if some are present
        # A technique is "fully exposed" if all are present
        if len(present) == 0:
            status = "BLOCKED"
            exposure = 0.0
        elif len(present) == len(required):
            status = "FULLY_EXPOSED"
            exposure = 100.0
        else:
            status = "PARTIALLY_EXPOSED"
            exposure = (len(present) / len(required)) * 100.0

        technique_results.append({
            "technique": tech_name,
            "description": tech_data.get("description", ""),
            "required_syscalls": sorted(required),
            "present_in_profile": sorted(present),
            "absent_from_profile": sorted(absent),
            "status": status,
            "exposure_percentage": round(exposure, 1),
        })

    # Compute overall containment score
    blocked_exploit_syscalls = all_exploit_syscalls - app_syscalls
    present_exploit_syscalls = all_exploit_syscalls & app_syscalls

    total_exploit = len(all_exploit_syscalls)
    blocked_count = len(blocked_exploit_syscalls)

    containment_score = (blocked_count / total_exploit * 100) if total_exploit > 0 else 100.0

    # Count technique statuses
    techniques_blocked = sum(1 for t in technique_results if t["status"] == "BLOCKED")
    techniques_partial = sum(1 for t in technique_results if t["status"] == "PARTIALLY_EXPOSED")
    techniques_exposed = sum(1 for t in technique_results if t["status"] == "FULLY_EXPOSED")

    report = {
        "version": "1.0",
        "generator": "syscallguard-blast-radius",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "profile_source": profile.get("source", "unknown"),
        "profile_version": profile.get("app_version", "unknown"),
        "containment_score": round(containment_score, 2),
        "total_exploit_syscalls": total_exploit,
        "blocked_exploit_syscalls": blocked_count,
        "present_exploit_syscalls": len(present_exploit_syscalls),
        "total_techniques": len(technique_results),
        "techniques_fully_blocked": techniques_blocked,
        "techniques_partially_exposed": techniques_partial,
        "techniques_fully_exposed": techniques_exposed,
        "blocked_exploit_syscall_list": sorted(blocked_exploit_syscalls),
        "present_exploit_syscall_list": sorted(present_exploit_syscalls),
        "technique_breakdown": technique_results,
    }

    return report


def format_blast_radius_summary(report: dict) -> str:
    """Format a human-readable blast radius report for terminal output."""
    lines = []
    score = report["containment_score"]

    if score >= 85:
        score_emoji = "🟢"
        score_label = "EXCELLENT"
    elif score >= 60:
        score_emoji = "🟡"
        score_label = "MODERATE"
    else:
        score_emoji = "🔴"
        score_label = "LOW"

    lines.append(f"{'='*60}")
    lines.append(f"  SyscallGuard — Blast Radius Containment Report")
    lines.append(f"{'='*60}")
    lines.append("")
    lines.append(f"  {score_emoji} Containment Score: {score:.1f}% ({score_label})")
    lines.append(f"     Exploit-critical syscalls blocked: {report['blocked_exploit_syscalls']}/{report['total_exploit_syscalls']}")
    lines.append(f"     Exploit-critical syscalls present: {report['present_exploit_syscalls']}/{report['total_exploit_syscalls']}")
    lines.append("")

    lines.append(f"  📊 Technique Breakdown:")
    lines.append(f"  {'─'*50}")

    for tech in report["technique_breakdown"]:
        if tech["status"] == "BLOCKED":
            icon = "🛡️"
        elif tech["status"] == "PARTIALLY_EXPOSED":
            icon = "⚠️"
        else:
            icon = "🔓"

        name = tech["technique"].replace("_", " ").title()
        lines.append(f"    {icon} {name:30s} {tech['status']:20s} ({tech['exposure_percentage']:.0f}% exposed)")

        if tech["present_in_profile"]:
            lines.append(f"       Present: {', '.join(tech['present_in_profile'])}")
        if tech["absent_from_profile"] and tech["status"] != "BLOCKED":
            lines.append(f"       Absent:  {', '.join(tech['absent_from_profile'])}")

    lines.append("")

    if report["present_exploit_syscall_list"]:
        lines.append(f"  ⚠️  Exploit syscalls in app profile:")
        for sc in report["present_exploit_syscall_list"]:
            lines.append(f"       • {sc}")
        lines.append("")

    lines.append(f"  ℹ️  The containment score measures what percentage of")
    lines.append(f"     known exploit technique syscalls are NOT present in")
    lines.append(f"     the application's syscall profile. Higher = better.")
    lines.append(f"{'='*60}")

    return "\n".join(lines)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="SyscallGuard: Compute blast radius containment score"
    )
    parser.add_argument("profile", help="Path to syscall profile JSON")
    parser.add_argument("--taxonomy", default=None,
                        help="Path to syscall taxonomy JSON")
    parser.add_argument("--output", default=None,
                        help="Path to write JSON blast radius report")

    args = parser.parse_args()

    # Load profile
    with open(args.profile, 'r') as f:
        profile = json.load(f)

    # Load taxonomy
    taxonomy = load_taxonomy(args.taxonomy)

    # Compute blast radius
    report = compute_blast_radius(profile, taxonomy)

    # Print summary
    print(format_blast_radius_summary(report))

    # Write JSON report
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n📄 JSON report written to: {args.output}")


if __name__ == "__main__":
    main()
