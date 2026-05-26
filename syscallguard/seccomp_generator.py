#!/usr/bin/env python3
"""
SyscallGuard — Seccomp Profile Generator
==========================================
Auto-generates Linux seccomp (Secure Computing) profiles from a
syscall baseline. This turns detection into PREVENTION — the kernel
itself blocks disallowed syscalls at runtime.

Usage:
    python seccomp_generator.py <profile.json> [--output seccomp-profile.json] [--mode whitelist|audit]
"""

import json
import sys
import os
from datetime import datetime, timezone
from pathlib import Path


def generate_seccomp_profile(
    profile: dict,
    mode: str = "whitelist",
    extra_allow: list = None
) -> dict:
    """
    Generate a Docker/OCI-compatible seccomp profile from a syscall baseline.

    Args:
        profile: SyscallGuard profile with 'syscalls' list
        mode: 'whitelist' (block all except allowed) or 'audit' (log violations)
        extra_allow: additional syscalls to always allow (safety net)

    Returns:
        dict: OCI-compatible seccomp profile
    """
    allowed_syscalls = set(profile.get("syscalls", []))

    # Always allow essential syscalls for container runtime
    essential = {
        "exit", "exit_group", "rt_sigreturn", "restart_syscall",
        "sigreturn", "futex", "nanosleep", "clock_nanosleep",
    }
    allowed_syscalls.update(essential)

    if extra_allow:
        allowed_syscalls.update(extra_allow)

    if mode == "whitelist":
        default_action = "SCMP_ACT_ERRNO"
    elif mode == "audit":
        default_action = "SCMP_ACT_LOG"
    else:
        default_action = "SCMP_ACT_ERRNO"

    seccomp_profile = {
        "_metadata": {
            "generator": "syscallguard-seccomp-generator",
            "version": "1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_profile": profile.get("app_version", "unknown"),
            "mode": mode,
            "total_allowed": len(allowed_syscalls),
            "description": (
                f"Auto-generated seccomp profile from SyscallGuard baseline. "
                f"Mode: {mode}. Allows {len(allowed_syscalls)} syscalls, "
                f"blocks all others."
            ),
        },
        "defaultAction": default_action,
        "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"],
        "syscalls": [
            {
                "names": sorted(allowed_syscalls),
                "action": "SCMP_ACT_ALLOW",
            }
        ],
    }

    return seccomp_profile


def compute_seccomp_stats(seccomp_profile: dict, taxonomy: dict = None) -> dict:
    """Compute statistics about the generated seccomp profile."""
    allowed = set(seccomp_profile["syscalls"][0]["names"])
    total_known = 0
    blocked_critical = []

    if taxonomy:
        tier1 = set(taxonomy.get("tier1_critical", {}).get("syscalls", []))
        tier2 = set(taxonomy.get("tier2_suspicious", {}).get("syscalls", []))
        tier3 = set(taxonomy.get("tier3_benign", {}).get("syscalls", []))
        total_known = len(tier1) + len(tier2) + len(tier3)
        blocked_critical = sorted(tier1 - allowed)

    return {
        "allowed_count": len(allowed),
        "total_known_syscalls": total_known,
        "blocked_critical_syscalls": blocked_critical,
        "blocked_critical_count": len(blocked_critical),
        "mode": seccomp_profile["_metadata"]["mode"],
    }


def format_seccomp_summary(seccomp_profile: dict, stats: dict) -> str:
    """Format a human-readable summary of the seccomp profile."""
    lines = []
    lines.append(f"{'='*60}")
    lines.append(f"  SyscallGuard — Seccomp Profile Generator")
    lines.append(f"{'='*60}")
    lines.append("")
    lines.append(f"  🛡️ Mode: {stats['mode'].upper()}")
    lines.append(f"     Allowed syscalls: {stats['allowed_count']}")

    if stats['blocked_critical_count'] > 0:
        lines.append(f"     Blocked critical (Tier 1): {stats['blocked_critical_count']}")
        lines.append("")
        lines.append(f"  🔒 Critical Syscalls BLOCKED by this profile:")
        for sc in stats["blocked_critical_syscalls"][:15]:
            lines.append(f"     ✗ {sc}")

    lines.append("")
    lines.append(f"  ℹ️  Use with Docker: docker run --security-opt seccomp=profile.json")
    lines.append(f"  ℹ️  Use with Kubernetes: seccompProfile.localhostProfile")
    lines.append(f"{'='*60}")
    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="SyscallGuard: Generate seccomp profile from baseline"
    )
    parser.add_argument("profile", help="Path to syscall profile JSON")
    parser.add_argument("--output", default=None, help="Output seccomp JSON path")
    parser.add_argument("--mode", default="whitelist",
                        choices=["whitelist", "audit"],
                        help="Seccomp mode: whitelist (block) or audit (log)")
    parser.add_argument("--taxonomy", default=None, help="Path to taxonomy JSON")
    args = parser.parse_args()

    with open(args.profile) as f:
        profile = json.load(f)

    seccomp = generate_seccomp_profile(profile, mode=args.mode)

    taxonomy = None
    taxonomy_path = args.taxonomy or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "syscall_taxonomy.json"
    )
    if os.path.exists(taxonomy_path):
        with open(taxonomy_path) as f:
            taxonomy = json.load(f)

    stats = compute_seccomp_stats(seccomp, taxonomy)
    print(format_seccomp_summary(seccomp, stats))

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump(seccomp, f, indent=2)
        print(f"\n📄 Seccomp profile written to: {args.output}")


if __name__ == "__main__":
    main()
