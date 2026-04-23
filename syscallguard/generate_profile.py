#!/usr/bin/env python3
"""
SyscallGuard — Strace-to-Profile Generator
===========================================
Parses raw strace output (captured with `strace -f -o <file>`) into a
standardized JSON syscall profile for downstream comparison.

Usage:
    python generate_profile.py <strace_log> <output_profile.json> [--source pytest|dependency] [--git-sha <sha>] [--req-hash <hash>]
"""

import json
import re
import sys
import hashlib
from datetime import datetime, timezone
from collections import Counter
from pathlib import Path


# Regex to extract syscall names from strace output lines
# Matches lines like: "12345 openat(AT_FDCWD, ..." or "read(3, ..."
# Also handles: "12345  0.000001 execve(...)" (relative timestamps)
STRACE_SYSCALL_RE = re.compile(
    r'^\s*(?:\d+\s+)?'                    # optional PID prefix (from -f flag)
    r'(?:[\d:.]+\s+)?'                     # optional timestamp (HH:MM:SS.xxx or 0.000001)
    r'([a-z_][a-z0-9_]*)\(',              # syscall name followed by '('
    re.IGNORECASE
)

# Also match "resumed" lines: "12345 <... openat resumed>"
STRACE_RESUMED_RE = re.compile(
    r'<\.\.\.\s+([a-z_][a-z0-9_]*)\s+resumed>',
    re.IGNORECASE
)


def parse_strace_log(filepath: str) -> tuple[list[str], Counter]:
    """
    Parse a raw strace log file and extract syscall names.

    Returns:
        tuple: (sorted unique syscall list, Counter of syscall frequencies)
    """
    syscall_counter = Counter()

    with open(filepath, 'r', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Try primary pattern: "PID syscall(...)"
            match = STRACE_SYSCALL_RE.match(line)
            if match:
                syscall_name = match.group(1).lower()
                # Filter out strace noise
                if syscall_name not in ('---', '+++', 'strace'):
                    syscall_counter[syscall_name] += 1
                continue

            # Try resumed pattern: "<... syscall resumed>"
            match = STRACE_RESUMED_RE.search(line)
            if match:
                syscall_name = match.group(1).lower()
                syscall_counter[syscall_name] += 1

    unique_syscalls = sorted(syscall_counter.keys())
    return unique_syscalls, syscall_counter


def generate_profile(
    strace_log: str,
    output_path: str,
    source: str = "pytest",
    git_sha: str = "unknown",
    req_hash: str = "unknown"
) -> dict:
    """
    Generate a JSON syscall profile from strace output.

    Args:
        strace_log: Path to raw strace output file
        output_path: Path to write the JSON profile
        source: Label for the profile source ("pytest" or "dependency")
        git_sha: Git commit SHA for versioning
        req_hash: SHA256 hash of requirements.txt for fingerprinting

    Returns:
        dict: The generated profile
    """
    unique_syscalls, syscall_counter = parse_strace_log(strace_log)

    profile = {
        "version": "1.0",
        "generator": "syscallguard",
        "app_version": git_sha,
        "requirements_hash": req_hash,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "syscalls": unique_syscalls,
        "syscall_counts": dict(syscall_counter.most_common()),
        "total_unique_syscalls": len(unique_syscalls),
        "total_syscall_invocations": sum(syscall_counter.values())
    }

    # Ensure output directory exists
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(profile, f, indent=2)

    return profile


def compute_requirements_hash(req_file: str) -> str:
    """Compute SHA256 hash of a requirements.txt file."""
    try:
        with open(req_file, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except FileNotFoundError:
        return "file_not_found"


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="SyscallGuard: Generate syscall profile from strace output"
    )
    parser.add_argument("strace_log", help="Path to strace output file")
    parser.add_argument("output", help="Path to write JSON profile")
    parser.add_argument("--source", default="pytest",
                        choices=["pytest", "dependency"],
                        help="Profile source label")
    parser.add_argument("--git-sha", default="unknown",
                        help="Git commit SHA")
    parser.add_argument("--req-hash", default=None,
                        help="SHA256 of requirements.txt (auto-computed if --req-file given)")
    parser.add_argument("--req-file", default=None,
                        help="Path to requirements.txt (computes hash automatically)")

    args = parser.parse_args()

    # Auto-compute requirements hash if file given
    req_hash = args.req_hash or "unknown"
    if args.req_file:
        req_hash = compute_requirements_hash(args.req_file)

    profile = generate_profile(
        strace_log=args.strace_log,
        output_path=args.output,
        source=args.source,
        git_sha=args.git_sha,
        req_hash=req_hash
    )

    print(f"✅ Profile generated: {args.output}")
    print(f"   Unique syscalls: {profile['total_unique_syscalls']}")
    print(f"   Total invocations: {profile['total_syscall_invocations']}")
    print(f"   Source: {profile['source']}")
    print(f"   Requirements hash: {profile['requirements_hash'][:16]}...")


if __name__ == "__main__":
    main()
