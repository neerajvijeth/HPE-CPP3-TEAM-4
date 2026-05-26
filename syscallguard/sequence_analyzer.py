#!/usr/bin/env python3
"""
SyscallGuard — Syscall Sequence (N-gram) Analyzer
===================================================
Analyzes syscall ordering patterns to detect suspicious sequences.
Individual syscalls may be benign, but certain SEQUENCES indicate attacks:

    socket → connect → fork → execve → sendto  = Reverse shell!
    socket → connect → sendto → recvfrom        = Normal HTTP

Usage:
    python sequence_analyzer.py <strace_log> [--n 3] [--output report.json]
"""

import json
import re
import sys
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


# Known suspicious n-gram patterns (hand-curated)
SUSPICIOUS_PATTERNS = {
    # Reverse shell patterns
    ("socket", "connect", "execve"): {
        "name": "Reverse Shell",
        "severity": "CRITICAL",
        "description": "Network socket followed by process execution — classic reverse shell",
    },
    ("socket", "connect", "fork"): {
        "name": "Network Fork",
        "severity": "HIGH",
        "description": "Network connection followed by process fork — potential C2 communication",
    },
    ("fork", "execve", "socket"): {
        "name": "Fork-Exec-Connect",
        "severity": "CRITICAL",
        "description": "Fork + execute + network — backdoor pattern",
    },
    # Process injection patterns
    ("ptrace", "process_vm_readv"): {
        "name": "Process Memory Read",
        "severity": "CRITICAL",
        "description": "Attaching to and reading another process's memory",
    },
    ("ptrace", "process_vm_writev"): {
        "name": "Process Memory Write",
        "severity": "CRITICAL",
        "description": "Attaching to and writing to another process's memory — code injection",
    },
    # Fileless malware patterns
    ("memfd_create", "write", "execve"): {
        "name": "Fileless Execution",
        "severity": "CRITICAL",
        "description": "Creating anonymous file in memory and executing it — fileless malware",
    },
    ("memfd_create", "write", "fork"): {
        "name": "Fileless Fork",
        "severity": "HIGH",
        "description": "Memory-only file creation followed by fork",
    },
    # Privilege escalation patterns
    ("setuid", "execve"): {
        "name": "Privilege Exec",
        "severity": "CRITICAL",
        "description": "Changing UID then executing — privilege escalation",
    },
    ("setuid", "setgid", "execve"): {
        "name": "Full Priv Escalation",
        "severity": "CRITICAL",
        "description": "Setting both UID/GID then executing — full privilege escalation",
    },
    # Container escape patterns
    ("unshare", "mount", "pivot_root"): {
        "name": "Container Escape",
        "severity": "CRITICAL",
        "description": "Namespace manipulation + mount + pivot — container escape attempt",
    },
    ("setns", "mount"): {
        "name": "Namespace Injection",
        "severity": "CRITICAL",
        "description": "Entering another namespace and mounting — lateral movement",
    },
    # Credential theft
    ("openat", "read", "sendto"): {
        "name": "File Exfiltration",
        "severity": "HIGH",
        "description": "Reading file then sending data — potential credential/data theft",
    },
    ("keyctl", "sendto"): {
        "name": "Key Exfiltration",
        "severity": "CRITICAL",
        "description": "Accessing kernel keyring then sending data — credential theft",
    },
}

# Regex for extracting syscall names from strace
STRACE_SYSCALL_RE = re.compile(
    r'^\s*(?:\d+\s+)?(?:[\d:.]+\s+)?([a-z_][a-z0-9_]*)\(',
    re.IGNORECASE
)


def extract_syscall_sequence(strace_log: str, max_length: int = 100000) -> list:
    """Extract ordered sequence of syscall names from strace log."""
    sequence = []
    with open(strace_log, 'r', errors='replace') as f:
        for line in f:
            match = STRACE_SYSCALL_RE.match(line.strip())
            if match:
                name = match.group(1).lower()
                if name not in ('---', '+++', 'strace'):
                    sequence.append(name)
            if len(sequence) >= max_length:
                break
    return sequence


def extract_ngrams(sequence: list, n: int = 3) -> Counter:
    """Extract n-grams from a syscall sequence."""
    ngrams = Counter()
    for i in range(len(sequence) - n + 1):
        gram = tuple(sequence[i:i + n])
        ngrams[gram] += 1
    return ngrams


def detect_suspicious_sequences(
    ngrams: Counter,
    min_n: int = 2,
    max_n: int = 3
) -> list:
    """Check n-grams against known suspicious patterns."""
    detections = []
    for pattern, info in SUSPICIOUS_PATTERNS.items():
        n = len(pattern)
        if n < min_n or n > max_n:
            continue
        count = ngrams.get(pattern, 0)
        if count > 0:
            detections.append({
                "pattern": list(pattern),
                "pattern_name": info["name"],
                "severity": info["severity"],
                "description": info["description"],
                "occurrences": count,
            })

    detections.sort(key=lambda d: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(d["severity"], 3))
    return detections


def analyze_sequences(
    strace_log: str = None,
    syscall_sequence: list = None,
    ngram_sizes: list = None
) -> dict:
    """Full sequence analysis on strace log or pre-extracted sequence."""
    if ngram_sizes is None:
        ngram_sizes = [2, 3]

    if syscall_sequence is None and strace_log:
        syscall_sequence = extract_syscall_sequence(strace_log)
    elif syscall_sequence is None:
        syscall_sequence = []

    # Extract all n-grams
    all_ngrams = Counter()
    for n in ngram_sizes:
        all_ngrams.update(extract_ngrams(syscall_sequence, n))

    # Check for suspicious patterns
    detections = detect_suspicious_sequences(all_ngrams, min(ngram_sizes), max(ngram_sizes))

    # Top most frequent n-grams (for general profiling)
    top_ngrams = [
        {"pattern": list(k), "count": v}
        for k, v in all_ngrams.most_common(20)
    ]

    report = {
        "version": "1.0",
        "generator": "syscallguard-sequence-analyzer",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_syscalls_in_sequence": len(syscall_sequence),
        "ngram_sizes_analyzed": ngram_sizes,
        "total_unique_ngrams": len(all_ngrams),
        "suspicious_detections": len(detections),
        "detections": detections,
        "top_ngrams": top_ngrams,
        "sequence_risk_score": sum(
            {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5}.get(d["severity"], 1) * d["occurrences"]
            for d in detections
        ),
    }

    return report


def format_sequence_summary(report: dict) -> str:
    """Format human-readable sequence analysis report."""
    lines = []
    lines.append(f"{'='*60}")
    lines.append(f"  SyscallGuard — Sequence (N-gram) Analysis")
    lines.append(f"{'='*60}")
    lines.append(f"  Syscalls analyzed: {report['total_syscalls_in_sequence']}")
    lines.append(f"  Unique n-grams: {report['total_unique_ngrams']}")
    lines.append("")

    if report["detections"]:
        lines.append(f"  🚨 Suspicious Sequences Detected: {report['suspicious_detections']}")
        lines.append(f"  {'─'*50}")
        for d in report["detections"]:
            icon = "🔴" if d["severity"] == "CRITICAL" else "🟡"
            pattern = " → ".join(d["pattern"])
            lines.append(f"    {icon} [{d['severity']}] {d['pattern_name']}")
            lines.append(f"       Pattern: {pattern}")
            lines.append(f"       Count: {d['occurrences']}×")
            lines.append(f"       {d['description']}")
    else:
        lines.append(f"  ✅ No suspicious sequences detected")

    lines.append("")
    lines.append(f"  Sequence Risk Score: {report['sequence_risk_score']}")
    lines.append(f"{'='*60}")
    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SyscallGuard: Sequence n-gram analyzer")
    parser.add_argument("strace_log", help="Path to strace log file")
    parser.add_argument("--n", type=int, nargs="+", default=[2, 3], help="N-gram sizes")
    parser.add_argument("--output", default=None, help="Output JSON path")
    args = parser.parse_args()

    report = analyze_sequences(strace_log=args.strace_log, ngram_sizes=args.n)
    print(format_sequence_summary(report))

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n📄 Sequence report written to: {args.output}")


if __name__ == "__main__":
    main()
