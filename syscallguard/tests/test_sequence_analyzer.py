#!/usr/bin/env python3
"""
Unit tests for SyscallGuard — sequence_analyzer.py
Tests n-gram extraction and suspicious pattern detection.
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sequence_analyzer import (
    extract_ngrams,
    detect_suspicious_sequences,
    analyze_sequences,
    format_sequence_summary,
)
from collections import Counter


class TestNgramExtraction:

    def test_basic_trigrams(self):
        """Should extract correct trigrams."""
        seq = ["read", "write", "close", "mmap", "brk"]
        ngrams = extract_ngrams(seq, n=3)
        assert ngrams[("read", "write", "close")] == 1
        assert ngrams[("write", "close", "mmap")] == 1
        assert len(ngrams) == 3

    def test_bigrams(self):
        """Should extract correct bigrams."""
        seq = ["read", "write", "close"]
        ngrams = extract_ngrams(seq, n=2)
        assert ngrams[("read", "write")] == 1
        assert ngrams[("write", "close")] == 1
        assert len(ngrams) == 2

    def test_repeated_patterns(self):
        """Repeated patterns should have correct counts."""
        seq = ["read", "write", "read", "write", "read"]
        ngrams = extract_ngrams(seq, n=2)
        assert ngrams[("read", "write")] == 2
        assert ngrams[("write", "read")] == 2

    def test_too_short_sequence(self):
        """Sequence shorter than n should return empty."""
        seq = ["read"]
        ngrams = extract_ngrams(seq, n=3)
        assert len(ngrams) == 0

    def test_empty_sequence(self):
        """Empty sequence should return empty."""
        ngrams = extract_ngrams([], n=3)
        assert len(ngrams) == 0


class TestSuspiciousDetection:

    def test_reverse_shell_detected(self):
        """Should detect reverse shell pattern."""
        ngrams = Counter({
            ("socket", "connect", "execve"): 2,
            ("read", "write", "close"): 100,
        })
        detections = detect_suspicious_sequences(ngrams)
        assert len(detections) >= 1
        names = [d["pattern_name"] for d in detections]
        assert "Reverse Shell" in names

    def test_process_injection_detected(self):
        """Should detect process injection pattern."""
        ngrams = Counter({
            ("ptrace", "process_vm_readv"): 1,
        })
        detections = detect_suspicious_sequences(ngrams)
        assert len(detections) >= 1
        names = [d["pattern_name"] for d in detections]
        assert "Process Memory Read" in names

    def test_fileless_malware_detected(self):
        """Should detect fileless execution pattern."""
        ngrams = Counter({
            ("memfd_create", "write", "execve"): 1,
        })
        detections = detect_suspicious_sequences(ngrams)
        names = [d["pattern_name"] for d in detections]
        assert "Fileless Execution" in names

    def test_no_suspicious_patterns(self):
        """Normal patterns should not trigger detection."""
        ngrams = Counter({
            ("read", "write", "close"): 100,
            ("mmap", "mprotect", "munmap"): 50,
            ("read", "close"): 200,
        })
        detections = detect_suspicious_sequences(ngrams)
        assert len(detections) == 0

    def test_container_escape_detected(self):
        """Should detect container escape pattern."""
        ngrams = Counter({
            ("unshare", "mount", "pivot_root"): 1,
        })
        detections = detect_suspicious_sequences(ngrams)
        names = [d["pattern_name"] for d in detections]
        assert "Container Escape" in names

    def test_sorted_by_severity(self):
        """Detections should be sorted by severity (CRITICAL first)."""
        ngrams = Counter({
            ("openat", "read", "sendto"): 5,  # HIGH
            ("socket", "connect", "execve"): 1,  # CRITICAL
        })
        detections = detect_suspicious_sequences(ngrams)
        if len(detections) >= 2:
            assert detections[0]["severity"] == "CRITICAL"


class TestFullAnalysis:

    def test_clean_sequence(self):
        """Clean syscall sequence should have no detections."""
        seq = ["read", "write", "close", "mmap", "brk", "read", "write"]
        report = analyze_sequences(syscall_sequence=seq)
        assert report["suspicious_detections"] == 0
        assert report["sequence_risk_score"] == 0

    def test_attack_sequence(self):
        """Sequence with reverse shell should be flagged."""
        seq = ["read", "socket", "connect", "execve", "write", "close"]
        report = analyze_sequences(syscall_sequence=seq)
        assert report["suspicious_detections"] > 0
        assert report["sequence_risk_score"] > 0

    def test_report_structure(self):
        """Report should contain expected fields."""
        report = analyze_sequences(syscall_sequence=["read", "write"])
        assert "total_syscalls_in_sequence" in report
        assert "suspicious_detections" in report
        assert "detections" in report
        assert "sequence_risk_score" in report
        assert "top_ngrams" in report

    def test_summary_formatting(self):
        """Summary should be readable."""
        seq = ["read", "socket", "connect", "execve", "close"]
        report = analyze_sequences(syscall_sequence=seq)
        summary = format_sequence_summary(report)
        assert "Sequence" in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
