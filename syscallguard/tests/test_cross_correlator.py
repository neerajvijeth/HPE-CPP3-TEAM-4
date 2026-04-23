#!/usr/bin/env python3
"""
Unit tests for SyscallGuard — cross_correlator.py
Tests cross-profile correlation between pytest and dependency profiles.
"""

import json
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cross_correlator import (
    cross_correlate,
    format_correlation_summary,
    load_taxonomy,
)


@pytest.fixture
def taxonomy():
    return load_taxonomy()


class TestCrossCorrelation:

    def test_identical_profiles(self, taxonomy):
        """Identical profiles should have 100% coverage."""
        profile = {"syscalls": ["read", "write", "close"]}
        report = cross_correlate(profile, profile, taxonomy)
        assert report["dependency_coverage"] == 100.0
        assert report["dep_only_count"] == 0
        assert report["pytest_only_count"] == 0

    def test_dep_only_detected(self, taxonomy):
        """Syscalls only in dep profile should be flagged."""
        pytest_prof = {"syscalls": ["read", "write"]}
        dep_prof = {"syscalls": ["read", "write", "socket", "connect"]}
        report = cross_correlate(pytest_prof, dep_prof, taxonomy)
        assert report["dep_only_count"] == 2
        dep_only_names = [s["syscall"] for s in report["dep_only_syscalls"]]
        assert "socket" in dep_only_names
        assert "connect" in dep_only_names

    def test_pytest_only_detected(self, taxonomy):
        """Syscalls only in pytest should be tracked."""
        pytest_prof = {"syscalls": ["read", "write", "mmap"]}
        dep_prof = {"syscalls": ["read", "write"]}
        report = cross_correlate(pytest_prof, dep_prof, taxonomy)
        assert report["pytest_only_count"] == 1

    def test_tier_classification(self, taxonomy):
        """Dep-only syscalls should have tier info."""
        pytest_prof = {"syscalls": ["read"]}
        dep_prof = {"syscalls": ["read", "ptrace"]}
        report = cross_correlate(pytest_prof, dep_prof, taxonomy)
        ptrace_entry = [s for s in report["dep_only_syscalls"] if s["syscall"] == "ptrace"]
        assert len(ptrace_entry) == 1
        assert ptrace_entry[0]["tier"] == 1

    def test_untested_risk_score(self, taxonomy):
        """Untested Tier 1 syscalls should produce high risk score."""
        pytest_prof = {"syscalls": ["read"]}
        dep_prof = {"syscalls": ["read", "ptrace", "execve"]}
        report = cross_correlate(pytest_prof, dep_prof, taxonomy)
        assert report["untested_risk_score"] >= 20  # Two Tier 1 × 10 each

    def test_coverage_calculation(self, taxonomy):
        """Coverage should be (common / dep_total) × 100."""
        pytest_prof = {"syscalls": ["read", "write", "close", "mmap"]}
        dep_prof = {"syscalls": ["read", "write", "socket", "connect"]}
        report = cross_correlate(pytest_prof, dep_prof, taxonomy)
        # Common = {read, write} = 2, dep_total = 4 → 50%
        assert report["dependency_coverage"] == 50.0

    def test_empty_profiles(self, taxonomy):
        """Empty profiles should handle gracefully."""
        report = cross_correlate({"syscalls": []}, {"syscalls": []}, taxonomy)
        assert report["dependency_coverage"] == 100.0
        assert report["dep_only_count"] == 0

    def test_report_structure(self, taxonomy):
        """Report should contain all expected fields."""
        report = cross_correlate(
            {"syscalls": ["read"]},
            {"syscalls": ["write"]},
            taxonomy
        )
        assert "dep_only_count" in report
        assert "pytest_only_count" in report
        assert "dependency_coverage" in report
        assert "untested_risk_score" in report
        assert "common_syscall_list" in report

    def test_summary_formatting(self, taxonomy):
        """Summary should be formatted correctly."""
        report = cross_correlate(
            {"syscalls": ["read"]},
            {"syscalls": ["read", "socket"]},
            taxonomy
        )
        summary = format_correlation_summary(report)
        assert "Cross-Profile Correlation" in summary
        assert "Coverage" in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
