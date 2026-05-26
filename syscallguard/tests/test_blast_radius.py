#!/usr/bin/env python3
"""
Unit tests for SyscallGuard — blast_radius.py
Tests the containment score computation and exploit technique analysis.
"""

import json
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blast_radius import compute_blast_radius, load_taxonomy, format_blast_radius_summary


@pytest.fixture
def taxonomy():
    return load_taxonomy()


@pytest.fixture
def sample_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_profiles")


@pytest.fixture
def baseline_profile(sample_dir):
    with open(os.path.join(sample_dir, "baseline.json")) as f:
        return json.load(f)


@pytest.fixture
def attack_profile(sample_dir):
    with open(os.path.join(sample_dir, "current_with_drift.json")) as f:
        return json.load(f)


class TestBlastRadius:

    def test_minimal_profile_high_containment(self, taxonomy):
        """A profile with only benign syscalls should have high containment"""
        profile = {"syscalls": ["read", "write", "close", "brk", "mmap"]}
        report = compute_blast_radius(profile, taxonomy)
        assert report["containment_score"] > 90.0
        assert report["techniques_fully_blocked"] > 5

    def test_empty_profile_full_containment(self, taxonomy):
        """Empty profile blocks ALL exploit syscalls → 100% containment"""
        profile = {"syscalls": []}
        report = compute_blast_radius(profile, taxonomy)
        assert report["containment_score"] == 100.0
        assert report["techniques_fully_exposed"] == 0

    def test_baseline_containment(self, baseline_profile, taxonomy):
        """Baseline profile should have reasonable containment"""
        report = compute_blast_radius(baseline_profile, taxonomy)
        # Baseline has socket, connect, sendto, recvfrom, clone — some exposure
        assert report["containment_score"] > 50.0
        assert report["containment_score"] < 100.0

    def test_attack_profile_lower_containment(self, attack_profile, baseline_profile, taxonomy):
        """Attack profile should have lower containment than baseline"""
        baseline_report = compute_blast_radius(baseline_profile, taxonomy)
        attack_report = compute_blast_radius(attack_profile, taxonomy)
        assert attack_report["containment_score"] < baseline_report["containment_score"]

    def test_process_injection_exposure(self, attack_profile, taxonomy):
        """Attack profile with ptrace should show process injection exposed"""
        report = compute_blast_radius(attack_profile, taxonomy)
        injection = next(
            t for t in report["technique_breakdown"]
            if t["technique"] == "process_injection"
        )
        assert injection["status"] in ("PARTIALLY_EXPOSED", "FULLY_EXPOSED")
        assert "ptrace" in injection["present_in_profile"]

    def test_technique_breakdown_completeness(self, baseline_profile, taxonomy):
        """All exploit techniques should be represented in breakdown"""
        report = compute_blast_radius(baseline_profile, taxonomy)
        technique_names = [t["technique"] for t in report["technique_breakdown"]]
        assert "remote_code_execution" in technique_names
        assert "privilege_escalation" in technique_names
        assert "container_escape" in technique_names
        assert "process_injection" in technique_names
        assert "network_exfiltration" in technique_names

    def test_report_structure(self, baseline_profile, taxonomy):
        """Report should contain all expected fields"""
        report = compute_blast_radius(baseline_profile, taxonomy)
        assert "containment_score" in report
        assert "total_exploit_syscalls" in report
        assert "blocked_exploit_syscalls" in report
        assert "technique_breakdown" in report
        assert isinstance(report["technique_breakdown"], list)

    def test_format_summary_output(self, baseline_profile, taxonomy):
        """Summary formatter should produce readable output"""
        report = compute_blast_radius(baseline_profile, taxonomy)
        summary = format_blast_radius_summary(report)
        assert "Containment Score" in summary
        assert "Technique Breakdown" in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
