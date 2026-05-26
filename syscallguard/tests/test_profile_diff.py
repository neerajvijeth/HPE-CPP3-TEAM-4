#!/usr/bin/env python3
"""
Unit tests for SyscallGuard — profile_diff.py
Tests the Jaccard similarity engine, danger tier classification,
weighted risk scoring, and pass/fail threshold gating.
"""

import json
import os
import sys
import pytest

# Add parent dir to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from profile_diff import (
    compute_jaccard,
    classify_syscall,
    diff_profiles,
    load_taxonomy,
    format_summary,
)


# ─── Fixtures ────────────────────────────────────────────────

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


@pytest.fixture
def benign_profile(sample_dir):
    with open(os.path.join(sample_dir, "current_benign_update.json")) as f:
        return json.load(f)


# ─── Jaccard Similarity Tests ────────────────────────────────

class TestJaccardSimilarity:

    def test_identical_sets(self):
        """Identical profiles should have Jaccard = 1.0"""
        s = {"read", "write", "close", "mmap"}
        assert compute_jaccard(s, s) == 1.0

    def test_empty_sets(self):
        """Two empty sets should return Jaccard = 1.0"""
        assert compute_jaccard(set(), set()) == 1.0

    def test_completely_disjoint(self):
        """Completely different sets should return Jaccard = 0.0"""
        a = {"read", "write"}
        b = {"ptrace", "execve"}
        assert compute_jaccard(a, b) == 0.0

    def test_known_jaccard_value(self):
        """Verify known Jaccard computation: J({1,2,3}, {2,3,4}) = 2/4 = 0.5"""
        a = {"a", "b", "c"}
        b = {"b", "c", "d"}
        assert compute_jaccard(a, b) == 0.5

    def test_subset_relationship(self):
        """If B ⊂ A, Jaccard = |B| / |A|"""
        a = {"read", "write", "close", "mmap"}
        b = {"read", "write"}
        assert compute_jaccard(a, b) == 2 / 4

    def test_one_empty_set(self):
        """One empty set should return Jaccard = 0.0"""
        a = {"read", "write"}
        assert compute_jaccard(a, set()) == 0.0


# ─── Syscall Classification Tests ────────────────────────────

class TestSyscallClassification:

    def test_tier1_ptrace(self, taxonomy):
        result = classify_syscall("ptrace", taxonomy)
        assert result["tier"] == 1
        assert result["tier_name"] == "CRITICAL"
        assert result["weight"] == 10

    def test_tier1_execve(self, taxonomy):
        result = classify_syscall("execve", taxonomy)
        assert result["tier"] == 1
        assert result["weight"] == 10

    def test_tier1_socket(self, taxonomy):
        result = classify_syscall("socket", taxonomy)
        assert result["tier"] == 1
        assert result["weight"] == 10

    def test_tier2_openat(self, taxonomy):
        result = classify_syscall("openat", taxonomy)
        assert result["tier"] == 2
        assert result["tier_name"] == "SUSPICIOUS"
        assert result["weight"] == 3

    def test_tier3_read(self, taxonomy):
        result = classify_syscall("read", taxonomy)
        assert result["tier"] == 3
        assert result["tier_name"] == "BENIGN"
        assert result["weight"] == 1

    def test_unknown_syscall(self, taxonomy):
        result = classify_syscall("totally_fake_syscall_xyz", taxonomy)
        assert result["tier"] == 0
        assert result["tier_name"] == "UNKNOWN"
        assert result["weight"] == 5


# ─── Profile Diff Tests ─────────────────────────────────────

class TestProfileDiff:

    def test_identical_profiles_pass(self, baseline_profile, taxonomy):
        """Comparing a profile to itself should produce Jaccard=1.0 and PASS"""
        report = diff_profiles(baseline_profile, baseline_profile, taxonomy)
        assert report["metrics"]["jaccard_similarity"] == 1.0
        assert report["metrics"]["novel_count"] == 0
        assert report["risk_assessment"]["risk_score"] == 0
        assert report["risk_assessment"]["verdict"] == "PASS"

    def test_attack_profile_detected(self, attack_profile, baseline_profile, taxonomy):
        """Attack profile with ptrace/execve/process_vm_readv should FAIL"""
        report = diff_profiles(attack_profile, baseline_profile, taxonomy)

        # Should detect novel syscalls
        assert report["metrics"]["novel_count"] > 0

        # Should detect tier-1 critical syscalls
        assert report["tier_summary"]["tier1"] > 0

        # Jaccard should be < 1.0
        assert report["metrics"]["jaccard_similarity"] < 1.0

        # Risk score should exceed default threshold of 10
        assert report["risk_assessment"]["risk_score"] > 10
        assert report["risk_assessment"]["verdict"] == "FAIL"

        # Verify specific dangerous syscalls were flagged
        novel_names = [s["syscall"] for s in report["novel_syscalls"]]
        assert "ptrace" in novel_names
        assert "process_vm_readv" in novel_names
        assert "execve" in novel_names
        assert "memfd_create" in novel_names

    def test_benign_update_passes(self, benign_profile, baseline_profile, taxonomy):
        """Benign update adding only tier-3 syscalls should PASS"""
        report = diff_profiles(benign_profile, baseline_profile, taxonomy)

        # Should detect some novel syscalls
        assert report["metrics"]["novel_count"] > 0

        # Should NOT have tier-1 critical syscalls
        assert report["tier_summary"]["tier1"] == 0

        # Risk score should be within threshold
        assert report["risk_assessment"]["risk_score"] <= 10
        assert report["risk_assessment"]["verdict"] == "PASS"

    def test_custom_threshold_strict(self, benign_profile, baseline_profile, taxonomy):
        """With threshold=0, even benign additions should FAIL"""
        report = diff_profiles(benign_profile, baseline_profile, taxonomy, threshold=0)
        assert report["risk_assessment"]["verdict"] == "FAIL"

    def test_custom_threshold_relaxed(self, attack_profile, baseline_profile, taxonomy):
        """With threshold=999, even attack profile should PASS"""
        report = diff_profiles(attack_profile, baseline_profile, taxonomy, threshold=999)
        assert report["risk_assessment"]["verdict"] == "PASS"

    def test_removed_syscalls_tracked(self, taxonomy):
        """Syscalls removed from baseline should be reported"""
        current = {"syscalls": ["read", "write"]}
        baseline = {"syscalls": ["read", "write", "close", "mmap"]}
        report = diff_profiles(current, baseline, taxonomy)
        assert report["metrics"]["removed_count"] == 2
        assert "close" in report["removed_syscalls"]
        assert "mmap" in report["removed_syscalls"]


# ─── Summary Formatting Tests ────────────────────────────────

class TestFormatting:

    def test_summary_contains_key_info(self, attack_profile, baseline_profile, taxonomy):
        report = diff_profiles(attack_profile, baseline_profile, taxonomy)
        summary = format_summary(report)

        assert "Jaccard Similarity" in summary
        assert "FAIL" in summary
        assert "ptrace" in summary
        assert "Risk Score" in summary

    def test_pass_summary(self, benign_profile, baseline_profile, taxonomy):
        report = diff_profiles(benign_profile, baseline_profile, taxonomy)
        summary = format_summary(report)

        assert "PASS" in summary
        assert "SUPPLY CHAIN ANOMALY" not in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
