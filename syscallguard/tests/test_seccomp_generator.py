#!/usr/bin/env python3
"""
Unit tests for SyscallGuard — seccomp_generator.py
Tests seccomp profile generation and statistics.
"""

import json
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from seccomp_generator import (
    generate_seccomp_profile,
    compute_seccomp_stats,
    format_seccomp_summary,
)


@pytest.fixture
def sample_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_profiles")


@pytest.fixture
def baseline_profile(sample_dir):
    with open(os.path.join(sample_dir, "baseline.json")) as f:
        return json.load(f)


@pytest.fixture
def taxonomy():
    taxonomy_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "syscall_taxonomy.json"
    )
    with open(taxonomy_path) as f:
        return json.load(f)


class TestSeccompGeneration:

    def test_whitelist_mode(self, baseline_profile):
        """Whitelist mode should block by default."""
        profile = generate_seccomp_profile(baseline_profile, mode="whitelist")
        assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
        assert profile["syscalls"][0]["action"] == "SCMP_ACT_ALLOW"

    def test_audit_mode(self, baseline_profile):
        """Audit mode should log instead of block."""
        profile = generate_seccomp_profile(baseline_profile, mode="audit")
        assert profile["defaultAction"] == "SCMP_ACT_LOG"

    def test_essential_syscalls_included(self, baseline_profile):
        """Essential runtime syscalls should always be allowed."""
        profile = generate_seccomp_profile(baseline_profile)
        allowed = set(profile["syscalls"][0]["names"])
        assert "exit" in allowed
        assert "exit_group" in allowed
        assert "rt_sigreturn" in allowed
        assert "futex" in allowed

    def test_baseline_syscalls_included(self, baseline_profile):
        """All baseline syscalls should be in the allowed list."""
        profile = generate_seccomp_profile(baseline_profile)
        allowed = set(profile["syscalls"][0]["names"])
        for sc in baseline_profile["syscalls"]:
            assert sc in allowed

    def test_extra_allow(self, baseline_profile):
        """Extra allowed syscalls should be included."""
        profile = generate_seccomp_profile(
            baseline_profile, extra_allow=["custom_syscall"]
        )
        allowed = set(profile["syscalls"][0]["names"])
        assert "custom_syscall" in allowed

    def test_empty_profile(self):
        """Empty profile should still include essentials."""
        profile = generate_seccomp_profile({"syscalls": []})
        allowed = set(profile["syscalls"][0]["names"])
        assert len(allowed) > 0  # Essential syscalls
        assert "exit" in allowed

    def test_architectures(self, baseline_profile):
        """Should include standard architectures."""
        profile = generate_seccomp_profile(baseline_profile)
        assert "SCMP_ARCH_X86_64" in profile["architectures"]

    def test_dangerous_syscalls_blocked(self, baseline_profile, taxonomy):
        """Dangerous syscalls NOT in baseline should be blocked."""
        profile = generate_seccomp_profile(baseline_profile)
        allowed = set(profile["syscalls"][0]["names"])
        # ptrace is Tier 1 and not in baseline
        assert "ptrace" not in allowed
        assert "execve" not in allowed
        assert "mount" not in allowed


class TestSeccompStats:

    def test_stats_structure(self, baseline_profile, taxonomy):
        """Stats should have correct structure."""
        profile = generate_seccomp_profile(baseline_profile)
        stats = compute_seccomp_stats(profile, taxonomy)
        assert "allowed_count" in stats
        assert "blocked_critical_count" in stats
        assert "blocked_critical_syscalls" in stats

    def test_blocked_critical_listed(self, baseline_profile, taxonomy):
        """Critical blocked syscalls should be enumerated."""
        profile = generate_seccomp_profile(baseline_profile)
        stats = compute_seccomp_stats(profile, taxonomy)
        assert stats["blocked_critical_count"] > 0
        assert "ptrace" in stats["blocked_critical_syscalls"]

    def test_summary_formatting(self, baseline_profile, taxonomy):
        """Summary should contain key info."""
        profile = generate_seccomp_profile(baseline_profile)
        stats = compute_seccomp_stats(profile, taxonomy)
        summary = format_seccomp_summary(profile, stats)
        assert "Seccomp Profile" in summary
        assert "BLOCKED" in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
