#!/usr/bin/env python3
"""
Unit tests for SyscallGuard — cosine_engine.py
Tests cosine similarity computation and frequency vector analysis.
"""

import json
import os
import sys
import math
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cosine_engine import (
    cosine_similarity,
    build_frequency_vectors,
    compute_profile_cosine,
    format_cosine_summary,
)


@pytest.fixture
def sample_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_profiles")


@pytest.fixture
def baseline_profile(sample_dir):
    with open(os.path.join(sample_dir, "baseline.json")) as f:
        return json.load(f)


@pytest.fixture
def spike_profile(sample_dir):
    with open(os.path.join(sample_dir, "frequency_spike_attack.json")) as f:
        return json.load(f)


@pytest.fixture
def benign_profile(sample_dir):
    with open(os.path.join(sample_dir, "current_benign_update.json")) as f:
        return json.load(f)


class TestCosineSimilarity:

    def test_identical_vectors(self):
        """Identical vectors should have cosine = 1.0."""
        vec = [1, 2, 3, 4, 5]
        assert cosine_similarity(vec, vec) == pytest.approx(1.0)

    def test_orthogonal_vectors(self):
        """Orthogonal vectors should have cosine = 0.0."""
        a = [1, 0, 0]
        b = [0, 1, 0]
        assert cosine_similarity(a, b) == pytest.approx(0.0)

    def test_opposite_impossible_for_counts(self):
        """Negative values aren't realistic for syscall counts, but test anyway."""
        a = [1, 0]
        b = [-1, 0]
        assert cosine_similarity(a, b) == pytest.approx(-1.0)

    def test_proportional_vectors(self):
        """Proportional vectors (same direction) should have cosine = 1.0."""
        a = [1, 2, 3]
        b = [2, 4, 6]
        assert cosine_similarity(a, b) == pytest.approx(1.0)

    def test_empty_vectors(self):
        """Two empty vectors should return 1.0."""
        assert cosine_similarity([], []) == 1.0

    def test_one_empty(self):
        """One empty vector should return 0.0."""
        assert cosine_similarity([1, 2], []) == 0.0

    def test_zero_vectors(self):
        """Two zero vectors should return 1.0."""
        assert cosine_similarity([0, 0, 0], [0, 0, 0]) == 1.0

    def test_known_value(self):
        """Verify a known cosine computation."""
        a = [3, 4]
        b = [4, 3]
        # cos = (12 + 12) / (5 * 5) = 24/25 = 0.96
        assert cosine_similarity(a, b) == pytest.approx(0.96)


class TestFrequencyVectors:

    def test_aligned_vectors(self):
        """Vectors should be aligned over union of keys."""
        cur = {"read": 10, "write": 20}
        base = {"read": 10, "socket": 5}
        c, b, labels = build_frequency_vectors(cur, base)
        assert "read" in labels
        assert "write" in labels
        assert "socket" in labels
        assert len(c) == len(b) == len(labels)

    def test_missing_values_zero(self):
        """Missing syscalls should get zero in the vector."""
        cur = {"read": 10}
        base = {"write": 20}
        c, b, labels = build_frequency_vectors(cur, base)
        # read is in cur but not base → base should have 0
        read_idx = labels.index("read")
        assert b[read_idx] == 0
        assert c[read_idx] == 10


class TestProfileCosine:

    def test_identical_profiles(self, baseline_profile):
        """Identical profiles should have cosine ≈ 1.0."""
        report = compute_profile_cosine(baseline_profile, baseline_profile)
        assert report["cosine_similarity"] == pytest.approx(1.0, abs=0.001)

    def test_spike_attack_divergence(self, spike_profile, baseline_profile):
        """Spike attack should show significant cosine divergence."""
        report = compute_profile_cosine(spike_profile, baseline_profile)
        # Spike attack has massive changes, cosine should drop
        assert report["cosine_similarity"] < 0.99

    def test_benign_update_similar(self, benign_profile, baseline_profile):
        """Benign update should have high cosine similarity."""
        report = compute_profile_cosine(benign_profile, baseline_profile)
        assert report["cosine_similarity"] > 0.99

    def test_report_structure(self, baseline_profile, spike_profile):
        """Report should contain all required fields."""
        report = compute_profile_cosine(spike_profile, baseline_profile)
        assert "cosine_similarity" in report
        assert "log_cosine_similarity" in report
        assert "vector_dimensions" in report
        assert "top_divergence_contributors" in report

    def test_summary_formatting(self, baseline_profile, spike_profile):
        """Summary should be formatted correctly."""
        report = compute_profile_cosine(spike_profile, baseline_profile)
        summary = format_cosine_summary(report)
        assert "Cosine Similarity" in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
