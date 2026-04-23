#!/usr/bin/env python3
"""
Unit tests for SyscallGuard — frequency_analyzer.py
Tests frequency anomaly detection, severity classification, and risk scoring.
"""

import json
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from frequency_analyzer import (
    detect_frequency_anomalies,
    compute_frequency_risk_score,
    analyze_frequencies,
    format_frequency_summary,
    load_taxonomy,
)


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
def spike_profile(sample_dir):
    with open(os.path.join(sample_dir, "frequency_spike_attack.json")) as f:
        return json.load(f)


@pytest.fixture
def benign_profile(sample_dir):
    with open(os.path.join(sample_dir, "current_benign_update.json")) as f:
        return json.load(f)


class TestFrequencyDetection:

    def test_no_anomalies_identical(self):
        """Identical counts should produce no anomalies."""
        counts = {"read": 100, "write": 50, "close": 200}
        anomalies = detect_frequency_anomalies(counts, counts)
        assert len(anomalies) == 0

    def test_detects_spike(self):
        """A 10× spike should be detected with default z_threshold=3."""
        current = {"read": 100, "socket": 45000}
        baseline = {"read": 100, "socket": 45}
        anomalies = detect_frequency_anomalies(current, baseline, z_threshold=3.0)
        assert len(anomalies) == 1
        assert anomalies[0]["syscall"] == "socket"
        assert anomalies[0]["direction"] == "SPIKE"
        assert anomalies[0]["ratio"] == 1000.0

    def test_detects_drop(self):
        """A significant drop should be detected."""
        current = {"read": 1}
        baseline = {"read": 10000}
        anomalies = detect_frequency_anomalies(current, baseline, z_threshold=3.0)
        assert len(anomalies) == 1
        assert anomalies[0]["direction"] == "DROP"

    def test_ignores_new_syscalls(self):
        """Syscalls not in baseline should be ignored (handled by Jaccard)."""
        current = {"read": 100, "ptrace": 5}
        baseline = {"read": 100}
        anomalies = detect_frequency_anomalies(current, baseline)
        assert len(anomalies) == 0  # ptrace is new, not a frequency anomaly

    def test_below_threshold_not_flagged(self):
        """Small variations within threshold should not be flagged."""
        current = {"read": 120}
        baseline = {"read": 100}
        anomalies = detect_frequency_anomalies(current, baseline, z_threshold=3.0)
        assert len(anomalies) == 0

    def test_tier_classification(self, taxonomy):
        """Anomalies should include tier info when taxonomy provided."""
        current = {"socket": 45000}
        baseline = {"socket": 45}
        anomalies = detect_frequency_anomalies(current, baseline, taxonomy=taxonomy)
        assert anomalies[0]["tier"] == 1  # socket is Tier 1

    def test_sorted_by_magnitude(self):
        """Anomalies should be sorted by ratio magnitude."""
        current = {"read": 1000, "write": 50000}
        baseline = {"read": 100, "write": 50}
        anomalies = detect_frequency_anomalies(current, baseline, z_threshold=3.0)
        assert len(anomalies) == 2
        # write has 1000× ratio vs read's 10×, should be first
        assert anomalies[0]["syscall"] == "write"


class TestFrequencyRiskScore:

    def test_zero_for_no_anomalies(self):
        """No anomalies = zero risk score."""
        assert compute_frequency_risk_score([]) == 0

    def test_scores_critical_higher(self):
        """CRITICAL severity should score higher than MEDIUM."""
        critical = [{"severity": "CRITICAL", "tier": 1, "direction": "SPIKE"}]
        medium = [{"severity": "MEDIUM", "tier": 3, "direction": "SPIKE"}]
        assert compute_frequency_risk_score(critical) > compute_frequency_risk_score(medium)

    def test_tier1_bonus(self):
        """Tier 1 syscalls get extra risk points."""
        tier1 = [{"severity": "MEDIUM", "tier": 1, "direction": "SPIKE"}]
        tier3 = [{"severity": "MEDIUM", "tier": 3, "direction": "SPIKE"}]
        assert compute_frequency_risk_score(tier1) > compute_frequency_risk_score(tier3)


class TestFullAnalysis:

    def test_spike_attack_detected(self, spike_profile, baseline_profile, taxonomy):
        """Frequency spike attack should produce anomalies."""
        report = analyze_frequencies(spike_profile, baseline_profile, taxonomy=taxonomy)
        assert report["anomalies_detected"] > 0
        assert report["frequency_risk_score"] > 0
        # Check that network syscalls are flagged
        flagged = {a["syscall"] for a in report["anomalies"]}
        assert "socket" in flagged or "connect" in flagged or "sendto" in flagged

    def test_benign_update_no_anomalies(self, benign_profile, baseline_profile, taxonomy):
        """Benign update with minor count changes should have no/few anomalies."""
        report = analyze_frequencies(benign_profile, baseline_profile, taxonomy=taxonomy)
        # Benign profile has very similar counts — no spikes
        assert report["anomalies_detected"] == 0

    def test_identical_profiles(self, baseline_profile, taxonomy):
        """Identical profiles should have zero anomalies."""
        report = analyze_frequencies(baseline_profile, baseline_profile, taxonomy=taxonomy)
        assert report["anomalies_detected"] == 0
        assert report["frequency_risk_score"] == 0

    def test_report_structure(self, spike_profile, baseline_profile, taxonomy):
        """Report should contain all expected fields."""
        report = analyze_frequencies(spike_profile, baseline_profile, taxonomy=taxonomy)
        assert "anomalies_detected" in report
        assert "frequency_risk_score" in report
        assert "spike_count" in report
        assert "drop_count" in report
        assert "anomalies" in report

    def test_summary_formatting(self, spike_profile, baseline_profile, taxonomy):
        """Summary should contain key information."""
        report = analyze_frequencies(spike_profile, baseline_profile, taxonomy=taxonomy)
        summary = format_frequency_summary(report)
        assert "Frequency Anomaly" in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
