from datetime import UTC, datetime, timedelta

import pytest

from app import db
from app.models.secdebt import SecDebtFinding, SecDebtScanRun
from app.utils import secdebt_ingest


def test_secdebt_finding_debt_score_increases_with_age():
    recent = SecDebtFinding(
        tool="bandit",
        vuln_id="B101",
        title="assert used",
        severity="HIGH",
        reachability=1.0,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )
    old = SecDebtFinding(
        tool="bandit",
        vuln_id="B102",
        title="old finding",
        severity="HIGH",
        reachability=1.0,
        first_seen=datetime.now(UTC) - timedelta(days=40),
        last_seen=datetime.now(UTC),
    )

    assert old.calculate_debt_score() > recent.calculate_debt_score()


def test_secdebt_dashboard_and_api_stats(logged_in_admin):
    response = logged_in_admin.get("/secdebt/")
    assert response.status_code == 200
    assert b"SecDebt Optimizer" in response.data

    stats = logged_in_admin.get("/secdebt/api/stats")
    assert stats.status_code == 200
    assert stats.get_json()["total_findings"] == 0


def test_secdebt_ingest_requires_token(client):
    response = client.post("/secdebt/api/ingest", json={})
    assert response.status_code == 403


def test_secdebt_ingest_with_token_creates_run(client, monkeypatch):
    monkeypatch.setenv("SECDEBT_INGEST_TOKEN", "test-token")

    response = client.post(
        "/secdebt/api/ingest",
        headers={"X-Ingest-Token": "test-token"},
        json={
            "commit_sha": "abc123",
            "branch": "hps-test",
            "triggered_by": "pytest",
        },
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert SecDebtScanRun.query.filter_by(commit_sha="abc123").count() == 1


def test_secdebt_ingest_returns_generic_error_message(client, monkeypatch):
    monkeypatch.setenv("SECDEBT_INGEST_TOKEN", "test-token")

    def fail_ingest(**_kwargs):
        raise ValueError("sensitive parser detail from report")

    monkeypatch.setattr("app.routes.secdebt.ingest_reports", fail_ingest)

    response = client.post(
        "/secdebt/api/ingest",
        headers={"X-Ingest-Token": "test-token"},
        json={"triggered_by": "pytest"},
    )

    assert response.status_code == 500
    payload = response.get_json()
    assert payload["status"] == "error"
    assert payload["message"] == "SecDebt ingest failed. Check server logs for details."
    assert "sensitive parser detail" not in response.get_data(as_text=True)


def test_admin_can_resolve_secdebt_finding(logged_in_admin):
    finding = SecDebtFinding(
        tool="trivy",
        vuln_id="CVE-2026-0001",
        title="example vulnerability",
        severity="HIGH",
        reachability=0.7,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )
    db.session.add(finding)
    db.session.commit()

    response = logged_in_admin.post(f"/secdebt/api/resolve/{finding.id}")

    assert response.status_code == 200
    assert SecDebtFinding.query.get(finding.id).is_resolved is True


def test_secdebt_findings_api_filters_and_includes_metadata(logged_in_admin):
    open_finding = SecDebtFinding(
        tool="trivy",
        vuln_id="CVE-2026-0002",
        title="open vulnerability",
        description="dependency issue",
        severity="HIGH",
        reachability=0.7,
        file_path="requirements.txt",
        line_number=1,
        first_seen=datetime.now(UTC) - timedelta(days=10),
        last_seen=datetime.now(UTC),
    )
    resolved_finding = SecDebtFinding(
        tool="bandit",
        vuln_id="B101",
        title="resolved finding",
        severity="LOW",
        reachability=1.0,
        is_resolved=True,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )
    db.session.add_all([open_finding, resolved_finding])
    db.session.commit()

    response = logged_in_admin.get("/secdebt/api/findings?tool=trivy&severity=HIGH")

    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload) == 1
    assert payload[0]["vuln_id"] == "CVE-2026-0002"
    assert payload[0]["description"] == "dependency issue"
    assert payload[0]["reachability"] == 0.7
    assert payload[0]["is_resolved"] is False
    assert payload[0]["interest_multiplier"] == 1.5


def test_safe_report_path_rejects_absolute_and_parent_paths():
    with pytest.raises(ValueError):
        secdebt_ingest._safe_report_path("/tmp/report.json")

    with pytest.raises(ValueError):
        secdebt_ingest._safe_report_path("../report.json")


def test_safe_report_path_accepts_known_relative_report(monkeypatch, tmp_path):
    monkeypatch.setattr(secdebt_ingest, "DEFAULT_REPORT_DIR", tmp_path)

    report_path = secdebt_ingest._safe_report_path("odc-reports/dependency-check-report.json")

    assert report_path == tmp_path / "odc-reports" / "dependency-check-report.json"
