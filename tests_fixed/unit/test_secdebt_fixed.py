from datetime import UTC, datetime, timedelta

from app import db
from app.models.secdebt import SecDebtFinding, SecDebtScanRun


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
