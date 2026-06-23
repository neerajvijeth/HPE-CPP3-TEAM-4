import logging
import os
from datetime import UTC, datetime

from app import db
from app.models.secdebt import SecDebtFinding, SecDebtScanRun
from app.utils.secdebt_parsers import (
    parse_bandit,
    parse_owasp,
    parse_pylint,
    parse_sonar,
    parse_trivy,
)

logger = logging.getLogger(__name__)

REPORT_FILES = {
    "bandit": "bandit-report.txt",
    "pylint": "pylint-report.txt",
    "trivy": "trivy-results.txt",
    "owasp": os.path.join("odc-reports", "dependency-check-report.json"),
    "sonar": "sonar-issues.json",
}

PARSERS = {
    "bandit": parse_bandit,
    "pylint": parse_pylint,
    "trivy": parse_trivy,
    "owasp": parse_owasp,
    "sonar": parse_sonar,
}


def _dedup_key(tool, vuln_id, file_path, line_number):
    return f"{tool}::{vuln_id}::{file_path or ''}::{line_number or 0}"


def ingest_reports(report_dir=".", commit_sha=None, branch=None, triggered_by="manual"):
    now = datetime.now(UTC)
    parsed_findings = []
    tools_ingested = []

    for tool, filename in REPORT_FILES.items():
        report_path = os.path.join(report_dir, filename)
        if not os.path.exists(report_path):
            logger.info("SecDebt skipped missing %s report: %s", tool, report_path)
            continue

        findings = PARSERS[tool](report_path)
        tools_ingested.append(tool)
        parsed_findings.extend(findings)

    existing = {}
    for finding in SecDebtFinding.query.filter_by(is_resolved=False).all():
        key = _dedup_key(finding.tool, finding.vuln_id, finding.file_path, finding.line_number)
        existing[key] = finding

    seen = set()
    new_count = 0

    for item in parsed_findings:
        key = _dedup_key(item["tool"], item["vuln_id"], item.get("file_path"), item.get("line_number"))
        seen.add(key)

        if key in existing:
            finding = existing[key]
            finding.last_seen = now
            finding.severity = item["severity"]
            finding.reachability = item.get("reachability", 0.5)
            finding.raw_snippet = item.get("raw_snippet")
            finding.commit_sha = commit_sha
        else:
            finding = SecDebtFinding(
                tool=item["tool"],
                vuln_id=item["vuln_id"],
                title=item["title"],
                description=item.get("description"),
                severity=item["severity"],
                reachability=item.get("reachability", 0.5),
                file_path=item.get("file_path"),
                line_number=item.get("line_number"),
                first_seen=now,
                last_seen=now,
                raw_snippet=item.get("raw_snippet"),
                commit_sha=commit_sha,
            )
            db.session.add(finding)
            new_count += 1

        finding.is_resolved = False
        finding.resolved_at = None
        finding.update_debt_score()

    resolved_count = 0
    for key, finding in existing.items():
        if key not in seen and finding.tool in tools_ingested:
            finding.is_resolved = True
            finding.resolved_at = now
            resolved_count += 1

    db.session.flush()

    open_findings = SecDebtFinding.query.filter_by(is_resolved=False).all()
    total_score = round(sum(finding.debt_score for finding in open_findings), 2)

    run = SecDebtScanRun(
        run_at=now,
        commit_sha=commit_sha,
        branch=branch,
        tools_ingested=",".join(tools_ingested),
        total_findings=len(open_findings),
        new_findings=new_count,
        resolved_findings=resolved_count,
        total_debt_score=total_score,
        triggered_by=triggered_by,
    )
    db.session.add(run)
    db.session.commit()
    return run


def get_dashboard_stats():
    open_findings = SecDebtFinding.query.filter_by(is_resolved=False).all()
    by_severity = {}
    by_tool = {}

    for finding in open_findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_tool[finding.tool] = by_tool.get(finding.tool, 0) + 1

    top_findings = sorted(open_findings, key=lambda item: item.debt_score, reverse=True)
    history = SecDebtScanRun.query.order_by(SecDebtScanRun.run_at.asc()).limit(10).all()

    return {
        "total_findings": len(open_findings),
        "total_score": round(sum(finding.debt_score for finding in open_findings), 2),
        "by_severity": by_severity,
        "by_tool": by_tool,
        "top_findings": top_findings[:20],
        "last_run": SecDebtScanRun.query.order_by(SecDebtScanRun.run_at.desc()).first(),
        "history": history,
    }
