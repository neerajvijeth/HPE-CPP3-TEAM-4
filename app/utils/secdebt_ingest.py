"""
SecDebt Ingest Engine
=====================
Orchestrates reading reports → parsing → deduplication → DB upsert → debt scoring.

Usage (called from Flask route or GitHub Actions webhook):

    from app.utils.secdebt_ingest import ingest_reports
    run = ingest_reports(
        report_dir="/workspace",          # where tool reports live
        commit_sha="abc123",
        branch="main",
        triggered_by="github-actions"
    )
"""

import os
import logging
from datetime import datetime, UTC
from typing import Optional

from app import db
from app.models.secdebt import SecDebtFinding, SecDebtScanRun
from app.utils.secdebt_parsers import (
    parse_bandit,
    parse_trivy,
    parse_pylint,
    parse_owasp,
    parse_sonar,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Report path configuration
# Default filenames match what each GitHub Actions workflow produces.
# ---------------------------------------------------------------------------

REPORT_FILES = {
    "bandit": "bandit-report.txt",
    "trivy":  "trivy-results.txt",
    "pylint": "pylint-report.txt",
    "owasp":  os.path.join("odc-reports", "dependency-check-report.json"),
    "sonar":  "sonar-issues.json",   # optional
}

PARSERS = {
    "bandit": parse_bandit,
    "trivy":  parse_trivy,
    "pylint": parse_pylint,
    "owasp":  parse_owasp,
    "sonar":  parse_sonar,
}


def _make_dedup_key(tool: str, vuln_id: str, file_path: Optional[str], line_number: Optional[int]) -> str:
    """
    Unique identity for a finding.
    Same tool + vuln_id + file:line == same logical issue.
    """
    return f"{tool}::{vuln_id}::{file_path or ''}::{line_number or 0}"


def ingest_reports(
    report_dir: str = ".",
    commit_sha: Optional[str] = None,
    branch: Optional[str] = None,
    triggered_by: str = "manual",
) -> SecDebtScanRun:
    """
    Main entry point.

    1. Parse each available report file.
    2. Upsert findings into secdebt_findings table.
       - New finding  → insert with first_seen = now
       - Known finding → update last_seen + recalculate debt score
       - Previously seen but absent now → mark is_resolved = True
    3. Create a SecDebtScanRun record with aggregate stats.
    4. Return the SecDebtScanRun instance.
    """
    now = datetime.now(UTC)
    all_parsed: list[dict] = []
    tools_ingested: list[str] = []

    # --- Step 1: Parse all available report files ---
    for tool, filename in REPORT_FILES.items():
        path = os.path.join(report_dir, filename)
        parser = PARSERS[tool]
        try:
            findings = parser(path)
            if findings:
                all_parsed.extend(findings)
                tools_ingested.append(tool)
                logger.info("Ingested %d findings from %s", len(findings), tool)
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Error parsing %s report: %s", tool, exc)

    # --- Step 2: Build a lookup of all current open findings in DB ---
    existing_open: dict[str, SecDebtFinding] = {}
    for finding in SecDebtFinding.query.filter_by(is_resolved=False).all():
        key = _make_dedup_key(
            finding.tool, finding.vuln_id, finding.file_path, finding.line_number
        )
        existing_open[key] = finding

    # --- Step 3: Process parsed findings ---
    seen_keys: set[str] = set()
    new_count = 0

    for item in all_parsed:
        key = _make_dedup_key(
            item["tool"], item["vuln_id"], item.get("file_path"), item.get("line_number")
        )
        seen_keys.add(key)

        if key in existing_open:
            # Update existing finding
            finding = existing_open[key]
            finding.last_seen = now
            finding.severity = item["severity"]
            finding.reachability = item.get("reachability", 0.5)
            finding.raw_snippet = item.get("raw_snippet")
            finding.commit_sha = commit_sha
            finding.update_debt_score()
        else:
            # New finding
            finding = SecDebtFinding(
                tool=item["tool"],
                vuln_id=item["vuln_id"],
                title=item["title"],
                description=item.get("description"),
                file_path=item.get("file_path"),
                line_number=item.get("line_number"),
                severity=item["severity"],
                reachability=item.get("reachability", 0.5),
                first_seen=now,
                last_seen=now,
                raw_snippet=item.get("raw_snippet"),
                commit_sha=commit_sha,
            )
            finding.update_debt_score()
            db.session.add(finding)
            new_count += 1

    # --- Step 4: Resolve findings that disappeared ---
    resolved_count = 0
    for key, finding in existing_open.items():
        if key not in seen_keys and tools_ingested:
            # Only auto-resolve if we had a successful run for that tool
            if finding.tool in tools_ingested:
                finding.is_resolved = True
                finding.resolved_at = now
                resolved_count += 1

    db.session.flush()

    # --- Step 5: Compute totals ---
    open_findings = SecDebtFinding.query.filter_by(is_resolved=False).all()
    total_score = sum(f.debt_score for f in open_findings)
    total_findings = len(open_findings)

    # --- Step 6: Create scan run record ---
    run = SecDebtScanRun(
        run_at=now,
        commit_sha=commit_sha,
        branch=branch,
        tools_ingested=",".join(tools_ingested),
        total_findings=total_findings,
        new_findings=new_count,
        resolved_findings=resolved_count,
        total_debt_score=round(total_score, 2),
        triggered_by=triggered_by,
    )
    db.session.add(run)
    db.session.commit()

    logger.info(
        "Ingest complete: %d total findings, %d new, %d resolved, score=%.2f",
        total_findings, new_count, resolved_count, total_score,
    )
    return run


def get_dashboard_stats() -> dict:
    """
    Aggregate stats for the dashboard summary cards.
    Returns a dict ready to pass to the Jinja template.
    """
    open_findings = SecDebtFinding.query.filter_by(is_resolved=False).all()

    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_tool = {}
    total_score = 0.0
    top_findings = []

    for f in open_findings:
        sev = f.severity.upper()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_tool[f.tool] = by_tool.get(f.tool, 0) + 1
        total_score += f.debt_score
        top_findings.append(f)

    # Sort by debt score descending for "fix these first" suggestions
    top_findings.sort(key=lambda x: x.debt_score, reverse=True)

    last_run = SecDebtScanRun.query.order_by(SecDebtScanRun.run_at.desc()).first()

    # Score history for the sparkline chart (last 10 runs)
    history = (
        SecDebtScanRun.query
        .order_by(SecDebtScanRun.run_at.asc())
        .limit(10)
        .all()
    )

    return {
        "total_findings": len(open_findings),
        "total_score": round(total_score, 2),
        "by_severity": by_severity,
        "by_tool": by_tool,
        "top_findings": top_findings[:20],   # top 20 to fix
        "all_findings": open_findings,
        "last_run": last_run,
        "history": history,
    }
