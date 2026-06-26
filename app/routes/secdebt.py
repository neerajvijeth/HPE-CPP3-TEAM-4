"""
SecDebt-Optimizer Flask Blueprint
==================================
Routes:
  GET  /secdebt                   → Dashboard page
  GET  /secdebt/api/stats         → JSON stats for live refresh
  GET  /secdebt/api/findings      → JSON list of findings (filterable)
  POST /secdebt/api/ingest        → Trigger ingest (from GitHub Actions or manually)
  POST /secdebt/api/resolve/<id>  → Manually mark a finding resolved
  GET  /secdebt/history           → Scan run history page

Authentication: login_required (same as rest of the app).
The /api/ingest endpoint additionally requires an INGEST_TOKEN header
so GitHub Actions can call it securely without a session cookie.
"""

import os
import logging
from datetime import datetime, UTC

from flask import (
    Blueprint, render_template, jsonify, request,
    abort, current_app
)
from flask_login import login_required, current_user

from app import db
from app import csrf
from app.models.secdebt import SecDebtFinding, SecDebtScanRun
from app.utils.secdebt_ingest import ingest_reports, get_dashboard_stats
from app.utils.logger import log_event

logger = logging.getLogger(__name__)

secdebt_bp = Blueprint("secdebt", __name__, url_prefix="/secdebt")


# ---------------------------------------------------------------------------
# Helper: token authentication for API endpoints called by GitHub Actions
# ---------------------------------------------------------------------------

def _check_ingest_token() -> bool:
    """
    Validates the X-Ingest-Token header against SECDEBT_INGEST_TOKEN env var.
    Returns True if valid, False otherwise.
    """
    token = os.environ.get("SECDEBT_INGEST_TOKEN", "")
    if not token:
        # If no token configured, only allow logged-in admin users
        return False
    provided = request.headers.get("X-Ingest-Token", "")
    return provided == token


# ---------------------------------------------------------------------------
# Dashboard (main page)
# ---------------------------------------------------------------------------

@secdebt_bp.route("/")
@login_required
def dashboard():
    stats = get_dashboard_stats()
    log_event(
        "secdebt_dashboard_view",
        user_id=current_user.id,
        ip_address=request.remote_addr,
    )
    return render_template("secdebt/dashboard.html", **stats)


# ---------------------------------------------------------------------------
# Scan history page
# ---------------------------------------------------------------------------

@secdebt_bp.route("/history")
@login_required
def history():
    runs = (
        SecDebtScanRun.query
        .order_by(SecDebtScanRun.run_at.desc())
        .limit(50)
        .all()
    )
    return render_template("secdebt/history.html", runs=runs)


# ---------------------------------------------------------------------------
# API: live stats (for JS auto-refresh on dashboard)
# ---------------------------------------------------------------------------

@secdebt_bp.route("/api/stats")
@login_required
def api_stats():
    stats = get_dashboard_stats()
    return jsonify({
        "total_findings": stats["total_findings"],
        "total_score": stats["total_score"],
        "by_severity": stats["by_severity"],
        "by_tool": stats["by_tool"],
        "last_run": stats["last_run"].run_at.isoformat() if stats["last_run"] else None,
        "history": [
            {
                "run_at": r.run_at.isoformat(),
                "total_score": r.total_debt_score,
                "total_findings": r.total_findings,
            }
            for r in stats["history"]
        ],
    })


# ---------------------------------------------------------------------------
# API: findings list with filtering
# ---------------------------------------------------------------------------

@secdebt_bp.route("/api/findings")
@login_required
def api_findings():
    tool = request.args.get("tool")
    severity = request.args.get("severity")
    resolved = request.args.get("resolved", "false").lower() == "true"
    sort_by = request.args.get("sort", "debt_score")   # debt_score | severity | age

    query = SecDebtFinding.query.filter_by(is_resolved=resolved)
    if tool:
        query = query.filter(SecDebtFinding.tool == tool)
    if severity:
        query = query.filter(SecDebtFinding.severity == severity.upper())

    if sort_by == "debt_score":
        query = query.order_by(SecDebtFinding.debt_score.desc())
    elif sort_by == "severity":
        query = query.order_by(SecDebtFinding.severity.desc())
    else:
        query = query.order_by(SecDebtFinding.first_seen.asc())

    findings = query.limit(200).all()

    return jsonify([
        {
            "id": f.id,
            "tool": f.tool,
            "vuln_id": f.vuln_id,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "reachability": f.reachability,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "first_seen": f.first_seen.isoformat(),
            "last_seen": f.last_seen.isoformat(),
            "age_days": f.age_days(),
            "interest_multiplier": f.interest_multiplier(),
            "debt_score": f.debt_score,
            "is_resolved": f.is_resolved,
        }
        for f in findings
    ])


# ---------------------------------------------------------------------------
# API: trigger ingest
# Called by GitHub Actions workflow (with X-Ingest-Token header)
# or by admin from the dashboard (with session auth).
# ---------------------------------------------------------------------------

@secdebt_bp.route("/api/ingest", methods=["POST"])
@csrf.exempt
def api_ingest():
    """
    Accepts JSON body:
    {
      "report_dir": "/workspace",       (optional, defaults to current dir)
      "commit_sha": "abc123",           (optional)
      "branch": "main",                 (optional)
      "triggered_by": "github-actions"  (optional)
    }
    Authentication: X-Ingest-Token header OR logged-in admin.
    """
    # Auth: token OR logged-in admin
    token_valid = _check_ingest_token()
    if not token_valid:
        if not (current_user.is_authenticated and current_user.is_admin()):
            abort(403)

    data = request.get_json(silent=True) or {}
    report_dir = data.get("report_dir", ".")
    commit_sha = data.get("commit_sha")
    branch = data.get("branch")
    triggered_by = data.get("triggered_by", "api")

    try:
        run = ingest_reports(
            report_dir=report_dir,
            commit_sha=commit_sha,
            branch=branch,
            triggered_by=triggered_by,
        )
        logger.info("Ingest triggered via API by %s", triggered_by)
        return jsonify({
            "status": "ok",
            "run_id": run.id,
            "total_findings": run.total_findings,
            "new_findings": run.new_findings,
            "resolved_findings": run.resolved_findings,
            "total_debt_score": run.total_debt_score,
            "tools_ingested": run.tools_ingested,
        }), 200
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Ingest failed: %s", exc)
        return jsonify({"status": "error", "message": str(exc)}), 500


# ---------------------------------------------------------------------------
# API: manually resolve a finding
# ---------------------------------------------------------------------------

@secdebt_bp.route("/api/resolve/<int:finding_id>", methods=["POST"])
@login_required
def api_resolve(finding_id: int):
    if not current_user.is_admin():
        abort(403)

    finding = SecDebtFinding.query.get_or_404(finding_id)
    finding.is_resolved = True
    finding.resolved_at = datetime.now(UTC)
    db.session.commit()

    log_event(
        "secdebt_finding_resolved",
        user_id=current_user.id,
        details=f"Resolved {finding.tool}:{finding.vuln_id}",
        ip_address=request.remote_addr,
    )
    return jsonify({"status": "ok", "finding_id": finding_id})


# ---------------------------------------------------------------------------
# API: reopen a resolved finding
# ---------------------------------------------------------------------------

@secdebt_bp.route("/api/reopen/<int:finding_id>", methods=["POST"])
@login_required
def api_reopen(finding_id: int):
    if not current_user.is_admin():
        abort(403)

    finding = SecDebtFinding.query.get_or_404(finding_id)
    finding.is_resolved = False
    finding.resolved_at = None
    finding.update_debt_score()
    db.session.commit()

    return jsonify({"status": "ok", "finding_id": finding_id})
