import logging
import os
from datetime import UTC, datetime

from flask import Blueprint, abort, jsonify, render_template, request
from flask_login import current_user, login_required

from app import csrf, db
from app.models.secdebt import SecDebtFinding, SecDebtScanRun
from app.utils.logger import log_event
from app.utils.secdebt_ingest import get_dashboard_stats, ingest_reports

logger = logging.getLogger(__name__)
secdebt_bp = Blueprint("secdebt", __name__, url_prefix="/secdebt")


def _check_ingest_token():
    expected = os.environ.get("SECDEBT_INGEST_TOKEN", "")
    provided = request.headers.get("X-Ingest-Token", "")
    return bool(expected) and provided == expected


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


@secdebt_bp.route("/history")
@login_required
def history():
    runs = SecDebtScanRun.query.order_by(SecDebtScanRun.run_at.desc()).limit(50).all()
    return render_template("secdebt/history.html", runs=runs)


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
                "run_at": run.run_at.isoformat(),
                "total_score": run.total_debt_score,
                "total_findings": run.total_findings,
            }
            for run in stats["history"]
        ],
    })


@secdebt_bp.route("/api/findings")
@login_required
def api_findings():
    tool = request.args.get("tool")
    severity = request.args.get("severity")
    resolved = request.args.get("resolved", "false").lower() == "true"
    sort_by = request.args.get("sort", "debt_score")

    query = SecDebtFinding.query.filter_by(is_resolved=resolved)
    if tool:
        query = query.filter_by(tool=tool)
    if severity:
        query = query.filter_by(severity=severity.upper())

    if sort_by == "age":
        query = query.order_by(SecDebtFinding.first_seen.asc())
    elif sort_by == "severity":
        query = query.order_by(SecDebtFinding.severity.desc())
    else:
        query = query.order_by(SecDebtFinding.debt_score.desc())

    findings = query.limit(200).all()
    return jsonify([
        {
            "id": finding.id,
            "tool": finding.tool,
            "vuln_id": finding.vuln_id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "reachability": finding.reachability,
            "debt_score": finding.debt_score,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "first_seen": finding.first_seen.isoformat(),
            "last_seen": finding.last_seen.isoformat(),
            "age_days": finding.age_days(),
            "interest_multiplier": finding.interest_multiplier(),
            "is_resolved": finding.is_resolved,
        }
        for finding in findings
    ])


@secdebt_bp.route("/api/ingest", methods=["POST"])
@csrf.exempt
def api_ingest():
    if not _check_ingest_token():
        if not (current_user.is_authenticated and current_user.is_admin()):
            abort(403)

    data = request.get_json(silent=True) or {}

    try:
        run = ingest_reports(
            commit_sha=data.get("commit_sha"),
            branch=data.get("branch"),
            triggered_by=data.get("triggered_by", "api"),
        )
    except Exception:  # pylint: disable=broad-except
        logger.exception("SecDebt ingest failed")
        return jsonify({
            "status": "error",
            "message": "SecDebt ingest failed. Check server logs for details.",
        }), 500

    return jsonify({
        "status": "ok",
        "run_id": run.id,
        "total_findings": run.total_findings,
        "new_findings": run.new_findings,
        "resolved_findings": run.resolved_findings,
        "total_debt_score": run.total_debt_score,
        "tools_ingested": run.tools_ingested,
    })


@secdebt_bp.route("/api/resolve/<int:finding_id>", methods=["POST"])
@login_required
def api_resolve(finding_id):
    if not current_user.is_admin():
        abort(403)

    finding = SecDebtFinding.query.get_or_404(finding_id)
    finding.is_resolved = True
    finding.resolved_at = datetime.now(UTC)
    db.session.commit()
    return jsonify({"status": "ok", "finding_id": finding_id})
