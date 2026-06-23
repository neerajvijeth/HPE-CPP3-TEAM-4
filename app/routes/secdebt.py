import logging
import os
from datetime import UTC, datetime

from flask import Blueprint, abort, jsonify, render_template, request
from flask_login import current_user, login_required

from app import db
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
    })


@secdebt_bp.route("/api/findings")
@login_required
def api_findings():
    query = SecDebtFinding.query.filter_by(is_resolved=False)
    tool = request.args.get("tool")
    severity = request.args.get("severity")
    if tool:
        query = query.filter_by(tool=tool)
    if severity:
        query = query.filter_by(severity=severity.upper())

    findings = query.order_by(SecDebtFinding.debt_score.desc()).limit(200).all()
    return jsonify([
        {
            "id": finding.id,
            "tool": finding.tool,
            "vuln_id": finding.vuln_id,
            "title": finding.title,
            "severity": finding.severity,
            "debt_score": finding.debt_score,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "first_seen": finding.first_seen.isoformat(),
            "last_seen": finding.last_seen.isoformat(),
            "age_days": finding.age_days(),
        }
        for finding in findings
    ])


@secdebt_bp.route("/api/ingest", methods=["POST"])
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
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("SecDebt ingest failed")
        return jsonify({"status": "error", "message": str(exc)}), 500

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
