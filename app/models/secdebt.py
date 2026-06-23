from datetime import UTC, datetime

from app import db


class SecDebtFinding(db.Model):
    __tablename__ = "secdebt_findings"

    id = db.Column(db.Integer, primary_key=True)
    tool = db.Column(db.String(50), nullable=False)
    vuln_id = db.Column(db.String(200), nullable=False)
    title = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), nullable=False, default="MEDIUM")
    reachability = db.Column(db.Float, default=0.5)
    file_path = db.Column(db.String(500), nullable=True)
    line_number = db.Column(db.Integer, nullable=True)
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)
    is_resolved = db.Column(db.Boolean, default=False)
    resolved_at = db.Column(db.DateTime, nullable=True)
    debt_score = db.Column(db.Float, default=0.0)
    raw_snippet = db.Column(db.Text, nullable=True)
    commit_sha = db.Column(db.String(64), nullable=True)

    __table_args__ = (
        db.UniqueConstraint(
            "tool", "vuln_id", "file_path", "line_number", name="uq_secdebt_finding_key"
        ),
    )

    def severity_score(self):
        return {
            "CRITICAL": 10.0,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5,
            "INFO": 1.0,
            "WARNING": 2.5,
        }.get((self.severity or "MEDIUM").upper(), 5.0)

    def age_days(self):
        first_seen = self.first_seen
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=UTC)
        return max(0, (datetime.now(UTC) - first_seen).days)

    def interest_multiplier(self):
        age = self.age_days()
        if age < 7:
            return 1.0
        if age < 30:
            return 1.5
        return 2.0

    def calculate_debt_score(self):
        severity_component = self.severity_score() * 0.5
        age_component = min(self.age_days(), 90) * 0.3
        reachability_component = (self.reachability or 0.5) * 10 * 0.2
        return round((severity_component + age_component + reachability_component) * self.interest_multiplier(), 2)

    def update_debt_score(self):
        self.debt_score = self.calculate_debt_score()


class SecDebtScanRun(db.Model):
    __tablename__ = "secdebt_scan_runs"

    id = db.Column(db.Integer, primary_key=True)
    run_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)
    commit_sha = db.Column(db.String(64), nullable=True)
    branch = db.Column(db.String(200), nullable=True)
    tools_ingested = db.Column(db.String(200), nullable=True)
    total_findings = db.Column(db.Integer, default=0)
    new_findings = db.Column(db.Integer, default=0)
    resolved_findings = db.Column(db.Integer, default=0)
    total_debt_score = db.Column(db.Float, default=0.0)
    triggered_by = db.Column(db.String(100), nullable=True)
