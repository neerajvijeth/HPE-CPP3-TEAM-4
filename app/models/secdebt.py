"""
SecDebt-Optimizer Models
========================
Stores parsed vulnerability findings from CI/CD tool reports
(Bandit, Trivy, Pylint, OWASP Dependency-Check, SonarQube).

Table: secdebt_findings
  - Persists across workflow runs
  - Tracks first_seen so age-based debt scoring works
  - Uses existing PostgreSQL container (no new DB needed)
"""

from app import db
from datetime import datetime, UTC


class SecDebtFinding(db.Model):
    __tablename__ = "secdebt_findings"

    id = db.Column(db.Integer, primary_key=True)

    # --- Source identification ---
    tool = db.Column(db.String(50), nullable=False)        # bandit | trivy | pylint | owasp | sonar
    vuln_id = db.Column(db.String(200), nullable=False)    # CVE-xxx / B101 / W0611 / etc.
    title = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(500), nullable=True)   # source file if applicable
    line_number = db.Column(db.Integer, nullable=True)

    # --- Severity (CRITICAL/HIGH/MEDIUM/LOW/INFO) ---
    severity = db.Column(db.String(20), nullable=False, default="MEDIUM")

    # --- Reachability hint (from tool context) ---
    # 1.0 = directly reachable, 0.5 = indirect, 0.0 = unreachable
    reachability = db.Column(db.Float, default=0.5)

    # --- Debt tracking ---
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)
    is_resolved = db.Column(db.Boolean, default=False)
    resolved_at = db.Column(db.DateTime, nullable=True)

    # --- Computed debt score (cached, recalculated on each ingest) ---
    debt_score = db.Column(db.Float, default=0.0)

    # --- Raw snippet from report for display ---
    raw_snippet = db.Column(db.Text, nullable=True)

    # --- Commit SHA that last surfaced this finding ---
    commit_sha = db.Column(db.String(64), nullable=True)

    def severity_score(self) -> float:
        """Numeric weight for severity level."""
        return {
            "CRITICAL": 10.0,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5,
            "INFO": 1.0,
            "WARNING": 2.5,  # pylint maps here
        }.get(self.severity.upper(), 5.0)

    def age_days(self) -> int:
        now = datetime.now(UTC)
        fs = self.first_seen
        if fs.tzinfo is None:
            fs = fs.replace(tzinfo=UTC)
        return max(0, (now - fs).days)

    def interest_multiplier(self) -> float:
        """
        Age-based interest multiplier:
          < 7 days  → 1.0x  (fresh)
          7-30 days → 1.5x  (accumulating)
          > 30 days → 2.0x  (high interest)
        """
        age = self.age_days()
        if age < 7:
            return 1.0
        if age < 30:
            return 1.5
        return 2.0

    def calculate_debt_score(self) -> float:
        """
        Weighted Scoring Algorithm (heuristics, no ML):
          Debt Score = (Severity × 0.5) + (Age in Days × 0.3) + (Reachability × 0.2)
        Then multiplied by the interest multiplier for long-standing debt.
        """
        severity_component = self.severity_score() * 0.5
        age_component = min(self.age_days(), 90) * 0.3   # cap age at 90 to bound score
        reachability_component = (self.reachability or 0.5) * 10 * 0.2
        raw = severity_component + age_component + reachability_component
        return round(raw * self.interest_multiplier(), 2)

    def update_debt_score(self):
        self.debt_score = self.calculate_debt_score()

    def __repr__(self):
        return f"<SecDebtFinding {self.tool}:{self.vuln_id} score={self.debt_score}>"


class SecDebtScanRun(db.Model):
    """
    Records each ingest run so you can see history over time.
    """
    __tablename__ = "secdebt_scan_runs"

    id = db.Column(db.Integer, primary_key=True)
    run_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)
    commit_sha = db.Column(db.String(64), nullable=True)
    branch = db.Column(db.String(200), nullable=True)
    tools_ingested = db.Column(db.String(200), nullable=True)   # comma-separated

    total_findings = db.Column(db.Integer, default=0)
    new_findings = db.Column(db.Integer, default=0)
    resolved_findings = db.Column(db.Integer, default=0)
    total_debt_score = db.Column(db.Float, default=0.0)

    triggered_by = db.Column(db.String(100), nullable=True)    # github-actions / manual

    def __repr__(self):
        return f"<SecDebtScanRun {self.id} at {self.run_at} score={self.total_debt_score}>"
