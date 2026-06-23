"""add secdebt tables

Revision ID: 9c1f2d3e4a5b
Revises: 167fb89423c0
Create Date: 2026-06-23 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "9c1f2d3e4a5b"
down_revision = "167fb89423c0"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "secdebt_findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tool", sa.String(length=50), nullable=False),
        sa.Column("vuln_id", sa.String(length=200), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("reachability", sa.Float(), nullable=True),
        sa.Column("file_path", sa.String(length=500), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("is_resolved", sa.Boolean(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("debt_score", sa.Float(), nullable=True),
        sa.Column("raw_snippet", sa.Text(), nullable=True),
        sa.Column("commit_sha", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tool", "vuln_id", "file_path", "line_number", name="uq_secdebt_finding_key"
        ),
    )

    op.create_table(
        "secdebt_scan_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_at", sa.DateTime(), nullable=False),
        sa.Column("commit_sha", sa.String(length=64), nullable=True),
        sa.Column("branch", sa.String(length=200), nullable=True),
        sa.Column("tools_ingested", sa.String(length=200), nullable=True),
        sa.Column("total_findings", sa.Integer(), nullable=True),
        sa.Column("new_findings", sa.Integer(), nullable=True),
        sa.Column("resolved_findings", sa.Integer(), nullable=True),
        sa.Column("total_debt_score", sa.Float(), nullable=True),
        sa.Column("triggered_by", sa.String(length=100), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade():
    op.drop_table("secdebt_scan_runs")
    op.drop_table("secdebt_findings")
