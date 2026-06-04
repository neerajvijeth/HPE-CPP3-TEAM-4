"""
SecDebt-Optimizer: Database Migration
======================================
Run this ONCE on the EC2 instance to create the two new tables
(secdebt_findings, secdebt_scan_runs) inside the existing PostgreSQL container.

Since your project uses Flask-Migrate, you have two options:

OPTION A — Flask-Migrate (recommended, already in your stack):
  1. Copy new model file into place
  2. Register blueprint (see INTEGRATION.md)
  3. Run:
       docker exec securevault_secure_app flask db migrate -m "add secdebt tables"
       docker exec securevault_secure_app flask db upgrade

OPTION B — Direct create_all (quick, no migration files):
  Run this script directly:
       docker exec securevault_secure_app python /opt/securevault/secdebt_migrate.py

This script uses Option B for quick onboarding.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# These two env vars must be set (same as in .env on EC2)
# They are already set because your app starts with them.

from app import create_app, db
from app.models.secdebt import SecDebtFinding, SecDebtScanRun  # noqa: F401

app = create_app()

with app.app_context():
    # create_all only creates tables that don't exist — safe to run multiple times
    db.create_all()
    print("✅ SecDebt tables created (secdebt_findings, secdebt_scan_runs)")
    print("   Tables in DB:", [t.name for t in db.engine.dialect.get_table_names
                               if callable(getattr(db.engine.dialect, 'get_table_names', None))])
