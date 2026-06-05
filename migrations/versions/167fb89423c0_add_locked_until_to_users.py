"""add locked_until to users

Revision ID: 167fb89423c0
Revises: 76c56f34b481
Create Date: 2026-06-05 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "167fb89423c0"
down_revision = "76c56f34b481"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("locked_until", sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column("users", "locked_until")
