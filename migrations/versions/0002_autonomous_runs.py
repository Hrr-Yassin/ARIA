"""Durable autonomous run snapshots. Existing chat records are preserved."""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("autonomous_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("session_id", sa.String(36), sa.ForeignKey("pentest_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("state", sa.String(30), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False))
    op.create_index("ix_autonomous_runs_session_id", "autonomous_runs", ["session_id"])


def downgrade():
    op.drop_table("autonomous_runs")
