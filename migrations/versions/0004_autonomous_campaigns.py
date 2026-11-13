"""Durable autonomous campaign schedules, supervisor leases and budgets."""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "autonomous_campaigns",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("session_id", sa.String(36),
                  sa.ForeignKey("pentest_sessions.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("owner_id", sa.String(36), sa.ForeignKey("users.id"),
                  nullable=False),
        sa.Column("state", sa.String(30), nullable=False),
        sa.Column("active_key", sa.String(36), nullable=True),
        sa.Column("goal", sa.String(50), nullable=False),
        sa.Column("target", sa.String(500), nullable=False),
        sa.Column("skill_level", sa.String(20), nullable=False),
        sa.Column("objective", sa.Text(), nullable=False),
        sa.Column("max_steps", sa.Integer(), nullable=False),
        sa.Column("auto_risk_threshold", sa.String(20), nullable=False),
        sa.Column("scope_digest", sa.String(64), nullable=False),
        sa.Column("auth_revision", sa.Integer(), nullable=False),
        sa.Column("worker_epoch", sa.Integer(), nullable=False),
        sa.Column("schedule", sa.JSON(), nullable=False),
        sa.Column("budget", sa.JSON(), nullable=False),
        sa.Column("usage", sa.JSON(), nullable=False),
        sa.Column("retry", sa.JSON(), nullable=False),
        sa.Column("run_id", sa.String(36), nullable=True),
        sa.Column("has_started", sa.Boolean(), nullable=False),
        sa.Column("auto_resume", sa.Boolean(), nullable=False),
        sa.Column("lease_holder", sa.String(64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(), nullable=True),
        sa.Column("next_action_at", sa.DateTime(), nullable=True),
        sa.Column("pause_reason", sa.String(200), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("active_key", name="uq_autonomous_campaigns_active_key"),
    )
    op.create_index("ix_autonomous_campaigns_session_id", "autonomous_campaigns",
                    ["session_id"])
    op.create_index("ix_autonomous_campaigns_owner_id", "autonomous_campaigns",
                    ["owner_id"])
    op.create_index("ix_autonomous_campaigns_state", "autonomous_campaigns",
                    ["state"])
    op.create_index("ix_autonomous_campaigns_next_action_at", "autonomous_campaigns",
                    ["next_action_at"])


def downgrade():
    op.drop_table("autonomous_campaigns")
