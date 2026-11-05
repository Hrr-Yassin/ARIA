"""Durable, request-bound Community replay approvals and outcomes."""
from alembic import op
import sqlalchemy as sa
revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("web_actions",
        sa.Column("id",sa.String(36),primary_key=True),
        sa.Column("session_id",sa.String(36),sa.ForeignKey("pentest_sessions.id",ondelete="CASCADE"),nullable=False),
        sa.Column("requester_id",sa.String(36),sa.ForeignKey("users.id"),nullable=False),
        sa.Column("evidence_id",sa.String(36),sa.ForeignKey("chat_logs.id"),nullable=False),
        sa.Column("state",sa.String(30),nullable=False),
        sa.Column("request_digest",sa.String(64),nullable=False),
        sa.Column("scope_digest",sa.String(64),nullable=False),
        sa.Column("protected_spec",sa.Text(),nullable=False),
        sa.Column("protected_response",sa.Text()),
        sa.Column("result",sa.JSON(),nullable=False),
        sa.Column("expires_at",sa.DateTime(),nullable=False),
        sa.Column("updated_at",sa.DateTime(),nullable=False))
    op.create_index("ix_web_actions_session_id","web_actions",["session_id"])


def downgrade():
    op.drop_table("web_actions")
