"""Add the bounded campaign operations ring (SPEC-14)."""
from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

_EMPTY_RING = (
    '{"schema": "aria.campaign.operations.v1", "generation": 0, '
    '"last_activity_at": null, "last_successful_at": null, "events": []}'
)


def upgrade():
    op.add_column(
        "autonomous_campaigns",
        sa.Column("operations", sa.JSON(), nullable=False,
                  server_default=sa.text("'" + _EMPTY_RING + "'::json")),
    )


def downgrade():
    op.drop_column("autonomous_campaigns", "operations")
