"""Version the complete v10 baseline; apply to an empty database only."""
from alembic import op
from migrations.schema_v1 import Base

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    Base.metadata.create_all(op.get_bind(), checkfirst=False)


def downgrade():
    bind = op.get_bind()
    Base.metadata.drop_all(bind, checkfirst=False)
    # PostgreSQL ENUMs are owned by this baseline, including names shared by columns.
    enums = {column.type.name: column.type for table in Base.metadata.tables.values()
             for column in table.columns if hasattr(column.type, 'enums')}
    for enum in enums.values():
        enum.drop(bind, checkfirst=True)
