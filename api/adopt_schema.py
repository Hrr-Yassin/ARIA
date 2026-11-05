"""Explicitly baseline a backed-up legacy database only if it matches v10 exactly."""
import asyncio
from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.autogenerate import compare_metadata
from sqlalchemy import inspect
from migrations.schema_v1 import Base
from memory.database_models import engine


def validate(connection):
    tables = set(inspect(connection).get_table_names())
    if tables != set(Base.metadata.tables):
        raise RuntimeError('Legacy table inventory differs; restore to a staging database and reconcile first')
    inspector = inspect(connection)
    if inspector.get_view_names():
        raise RuntimeError('Unexpected legacy views; automatic adoption refused')
    for name, table in Base.metadata.tables.items():
        expected_pk = [column.name for column in table.primary_key]
        if (inspector.get_pk_constraint(name)['constrained_columns'] != expected_pk
                or inspector.get_check_constraints(name)):
            raise RuntimeError('Legacy constraints differ; automatic adoption refused')
    expected_enums = {column.type.name: column.type.enums
                      for table in Base.metadata.tables.values()
                      for column in table.columns if hasattr(column.type, 'enums')}
    actual_enums = {enum['name']: enum['labels'] for enum in inspector.get_enums()}
    if expected_enums != actual_enums:
        raise RuntimeError('Legacy enum definitions differ; automatic adoption refused')
    differences = compare_metadata(MigrationContext.configure(connection,
        opts={'compare_type': True, 'compare_server_default': True}), Base.metadata)
    if differences:
        # Do not print database contents, connection strings or defaults.
        raise RuntimeError('Legacy schema differs from v10; automatic adoption refused')


async def check():
    try:
        async with engine.connect() as connection:
            await connection.run_sync(validate)
    finally:
        await engine.dispose()


if __name__ == '__main__':
    asyncio.run(check())
    command.stamp(Config('alembic.ini'), '0001')
    print('Schema verified and versioned at 0001')
