"""Validate retention SQL binds before dispatch to PostgreSQL."""
import unittest
from unittest.mock import AsyncMock

from sqlalchemy.dialects import postgresql
from worker.store import JobStore


class WorkerRetentionSQLTests(unittest.IsolatedAsyncioTestCase):
    async def test_retention_statement_has_no_phantom_json_binds(self):
        store = object.__new__(JobStore)
        store.owner = AsyncMock()
        store.backend_pid = 42
        store.owner.scalar.return_value = 42

        async def validate(statement, parameters):
            # This raises for JSON literals accidentally parsed as :true binds.
            bound = statement.compile(dialect=postgresql.dialect()).construct_params(parameters)
            self.assertEqual(set(bound), {'now'})
            self.assertIsInstance(bound['now'], str)

        store.owner.execute.side_effect = validate
        await store.expire_http()
        store.owner.execute.assert_awaited_once()
        store.owner.commit.assert_awaited_once()

    async def test_retention_refuses_a_replaced_database_connection(self):
        store = object.__new__(JobStore)
        store.owner = AsyncMock()
        store.backend_pid = 42
        store.owner.scalar.return_value = 43
        with self.assertRaisesRegex(RuntimeError, 'ownership was lost'):
            await store.expire_http()
        store.owner.execute.assert_not_awaited()
        store.owner.commit.assert_not_awaited()
