"""P2 regressions: responsiveness, bounded admission, strict playbook matching."""
import asyncio
import threading
import time
from unittest.mock import patch, AsyncMock

from tests.support import OfflineCase
from memory.vector_store import EmbeddingWorker, VectorStore
from memory.playbook_store import PlaybookStore, PlaybookModel


class P2Tests(OfflineCase):
    async def test_embedding_does_not_block_loop_and_has_no_queue(self):
        worker = EmbeddingWorker()
        started = threading.Event()
        release = threading.Event()

        def slow_encode(text):
            started.set()
            release.wait(3)
            return [1.0]

        try:
            with patch('memory.vector_store._embedder.encode', side_effect=slow_encode):
                first = asyncio.create_task(worker.encode('hello'))
                for _ in range(100):
                    if started.is_set():
                        break
                    await asyncio.sleep(.005)
                self.assertTrue(started.is_set())
                self.assertIsNone(await worker.encode('busy'))
                first.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await first
                self.assertIsNone(await worker.encode('still busy'))
                release.set()
                for _ in range(100):
                    if not worker._busy:
                        break
                    await asyncio.sleep(.005)
                self.assertFalse(worker._busy)
        finally:
            release.set()
            worker._executor.shutdown(wait=True)

    async def test_legacy_memory_never_loads_model(self):
        store = VectorStore()
        with patch('memory.vector_store._embedder.encode', side_effect=AssertionError):
            store.add('s', 'ssh service found')
            self.assertEqual(len(store.query('s', 'ssh')), 1)
            self.assertIsNone(await EmbeddingWorker().encode('x' * 8193))

    async def test_exact_service_and_version_are_required(self):
        store = PlaybookStore()
        pb = PlaybookModel('id', 'ssh', store._make_version_pattern('2.3.4'),
                           'audit', [], 1.0, 1, '', success_count=1)
        with patch.object(store, '_load_cache', AsyncMock(return_value={'id': pb})):
            self.assertIsNone(await store.get_best_playbook('libssh', '2.3.4'))
            self.assertIsNone(await store.get_best_playbook('ssh', '2.3.5'))
            self.assertIsNone(await store.get_best_playbook('ssh', ''))
            self.assertEqual(await store.get_best_playbook('ssh', '2.3.4'), pb)
        pb.version_pattern = r'^2\.3\..*$'
        with patch.object(store, '_load_cache', AsyncMock(return_value={'id': pb})):
            self.assertIsNone(await store.get_best_playbook('ssh', '2.3.5'))
        for version in ('2', '2.3', '2.3.4', '2+beta'):
            self.assertTrue(__import__('re').fullmatch(store._make_version_pattern(version), version))

    async def test_ready_fails_closed(self):
        with patch('api.main.init_db', AsyncMock(side_effect=RuntimeError('offline'))):
            self.assertEqual((await self.client.get('/api/ready')).status_code, 503)

    async def test_migration_sql_is_versioned_and_frozen(self):
        from io import StringIO
        from alembic import command
        from alembic.config import Config
        from migrations.schema_v1 import Base as Frozen
        from memory.database_models import Base
        self.assertEqual(set(Frozen.metadata.tables), set(Base.metadata.tables))
        for name in Frozen.metadata.tables:
            self.assertEqual(list(Frozen.metadata.tables[name].columns.keys()),
                             list(Base.metadata.tables[name].columns.keys()))
        output = StringIO()
        command.upgrade(Config('alembic.ini', output_buffer=output), 'head', sql=True)
        sql = output.getvalue()
        self.assertIn('CREATE TABLE alembic_version', sql)
        for name in Base.metadata.tables:
            self.assertIn('CREATE TABLE ' + name, sql)
        output = StringIO()
        command.downgrade(Config('alembic.ini', output_buffer=output), '0001:base', sql=True)
        for name in Base.metadata.tables:
            self.assertIn('DROP TABLE ' + name, output.getvalue())

    async def test_request_ids_are_generated_per_request(self):
        first = await self.client.get('/api/health', headers={'X-Request-ID': 'untrusted'})
        second = await self.client.get('/api/health')
        self.assertEqual(len(first.headers['X-Request-ID']), 32)
        self.assertNotEqual(first.headers['X-Request-ID'], second.headers['X-Request-ID'])
