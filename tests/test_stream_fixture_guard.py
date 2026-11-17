"""The passive telemetry harness cannot attach to an owner deployment."""
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from integration.reliability_stream import configure_fixture
from tests.support import OfflineCase


class StreamFixtureGuardTests(OfflineCase):
    def test_missing_fixture_marker_owner_database_and_enabled_worker_are_denied(self):
        for marker, database, worker in (
            ('0', 'aria_reliability_fixture_test', ''),
            ('1', 'owner_database', ''),
            ('1', 'other_test', ''),
            ('1', 'aria_reliability_fixture_test', 'http://worker.invalid'),
        ):
            with self.subTest(marker=marker, database=database, worker=worker), \
                 patch.dict(os.environ, {'ARIA_RELIABILITY_BROWSER': marker}), \
                 patch('config.settings.settings.DATABASE_URL', 'postgresql+asyncpg://fixture@127.0.0.1/'+database), \
                 patch('config.settings.settings.KALI_AGENT_URL', worker):
                original = object()
                app = SimpleNamespace(router=SimpleNamespace(lifespan_context=original))
                with self.assertRaises(RuntimeError):
                    configure_fixture(app, Path('/unopened-fixture-directory'))
                self.assertIs(app.router.lifespan_context, original)
