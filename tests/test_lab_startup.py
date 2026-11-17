"""Exercise bounded startup failure and cancellation without infrastructure."""
import asyncio
from pathlib import Path
import time
from unittest.mock import AsyncMock, patch

from tests.support import OfflineCase
from deploy.lab.wait_dependencies import wait_for_dependencies


class LabStartupTests(OfflineCase):
    async def test_eventually_ready_retries_without_starting_application(self):
        probe = AsyncMock(side_effect=[ConnectionRefusedError(), RuntimeError(), None])
        with patch('api.main.lifespan', side_effect=AssertionError('API must not start')):
            self.assertTrue(await wait_for_dependencies(probe, timeout=.2, interval=.005))
        self.assertEqual(probe.await_count, 3)

    async def test_permanently_unavailable_or_hung_probe_stops_within_deadline(self):
        async def hung():
            await asyncio.sleep(10)
        for probe in (AsyncMock(side_effect=ConnectionRefusedError('private detail')), hung):
            begin = time.monotonic()
            self.assertFalse(await wait_for_dependencies(probe, timeout=.03, interval=.005))
            self.assertLess(time.monotonic() - begin, 1)

    async def test_cancellation_does_not_turn_into_readiness_or_retry(self):
        probe = AsyncMock(side_effect=asyncio.CancelledError())
        with self.assertRaises(asyncio.CancelledError):
            await wait_for_dependencies(probe, timeout=.1, interval=.005)
        probe.assert_awaited_once()

    async def test_invalid_bounds_do_not_probe(self):
        for timeout, interval in ((0, 1), (121, 1), (1, 0), (1, 2)):
            probe = AsyncMock()
            with self.subTest(timeout=timeout, interval=interval), self.assertRaises(ValueError):
                await wait_for_dependencies(probe, timeout=timeout, interval=interval)
            probe.assert_not_awaited()

    async def test_templates_bound_restart_storm_and_preserve_process_containment(self):
        root = Path(__file__).resolve().parents[1]
        for name in ('deploy/aria.service', 'deploy/lab/aria-fedora.service.in'):
            unit = (root/name).read_text()
            with self.subTest(unit=name):
                self.assertIn('StartLimitIntervalSec=300', unit)
                self.assertIn('StartLimitBurst=5', unit)
                self.assertIn('KillMode=control-group', unit)
                self.assertIn('--workers 1', unit)
                self.assertIn('--host 127.0.0.1', unit)
        lab = (root/'deploy/lab/aria-fedora.service.in').read_text()
        dependencies = (root/'deploy/lab/aria-lab-dependencies.service.in').read_text()
        self.assertIn('Requires=aria-lab-dependencies.service', lab)
        self.assertIn('After=network.target aria-lab-dependencies.service', lab)
        # Podman helper processes belong to a separate remaining-active unit;
        # stopping/restarting the API must never kill database/cache helpers.
        self.assertNotIn('podman', lab)
        self.assertIn('RemainAfterExit=yes', dependencies)
        self.assertLess(dependencies.index('podman start aria-postgres aria-redis'),
                        dependencies.index('-m deploy.lab.wait_dependencies'))
