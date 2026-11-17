"""A fixed fixture Monday must work even after the host calendar passes it."""
from datetime import datetime, timezone, timedelta

from tests.support import OfflineCase
from tests.endurance_harness import SimulatedClock, monday_start, simulated_datetime


class SimulationClockTests(OfflineCase):
    async def test_guard_and_campaign_creation_share_expired_fixture_date(self):
        import memory.campaign_store as store
        import orchestrator.campaign_execution as guard
        real_store, real_guard = store.datetime, guard.datetime
        clock = SimulatedClock(monday_start(2000, 1, 3))
        with simulated_datetime(clock, campaign_store=True):
            self.assertEqual(store.datetime.now(timezone.utc), clock())
            self.assertEqual(guard.datetime.now(timezone.utc), clock())
            self.assertIsInstance(clock(), store.datetime)
            clock.advance(300)
            self.assertEqual(store.datetime.now(timezone.utc), clock())
        self.assertIs(store.datetime, real_store)
        self.assertIs(guard.datetime, real_guard)

    async def test_nested_clock_and_failed_context_restore_original_clock(self):
        import memory.campaign_store as store
        import orchestrator.campaign_execution as guard
        outer = SimulatedClock(monday_start())
        inner = SimulatedClock(outer()+timedelta(days=7))
        with simulated_datetime(outer, campaign_store=True):
            with self.assertRaises(ValueError):
                with simulated_datetime(inner):
                    self.assertEqual(guard.datetime.now(timezone.utc), inner())
                    raise ValueError('injected fixture failure')
            self.assertEqual(guard.datetime.now(timezone.utc), outer())
            self.assertEqual(store.datetime.now(timezone.utc), outer())
        self.assertIs(store.datetime, datetime)
        self.assertIs(guard.datetime, datetime)
