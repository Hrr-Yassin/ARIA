"""Bounded wall-clock soak for SPEC-15 endurance validation.

This is a *real-time* companion to the accelerated offline/PG simulations.  It
drives the real campaign supervisor, campaign ledger and campaign execution
guard against an in-memory campaign store with a deterministic synthetic run,
worker and model provider.  It never contacts a model provider, a real target,
a real worker or the database.

The workload is deliberately small: a 10-step synthetic campaign with a
compressed 1-5 second step interval, one mid-run process crash, and a wall
clock bound (default 60 seconds).  It verifies that the supervisor keeps a
single lease, never duplicates a worker dispatch, never bypasses the campaign
ledger, resumes from its checkpoint after recovery, and keeps durable state
bounded.  It is not evidence of eight-hour reliability; see
``docs/spec15-endurance-status.md``.

Usage:
    python integration/endurance_soak.py --seconds 60
"""
from __future__ import annotations

import argparse
import asyncio
import json
import resource
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config.settings import settings
from memory.campaign_store import (
    CampaignBudget, CampaignSchedule, CampaignSpec,
    parse_allowed_weekdays, within_window,
)
from orchestrator.campaign_supervisor import CampaignSupervisor
from tests.endurance_harness import (
    CAPABILITIES, DIGEST, EnginePlan, EnduranceCampaignStore, MemoryAccounting,
    SyntheticEngine, SyntheticWorker,
)

UTC = timezone.utc
OWNER = "soak-owner"
SESSION = "soak-session"
TARGET = "192.0.2.15"
STEPS = 10


@contextmanager
def _soak_settings(*, lease_seconds: int, retry_base_seconds: int):
    previous = (settings.CAMPAIGN_LEASE_SECONDS,
                settings.CAMPAIGN_RETRY_BASE_SECONDS)
    settings.CAMPAIGN_LEASE_SECONDS = lease_seconds
    settings.CAMPAIGN_RETRY_BASE_SECONDS = retry_base_seconds
    try:
        yield
    finally:
        (settings.CAMPAIGN_LEASE_SECONDS,
         settings.CAMPAIGN_RETRY_BASE_SECONDS) = previous


def _schedule() -> CampaignSchedule:
    """A synthetic window that covers the current wall-clock instant."""
    return CampaignSchedule(
        timezone="UTC",
        weekdays=list(parse_allowed_weekdays(settings.CAMPAIGN_ALLOWED_WEEKDAYS)),
        window_start="00:00", window_end="23:59",
        daily_runtime_seconds=3600)


async def run_soak(*, seconds: float, tick_seconds: float = 0.5,
                   lease_seconds: int = 3) -> dict:
    started = time.monotonic()
    clock = lambda: datetime.now(UTC)
    schedule = _schedule()
    plan = EnginePlan(
        required_successful_steps=STEPS,
        # Leave the crash/recovery reserve inside the wall-clock budget.
        step_interval_seconds=max(1.0, (seconds - 10.0) / STEPS),
        max_steps=12)
    store = EnduranceCampaignStore(clock=clock)
    context = {
        "owner_id": OWNER, "scope": {"targets": [TARGET]}, "target": TARGET,
        "scope_digest": DIGEST, "auth_revision": 4, "worker_epoch": 2,
        "worker_blocked": False,
    }

    async def context_loader(owner_id, session_id):
        return dict(context)

    async def capabilities():
        return dict(CAPABILITIES)

    async def planner_preflight(owner_id, session_id):
        return {"ready": True}

    async def worker_resume(owner_id, session_id):
        return None

    worker = SyntheticWorker(store, context_loader, clock)
    accounting = MemoryAccounting(store, clock, tokens_per_call=2000)
    engine = SyntheticEngine(
        store=store, accounting=accounting, worker=worker,
        context_loader=context_loader, clock=clock, plan=plan)

    def new_supervisor() -> CampaignSupervisor:
        return CampaignSupervisor(
            store=store, engine=engine, context_loader=context_loader,
            capabilities=capabilities, planner_preflight=planner_preflight,
            worker_resume=worker_resume, clock=clock)

    supervisor = new_supervisor()
    spec = CampaignSpec(
        session_id=SESSION, owner_id=OWNER, goal="discovery", target=TARGET,
        skill_level="expert", objective="Synthetic SPEC-15 wall-clock soak",
        max_steps=12, auto_risk_threshold="green_orange",
        schedule=schedule,
        budget=CampaignBudget(max_tokens=2_000_000,
                              max_cost_microusd=2_000_000),
        max_retries=2, scope_digest=DIGEST, auth_revision=4, worker_epoch=2,
        required_tools=["curl", "nmap"])
    campaign = await store.create(spec)
    campaign_id = campaign["id"]

    deadline = started + seconds
    crash_at = started + max(1.0, seconds / 2)
    crashed = False
    recoveries: list[str] = []
    steps_before_crash = 0
    ticks = 0
    window_violations: list[dict] = []
    last = time.monotonic()

    while time.monotonic() < deadline:
        now = clock()
        if not crashed and time.monotonic() >= crash_at:
            crashed = True
            steps_before_crash = len(engine.steps)
            engine.crash()
            supervisor = new_supervisor()
            # Let the old process lease expire in real wall-clock time.
            await asyncio.sleep(lease_seconds + 0.3)
            recoveries = list(await supervisor.recover(clock()))
        await supervisor.tick(now)
        current = time.monotonic()
        await engine.advance(current - last)
        last = current
        ticks += 1
        if not within_window(now, schedule):
            latest = [call for call in accounting.provider_calls if call.at == now]
            if latest:
                window_violations.append({"at": now.isoformat(),
                                          "calls": len(latest)})
        await asyncio.sleep(max(0.0, min(tick_seconds,
                                         deadline - time.monotonic())))

    row = await store.get(campaign_id)
    usage = row["usage"]
    reserved = sum(call.tokens for call in accounting.provider_calls)
    reported = sum(call.reported_tokens for call in accounting.provider_calls
                   if isinstance(call.reported_tokens, int))
    unique_keys = {receipt["work_key"] for receipt in worker.dispatches}
    steps_after_crash = len(engine.steps) - steps_before_crash
    rusage = resource.getrusage(resource.RUSAGE_SELF)
    report = {
        "schema": "aria.endurance.soak.v1",
        "synthetic": True,
        "wall_seconds": round(time.monotonic() - started, 3),
        "configured_seconds": seconds,
        "tick_seconds": tick_seconds,
        "lease_seconds": lease_seconds,
        "simulated_step_interval_seconds": plan.step_interval_seconds,
        "ticks": ticks,
        "crash_at_seconds": round(crash_at - started, 3),
        "crash_observed": crashed,
        "recovered_campaigns": len(recoveries),
        "steps_before_crash": steps_before_crash,
        "steps_after_crash": steps_after_crash,
        "steps_total": len(engine.steps),
        "campaign_state": row["state"],
        "reason_code": row["reason_code"],
        "retry_count": int(row["retry"]["count"]),
        "provider_calls": len(accounting.provider_calls),
        "provider_denials": len(accounting.denials),
        "worker_dispatches": len(worker.dispatches),
        "duplicate_dispatches": len(worker.duplicates),
        "denied_dispatches": len(worker.denied),
        "unique_work_keys": len(unique_keys),
        "accounting": {
            "reserved_tokens": int(usage["reserved_tokens"]),
            "reported_tokens": int(usage["reported_tokens"]),
            "expected_reserved_tokens": reserved,
            "expected_reported_tokens": reported,
            "unknown_usage_calls": int(usage["unknown_usage_calls"]),
            "stopped": bool(usage["stopped"]),
            "consistent": (
                int(usage["reserved_tokens"]) == reserved
                and int(usage["reported_tokens"]) == reported
                and int(usage["unknown_usage_calls"]) == 0
                and not usage["stopped"]),
        },
        "operations_retained": len(row["operations"]["events"]),
        "operations_max": 50,
        "campaign_row_bytes": len(json.dumps(row, default=str)),
        "window_violations": len(window_violations),
        "cpu_seconds": round(time.process_time(), 3),
        "cpu_user_seconds": round(rusage.ru_utime, 3),
        "cpu_system_seconds": round(rusage.ru_stime, 3),
        "peak_rss_kb": int(rusage.ru_maxrss),
        "limitations": [
            "Synthetic in-memory campaign store; no database or worker was used.",
            "Compressed step cadence; this is a bounded soak, not an 8-hour run.",
            "Any completed run proves this workload on this host, not provider reliability.",
        ],
    }
    report["safe"] = all((
        report["duplicate_dispatches"] == 0,
        report["denied_dispatches"] == 0,
        report["provider_denials"] == 0,
        report["window_violations"] == 0,
        report["accounting"]["consistent"],
        report["unique_work_keys"] == report["worker_dispatches"],
        report["steps_total"] == report["provider_calls"],
        report["steps_total"] == report["worker_dispatches"],
        report["operations_retained"] <= report["operations_max"],
        report["campaign_row_bytes"] < 60_000,
        report["campaign_state"] != "failed",
        (not crashed or steps_after_crash > 0
         or report["campaign_state"] == "completed"),
    ))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=60.0,
                        help="bounded wall-clock duration (15-300 seconds)")
    parser.add_argument("--tick", type=float, default=0.5,
                        help="supervisor tick interval in seconds")
    parser.add_argument("--lease", type=int, default=3,
                        help="compressed supervisor lease in seconds")
    args = parser.parse_args()
    seconds = min(300.0, max(15.0, float(args.seconds)))
    tick_seconds = min(2.0, max(0.1, float(args.tick)))
    lease_seconds = min(60, max(2, int(args.lease)))

    async def runner():
        with _soak_settings(lease_seconds=lease_seconds,
                            retry_base_seconds=1):
            return await run_soak(seconds=seconds, tick_seconds=tick_seconds,
                                  lease_seconds=lease_seconds)

    report = asyncio.run(runner())
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["safe"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
