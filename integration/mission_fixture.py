"""Loopback-only UI fixture using the real FastAPI router and in-memory records."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from uuid import uuid4

import tests  # disposable credentials and database name before importing the app
from fastapi import HTTPException
from starlette.responses import JSONResponse

from api import auth, main
from api.routers import pentest
from config.settings import settings
from memory.campaign_observability import append_operation
from memory.team_tasks import digest

OWNER = "fixture-owner"
ALPHA = "mc-alpha"
BETA = "mc-beta"
FOREIGN = "mc-foreign"
NOW = "2026-11-17T11:00:00+00:00"
TASK = "fixture-task-1"
TASK2 = "fixture-task-2"
EVIDENCE = "fixture-evidence-1"
CAMPAIGN = "fixture-campaign"
OLDER_CAMPAIGN = "fixture-campaign-previous"
JOB = "fixture-job-1"
REPORT = "10000000-0000-4000-8000-000000000001"
UNSIGNED_REPORT = "10000000-0000-4000-8000-000000000002"
PENDING_REVIEW = "fixture-proposal"
REPORT_FILES = {"report.md": "# Inventory evidence review\nRetained inventory review fixture"}
REPORT_DIGEST = digest(REPORT_FILES)


def session(sid, name, owner=OWNER):
    return {"session_id": sid, "user_id": owner, "name": name, "target": "records.example.test",
            "scope": {"targets": ["records.example.test"], "ports": [443], "exclusions": []},
            "phase": "reporting", "status": "active", "created_at": NOW, "updated_at": NOW}


EMPTY_TEAM = dict.fromkeys(("tasks", "evidence", "knowledge", "coverage", "verification_findings",
                            "report_drafts", "report_signoffs", "report_outcomes", "report_retests",
                            "report_correspondence", "research_hypotheses", "research_models"), [])
TEAM = {**EMPTY_TEAM, "tasks": [
    {"id": TASK, "title": "Review imported service inventory", "objective": "Verify timestamps in retained records",
     "owner_role": "web_intel", "state": "completed", "campaign_id": CAMPAIGN, "created_at": NOW,
     "evidence_inputs": [EVIDENCE], "dependencies": []},
    {"id": TASK2, "title": "Review evidence freshness", "objective": "Check the freshness of the signed records",
     "owner_role": "correlation", "state": "blocked", "campaign_id": CAMPAIGN, "created_at": NOW,
     "reason": "Awaiting current service inventory", "dependencies": [TASK], "evidence_inputs": [EVIDENCE]},
], "evidence": [{"id": EVIDENCE, "kind": "worker", "source_kind": "worker", "source_id": JOB,
                   "summary": "Recorded status and service timestamp", "created_at": NOW,
                   "provenance": {"source": "fixture"}}],
    "verification_findings": [{"id": "fixture-finding", "title": "Inventory timestamp is stale",
                               "state": "candidate", "severity": "info", "evidence_references": [EVIDENCE],
                               "scope_digest": digest(session(ALPHA, "")["scope"]), "evidence_snapshot": {}}]}
LIMITS = {"max_calls": 20, "max_tokens": 200000, "max_cost_microusd": 1000000, "tariffs": []}
USAGE = {"calls": 15, "reserved_tokens": 196074, "reserved_cost_microusd": 40000, "reported_tokens": 17230,
         "reported_cost_microusd": 27000, "unknown_usage_calls": 1, "unknown_cost_calls": 1,
         "stopped": False, "stop_reason": ""}


def attempts():
    return [{"id": f"attempt-{i}", "session_id": ALPHA, "campaign_id": CAMPAIGN, "task_id": TASK,
             "timestamp": f"2026-11-17T10:{i:02d}:00Z", "provider": "local", "model": "fixture-reviewed",
             "state": "failed" if i == 14 else "succeeded", "error_code": "timeout" if i == 14 else "",
             "reserved_tokens": 13071 + i % 2, "reported_tokens": None if i == 14 else 1230,
             "input_tokens": None if i == 14 else 900, "output_tokens": None if i == 14 else 330,
             "reserved_cost_microusd": 2667, "reported_cost_microusd": None if i == 14 else 1800,
             "provider_debug": "fixture-private-accounting-metadata",
             "timings": {"pool_attempt_ms": 60000 if i == 14 else 123 + i * 73}}
            for i in range(15)]


class Fixture:
    def __init__(self, current=False):
        self.current = current
        self.sessions = {ALPHA: session(ALPHA, "Service inventory review"),
                         BETA: session(BETA, "Quarterly controls review"),
                         FOREIGN: session(FOREIGN, "Private fixture", "other-owner")}
        self.campaign_state = "paused"
        self.operations = {}
        self.stream_disconnects = 1
        self.stream_count = 0
        self.faults = {}
        self.delays = {}
        self.epoch = 0
        self.worker_up = False
        self.pending = current
        self.rejections = 0
        self.export_digest = REPORT_DIGEST
        self.extra_team = 0
        self.bounded_state = None
        self.stop_requests = 0
        self.pause_requests = 0
        self.resume_requests = 0
        self.web_pending = 0
        self.web_summary_unavailable = False
        self.add_operation("campaign_paused", "paused", "Service inventory review paused")

    def add_operation(self, event, state, message):
        self.operations = append_operation(self.operations, event=event, to_state=state, message=message,
            campaign_id=CAMPAIGN, correlation="fixture-campaign-correlation", now=datetime.fromisoformat(NOW))

    def owner(self, sid, owner):
        row = self.sessions.get(sid)
        if row is None:
            raise HTTPException(404, "Session not found")
        if row["user_id"] != owner:
            raise HTTPException(403, "Ownership denied")
        return row

    async def login(self, username, password):
        if (username, password) == (OWNER, "fixture-only-password"):
            return SimpleNamespace(id=OWNER, username=OWNER, display_name="Fixture operator",
                role=SimpleNamespace(value="pentester"), skill_level=SimpleNamespace(value="intermediate"))

    async def identity(self, uid, revision=None):
        if uid != OWNER or revision != self.epoch:
            raise HTTPException(401, "Account or credentials are unavailable")
        return auth.TokenData(user_id=uid, username=OWNER, role="pentester", skill_level="intermediate",
                              auth_revision=revision)

    async def create(self, owner, target, name, context_type, scope):
        sid = uuid4().hex
        self.sessions[sid] = {**session(sid, name, owner), "target": target, "scope": scope, "phase": "scope"}
        return self.sessions[sid]

    async def team(self, sid, owner):
        row = self.owner(sid, owner)
        return {**deepcopy(TEAM if sid == ALPHA else EMPTY_TEAM), "cursor": 3 if sid == ALPHA else 0,
                "scope": row["scope"], "target": row["target"]}

    async def events(self, sid, owner, after):
        self.owner(sid, owner)
        records = []
        if sid == ALPHA:
            for i, item in enumerate([*TEAM["tasks"], *TEAM["evidence"]], 1):
                if i > after:
                    records.append({"id": f"team-{i}", "sequence": i, "timestamp": NOW, "actor": OWNER,
                                    "collection": "tasks" if i <= 2 else "evidence", "entity_id": item["id"],
                                    "data": item, "private_debug": "must stay out of event schema"})
            for index in range(max(4, after + 1), 4 + self.extra_team):
                timestamp = datetime.fromisoformat(NOW) + timedelta(seconds=index)
                records.append({"id": f"team-{index}", "sequence": index, "timestamp": timestamp.isoformat(),
                                "collection": "knowledge", "entity_id": f"observation-{index}", "data": {}})
        return {"events": records, "cursor": records[-1]["sequence"] if records else after}

    async def event_page(self, sid, owner, after, limit, *, before=None):
        records = (await self.events(sid, owner, after or 0))["events"]
        if before is not None:
            records = [record for record in records if record['sequence'] < before]
        return (records[-limit:] if after is None else records[:limit]), len(records) > limit

    async def budget(self, sid, owner):
        from llm.engagement_budget import ModelLimits, admission_snapshot
        self.owner(sid, owner)
        selected = {"provider": "local", "model": "fixture-reviewed"}
        records = attempts() + [{"id": "fixture-foreign-attempt", "session_id": FOREIGN}] if sid == ALPHA else []
        return {"limits": LIMITS, "configured_selection": selected,
                "admission": admission_snapshot({"model_usage": USAGE if sid == ALPHA else {}}, ModelLimits(**LIMITS), selected),
                "usage": USAGE if sid == ALPHA else {}, "attempts": records,
                "attempts_limit": 100, "cost_basis": "Synthetic accounting records"}

    async def campaign(self, sid):
        if sid == ALPHA:
            return {"id": CAMPAIGN, "session_id": sid, "owner_id": OWNER, "state": self.campaign_state,
                    "operations": self.operations, "goal": "Review retained service inventory"}

    async def campaign_status(self, sid, owner):
        self.owner(sid, owner)
        return await self.campaign(sid)

    async def health(self, row, owner):
        self.owner(row["session_id"], owner)
        return {"schema": "aria.campaign.health.v1", "state": row["state"], "campaign_id": CAMPAIGN,
                "generated_at": NOW, "goal": row["goal"], "progress": {"steps_taken": 4, "current_phase": "reporting"},
                "limitations": [], "alerts": [], "heartbeat": {"stale": False}, "budget": {}}

    async def cancel(self, cid, owner):
        self.owner(ALPHA, owner)
        assert cid == CAMPAIGN
        self.campaign_state = "cancelling"
        self.add_operation("campaign_cancel_requested", "cancelling", "Cancellation requested")
        return {"id": CAMPAIGN, "state": "cancelling"}

    async def pause(self, cid, owner):
        self.owner(ALPHA, owner)
        assert cid == CAMPAIGN
        self.pause_requests += 1
        self.campaign_state = 'pausing'
        return {'id': cid, 'state': 'pausing'}

    async def resume(self, cid, owner):
        self.owner(ALPHA, owner)
        assert cid == CAMPAIGN and self.campaign_state == 'paused'
        self.resume_requests += 1
        self.campaign_state = 'scheduled'
        return {'id': cid, 'state': 'scheduled'}

    async def stop(self, sid, *, user_id):
        self.owner(sid, user_id)
        assert sid == BETA and self.bounded_state is not None
        self.stop_requests += 1
        self.bounded_state = {'active': False, 'run_state': 'blocked', 'reason_code': 'cancelled',
                              'cancellation_confirmed': True}
        return {'status': 'stopped', 'pending': 0, 'cancelled': 0}

    async def stream(self, sid):
        import asyncio
        self.stream_count += 1
        if self.stream_disconnects:
            self.stream_disconnects -= 1
            return
        yield {"type": "auto_activity", "session_id": sid, "run_id": "fixture-run", "event_sequence": 1}
        yield {"type": "auto_activity", "session_id": sid, "run_id": "fixture-run", "event_sequence": 1}
        yield {"type": "auto_activity", "session_id": sid, "run_id": "fixture-run", "event_sequence": 3, "stream_gap": True}
        yield {"type": "auto_activity", "session_id": sid, "run_id": "fixture-run", "event_sequence": 2}
        await asyncio.sleep(3600)

    async def run_status(self, sid):
        if sid == BETA and self.bounded_state is not None:
            return deepcopy(self.bounded_state)
        if self.current and sid == ALPHA:
            return {"active": True, "waiting_approval": self.pending, "run_state": "awaiting_approval" if self.pending else "blocked",
                    "run_id": "fixture-run", "original_objective": "Review retained service inventory", "current_phase": "reporting",
                    "reason_code": "human_approval_required" if self.pending else "approval_rejected"}
        return {"active": False}

    def approvals(self, sid):
        if sid != ALPHA or not self.current:
            return []
        then = datetime.now(timezone.utc) - timedelta(minutes=4)
        items = [{"action_id": "fixture-expired", "tool": "curl", "created_at": then,
                  "expires_at": then + timedelta(minutes=1)}]
        if self.pending:
            items.append({"action_id": PENDING_REVIEW, "tool": "curl", "created_at": then,
                          "expires_at": then + timedelta(hours=1), "command": "fixture-private-arguments"})
        return items

    async def reject(self, *, session_id, action_id, decision, modified_command, user_id):
        self.owner(session_id, user_id)
        if decision != "reject" or action_id != PENDING_REVIEW or not self.pending:
            raise HTTPException(403, "Fixture only supports rejecting an existing pending proposal")
        self.rejections += 1
        self.pending = False
        return {"status": "recorded", "decision": decision}

    def patches(self):
        from llm.engagement_budget import model_accounting
        from memory.team_tasks import team_store
        from memory.worker_jobs import worker_jobs
        from memory.application_map import application_map
        from memory.attack_knowledge_base import attack_kb
        from memory.professional_reports import professional_reports
        from memory.professional_reports import zip_bundle
        from memory.command_registry import CommandEntry, command_registry
        from memory.web_actions import web_actions
        from api.routers import mission
        from security.login_throttle import login_throttle

        async def drafts(sid, owner):
            self.owner(sid, owner)
            return {"report_drafts": [
                {"id": REPORT, "title": "Inventory evidence review", "revision": 1},
                {"id": UNSIGNED_REPORT, "title": "Unsigned controls draft", "revision": 1},
            ] if sid == ALPHA else [], "report_signoffs": [{"report_id": REPORT}] if sid == ALPHA else []}

        async def preview(sid, owner, rid):
            self.owner(sid, owner)
            if sid != ALPHA or rid not in {REPORT, UNSIGNED_REPORT}:
                raise HTTPException(404, "Report missing")
            return {"files": REPORT_FILES, "report": {"package_sha256": REPORT_DIGEST}, "signed": rid == REPORT,
                    "signoff": {"package_sha256": REPORT_DIGEST} if rid == REPORT else None}

        async def export(sid, owner, rid):
            self.owner(sid, owner)
            if sid != ALPHA or rid != REPORT:
                raise HTTPException(409, "Report is not signed")
            return zip_bundle(REPORT_FILES), self.export_digest

        async def authorization_history(sid, owner, limit):
            self.owner(sid, owner)
            history = []
            if sid == ALPHA and self.current:
                stamp = datetime.fromisoformat(NOW)
                history.append(mission.RecordedAuthorization(id=PENDING_REVIEW, action_id=PENDING_REVIEW,
                    timestamp=stamp, event='proposal_registered'))
                if self.rejections:
                    history.insert(0, mission.RecordedAuthorization(id='fixture-journal-reject', action_id=PENDING_REVIEW,
                        timestamp=stamp + timedelta(seconds=1), event='rejection_recorded', decision='reject'))
            return mission.AuthorizationHistory(records=history, limit=limit)

        async def campaign_history(sid, owner, before, limit):
            self.owner(sid, owner)
            records = []
            if sid == ALPHA:
                now = datetime.fromisoformat(NOW)
                ids = [CAMPAIGN, *[f'fixture-campaign-{index}' for index in range(1, 25)], OLDER_CAMPAIGN]
                records = [mission.CampaignHistoryItem(id=cid, state=self.campaign_state if cid == CAMPAIGN else 'completed',
                    created_at=now - timedelta(days=i), updated_at=now - timedelta(days=i)) for i, cid in enumerate(ids)]
            if before:
                anchor = next((i for i, record in enumerate(records) if record.id == before), None)
                if anchor is None:
                    raise HTTPException(404, 'Campaign history cursor not found')
                records = records[anchor + 1:]
            return mission.CampaignHistoryPage(session_id=sid, campaigns=records[:limit],
                next_before=records[limit - 1].id if len(records) > limit else None)

        async def campaign_operations(sid, owner, cid):
            self.owner(sid, owner)
            if sid != ALPHA or cid not in (CAMPAIGN, OLDER_CAMPAIGN):
                raise HTTPException(404, 'Campaign not found')
            if cid == CAMPAIGN:
                return self.operations
            earlier = datetime.fromisoformat(NOW) - timedelta(days=25)
            ring = {}
            for index in range(54):
                ring = append_operation(ring, event='campaign_heartbeat', campaign_id=cid,
                    now=earlier + timedelta(seconds=index), correlation='previous-campaign')
            return append_operation(ring, event='campaign_completed', campaign_id=cid, to_state='completed',
                now=earlier + timedelta(seconds=54), correlation='previous-campaign')

        async def receipts(sid, owner, limit):
            self.owner(sid, owner)
            return [mission.Receipt(id=JOB, state="failed", created_at=datetime.fromisoformat(NOW),
                exit_code=1, output_sha256="1" * 64)] if sid == ALPHA else []

        async def replay_summary(sid, owner):
            self.owner(sid, owner)
            if self.web_summary_unavailable:
                raise RuntimeError('fixture-private-replay-failure')
            pending = self.web_pending if sid == BETA else 0
            return {'records': pending, 'pending_cancellations': pending, 'unknown_outcomes': 0}

        async def worker_capabilities():
            if not self.worker_up:
                raise ConnectionError('injected worker outage')
            return {"tools": ["curl", "nmap"], "authenticated_http_version": 1}

        async def map_snapshot(sid, owner):
            self.owner(sid, owner)
            if sid != ALPHA:
                return {"objects": {}, "workflows": {}, "captures": {}}
            return {"objects": {"asset": {"id": "asset", "label": "Inventory record", "evidence_ids": [EVIDENCE]}},
                    "workflows": {}, "captures": {"capture": {"id": "capture", "method": "GET", "evidence_id": EVIDENCE}}}

        def host_snapshot(sid):
            return [SimpleNamespace(ip='192.0.2.18', hostname='records.example.test',
                ports={443: {"state": "open", "service": "https"}})] if self.current and sid == ALPHA else []

        history = CommandEntry(command="curl fixture-private-arguments", cmd_hash="fixture-command",
                               result_summary="HTTP 200", stdout="HTTP/1.1 200 OK\nAuthorization: fixture-private-marker",
                               status="success", executed_at=datetime.fromisoformat(NOW).timestamp(), execution_time_ms=45)

        decision_db = MagicMock()
        decision_db.__aenter__.return_value.execute = AsyncMock(return_value=Mock())
        decision_db.__aenter__.return_value.execute.return_value.scalars.return_value.all.return_value = []
        return [patch.object(main, "log", Mock()), patch.object(main, "authenticate_user", self.login),
            patch.object(main, "auth_revision", return_value=0),
            patch.object(auth, "current_identity", self.identity), patch.object(login_throttle, "reserve", AsyncMock()),
            patch.object(settings, "KALI_AGENT_URL", "http://127.0.0.1:1"), patch.object(settings, "ALLOWED_ORIGINS", []),
            patch.object(worker_jobs.client, "capabilities", worker_capabilities),
            patch.object(main, "init_db", AsyncMock()),
            patch('memory.database_models.engine', SimpleNamespace(connect=lambda: decision_db)),
            patch.object(main.session_manager, "cache_available", AsyncMock(return_value=False)),
            patch.object(main.session_manager, "get_session", AsyncMock(side_effect=lambda sid, **kw: self.sessions.get(sid))),
            patch.object(main.session_manager, "list_sessions", AsyncMock(side_effect=lambda uid:
                [s for s in self.sessions.values() if s["user_id"] == uid])),
            patch.object(main.session_manager, "create_session", self.create),
            patch.object(main.session_manager, "get_chat_logs", AsyncMock(side_effect=lambda sid, **kw: [
                {'role': 'user', 'content': 'Retained fixture note for ' + sid}] if sid in self.sessions else [])),
            patch.object(main.session_manager, "get_findings_summary", AsyncMock(return_value={"total": 0, "counts": {}, "findings": []})),
            patch.object(pentest, "async_session", return_value=decision_db),
            patch.object(pentest.campaign_store, "latest_for_session", self.campaign),
            patch.object(pentest.campaign_store, "latest_active_for_session", self.campaign),
            patch.object(pentest.campaign_supervisor, "latest_status", self.campaign_status),
            patch.object(pentest.campaign_supervisor, "health_for_row", self.health),
            patch.object(pentest.campaign_supervisor, "cancel", self.cancel),
            patch.object(pentest.campaign_supervisor, "pause", self.pause),
            patch.object(pentest.campaign_supervisor, "resume", self.resume),
            patch.object(pentest.autonomous_engine, "request_stop", self.stop),
            patch.object(web_actions, "cancel_all", AsyncMock(side_effect=lambda sid, owner:
                {'pending': self.web_pending, 'cancelled': 0})),
            patch.object(pentest.autonomous_engine, "restored_status", self.run_status),
            patch.object(pentest.autonomous_engine, "stream_events", self.stream),
            patch.object(pentest.autonomous_engine, "get_pending_approvals", self.approvals),
            patch.object(pentest.autonomous_engine, "provide_approval_decision", self.reject),
            patch.object(team_store, "view", self.team), patch.object(team_store, "events", self.events),
            patch.object(team_store, "event_page", self.event_page),
            patch.object(model_accounting, "status", self.budget),
            patch.object(mission, "recent_worker_receipts", receipts),
            patch.object(mission, "recent_authorizations", authorization_history),
            patch.object(mission, "web_replay_summary", replay_summary),
            patch.object(mission, "read_campaign_history", campaign_history),
            patch.object(mission, "read_campaign_operations", campaign_operations),
            patch.object(command_registry, "get_history", side_effect=lambda sid: [history] if sid == ALPHA else []),
            patch.object(worker_jobs, "list_status", AsyncMock(return_value=[])),
            patch.object(application_map, "view", map_snapshot), patch.object(attack_kb, "get_all_hosts", side_effect=host_snapshot),
            patch.object(professional_reports, "list", drafts), patch.object(professional_reports, "preview", preview),
            patch.object(professional_reports, "export", export)]

    async def __call__(self, scope, receive, send):
        import asyncio
        if scope["type"] == "http":
            path = scope["path"]
            allowed_writes = {"/api/login", "/api/session/new", f"/api/pentest/{ALPHA}/campaign/cancel",
                              f"/api/pentest/{ALPHA}/campaign/pause", f"/api/pentest/{ALPHA}/campaign/resume",
                              f"/api/pentest/{BETA}/autonomous/stop",
                              f"/api/pentest/{ALPHA}/autonomous/approve"}
            if scope["method"] not in {"GET", "HEAD"} and path not in allowed_writes:
                return await JSONResponse({"detail": "Write disabled in UI fixture"}, status_code=403)(scope, receive, send)
            if path in self.delays:
                await asyncio.sleep(self.delays[path])
            if path in self.faults:
                status, body = self.faults[path]
                return await JSONResponse(body, status_code=status)(scope, receive, send)
        return await main.app(scope, receive, send)
