"""
PentestAI v8 — Session Manager
PostgreSQL for persistence, Redis for cache and real-time state.
"""
import asyncio
import json
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional

import structlog
from sqlalchemy import select, update, delete

from config.settings import settings
from memory.database_models import (
    PentestSession, Finding, ChatLog, AuditLog, Playbook,
    SessionStatus, PentestPhase, AuditAction, RiskLevel,
    async_session,
)
from security.har import HAR_CAPTURE_TYPE

log = structlog.get_logger(__name__)


class SessionManager:
    CACHE_TIMEOUT_SECONDS = 2

    def __init__(self):
        self._redis = None
        # Reject cache contents from a previous process or a failed invalidation.
        # Ownership and execution admission always read authoritative SQL.
        self._cache_generation = str(uuid.uuid4())

    async def initialize(self):
        """Connect to Redis."""
        client = None
        try:
            import redis.asyncio as aioredis
            client = aioredis.from_url(settings.REDIS_URL, decode_responses=True,
                socket_connect_timeout=self.CACHE_TIMEOUT_SECONDS,
                socket_timeout=self.CACHE_TIMEOUT_SECONDS)
            async with asyncio.timeout(self.CACHE_TIMEOUT_SECONDS):
                if await client.ping() is not True:
                    raise ConnectionError('Cache readiness unavailable')
            self._redis = client
            log.info("Redis connected")
        except Exception as e:
            log.warning("Redis unavailable, using DB only", error_type=type(e).__name__)
            self._redis = None
        finally:
            if client is not None and self._redis is not client:
                try:
                    async with asyncio.timeout(self.CACHE_TIMEOUT_SECONDS):
                        await client.aclose()
                except Exception as e:
                    log.warning('redis_initialization_cleanup_failed', error_type=type(e).__name__)

    async def close(self):
        client, self._redis = self._redis, None
        if client is not None:
            async with asyncio.timeout(self.CACHE_TIMEOUT_SECONDS):
                await client.aclose()

    async def _cache_operation(self, operation: str, *args):
        if self._redis is None:
            return None
        try:
            async with asyncio.timeout(self.CACHE_TIMEOUT_SECONDS):
                return await getattr(self._redis, operation)(*args)
        except Exception as e:
            self._cache_generation = str(uuid.uuid4())
            log.warning('session_cache_unavailable', operation=operation,
                        error_type=type(e).__name__)
            return None

    async def cache_available(self) -> bool:
        """Observe optional cache availability without changing durable state."""
        return await self._cache_operation('ping') is True

    async def _cache_session(self, session_id: str, data: dict) -> None:
        payload = {'schema':'aria.session.cache.v2',
                   'generation':self._cache_generation, 'data':data}
        await self._cache_operation('setex', f'session:{session_id}',
            settings.REDIS_SESSION_TTL, json.dumps(payload))

    # ── Sessions ─────────────────────────────────────────────────────────

    async def create_session(self, user_id: str, target: str, name: str = "",
                             context_type: str = "internal_corporate",
                             scope: dict = None) -> dict:
        from llm.engagement_budget import ModelLimits

        session_id = str(uuid.uuid4())
        if not name:
            name = f"Pentest {target}"

        model_limits = ModelLimits(max_calls=100, max_tokens=100_000, max_cost_microusd=500_000)
        async with async_session() as db:
            session = PentestSession(
                id=session_id,
                user_id=user_id,
                name=name,
                target=target,
                scope=scope or {"targets": [target], "exclusions": []},
                context_type=context_type,
                metadata_={"model_limits": model_limits.model_dump()},
            )
            db.add(session)
            await db.commit()

        # Cache in Redis
        await self._cache_session(session_id,
                {"session_id": session_id, "target": target, "user_id": user_id, "name": name,
                            "scope": scope or {"targets": [target], "exclusions": []},
                            "status": "active", "context_type": context_type,
                            "phase": "scope", "tools_run": [], "open_ports": []})

        return {"session_id": session_id, "name": name, "target": target}

    async def get_session(self, session_id: str, *, authoritative: bool = False) -> Optional[dict]:
        # Authorization callers bypass cached owner/scope data.
        if self._redis and not authoritative:
            cached = await self._cache_operation('get', f"session:{session_id}")
            if cached:
                try:
                    envelope = json.loads(cached)
                    data = envelope.get('data') if isinstance(envelope, dict) else None
                    if (envelope.get('schema') == 'aria.session.cache.v2'
                            and envelope.get('generation') == self._cache_generation
                            and isinstance(data, dict) and data.get('session_id') == session_id):
                        return data
                except (ValueError, TypeError, AttributeError):
                    self._cache_generation = str(uuid.uuid4())

        # Fallback to DB
        async with async_session() as db:
            result = await db.execute(select(PentestSession).where(PentestSession.id == session_id))
            session = result.scalar_one_or_none()
            if session:
                data = {
                    "session_id": session.id,
                    "target": session.target,
                    "user_id": session.user_id,
                    "name": session.name,
                    "phase": session.current_phase.value if session.current_phase else "scope",
                    "status": session.status.value if session.status else "active",
                    "tools_run": session.tools_run or [],
                    "open_ports": session.open_ports or [],
                    "context_type": session.context_type,
                    "scope": session.scope or {},
                    "created_at": session.created_at.isoformat() if session.created_at else "",
                }
                if not authoritative:
                    await self._cache_session(session_id, data)
                return data
        return None

    async def list_sessions(self, user_id: str) -> list:
        from sqlalchemy.orm import selectinload
        async with async_session() as db:
            result = await db.execute(
                select(PentestSession)
                .options(selectinload(PentestSession.findings))
                .where(PentestSession.user_id == user_id)
                .where(PentestSession.status != SessionStatus.ARCHIVED)
                .order_by(PentestSession.updated_at.desc())
            )
            sessions = result.scalars().unique().all()
            return [{
                "session_id": s.id,
                "name": s.name,
                "target": s.target,
                "status": s.status.value if s.status else "active",
                "phase": s.current_phase.value if s.current_phase else "scope",
                "created_at": s.created_at.isoformat() if s.created_at else "",
                "updated_at": s.updated_at.isoformat() if s.updated_at else "",
                "findings_count": len(s.findings) if s.findings else 0,
            } for s in sessions]

    async def delete_session(self, session_id: str):
        async with async_session() as db:
            await db.execute(update(PentestSession).where(PentestSession.id == session_id)
                             .values(status=SessionStatus.ARCHIVED))
            await db.commit()
        await self._cache_operation('delete', f"session:{session_id}")

    async def update_session(self, session_id: str, **kwargs):
        async with async_session() as db:
            await db.execute(update(PentestSession).where(PentestSession.id == session_id).values(**kwargs))
            await db.commit()
        # Invalidate cache
        await self._cache_operation('delete', f"session:{session_id}")

    async def update_phase(self, session_id: str, phase: str):
        try:
            p = PentestPhase(phase)
        except ValueError:
            return
        await self.update_session(session_id, current_phase=p, updated_at=datetime.utcnow())

    async def add_tools_run(self, session_id: str, tool: str):
        async with async_session() as db:
            result = await db.execute(select(PentestSession).where(PentestSession.id == session_id))
            session = result.scalar_one_or_none()
            if session:
                tools = session.tools_run or []
                if tool not in tools:
                    tools.append(tool)
                session.tools_run = tools
                session.updated_at = datetime.utcnow()
                await db.commit()

    async def update_open_ports(self, session_id: str, ports: list):
        async with async_session() as db:
            result = await db.execute(select(PentestSession).where(PentestSession.id == session_id))
            session = result.scalar_one_or_none()
            if session:
                existing = session.open_ports or []
                existing_set = {(p["port"], p["service"]) for p in existing}
                for p in ports:
                    key = (p["port"], p["service"])
                    if key not in existing_set:
                        existing.append(p)
                        existing_set.add(key)
                session.open_ports = existing
                session.updated_at = datetime.utcnow()
                await db.commit()

    # ── Findings ─────────────────────────────────────────────────────────

    async def add_finding(self, session_id: str, finding: dict):
        async with async_session() as db:
            f = Finding(
                session_id=session_id,
                title=finding.get("title", "Untitled"),
                severity=finding.get("severity", "info"),
                cvss_score=finding.get("cvss_score"),
                description=finding.get("description", ""),
                evidence=finding.get("evidence", ""),
                recommendation=finding.get("recommendation", ""),
                cve_ids=finding.get("cve_ids", []),
                vulnerability_type=finding.get("vulnerability_type", ""),
                exploit_complexity=finding.get("exploit_complexity", ""),
                business_impact=finding.get("business_impact", ""),
                agent_type=finding.get("agent_type", ""),
                confidence=finding.get("confidence", 0.5),
                metadata_=finding.get("metadata", {}),
                human_verified=False,
            )
            db.add(f)
            await db.commit()

    async def get_findings(self, session_id: str) -> list:
        async with async_session() as db:
            result = await db.execute(
                select(Finding).where(Finding.session_id == session_id)
                .order_by(Finding.created_at.desc())
            )
            findings = result.scalars().all()
            return [{
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "description": f.description,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
                "cve_ids": f.cve_ids or [],
                "vulnerability_type": f.vulnerability_type,
                "agent_type": f.agent_type,
                "confidence": f.confidence,
                "human_verified": bool(f.human_verified),
                "evidence_source": (f.metadata_ or {}).get("evidence_source", "legacy_unverified"),
                "created_at": f.created_at.isoformat() if f.created_at else "",
            } for f in findings]

    async def get_findings_summary(self, session_id: str) -> dict:
        findings = await self.get_findings(session_id)
        counts = {}
        for f in findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return {"findings": findings, "counts": counts, "total": len(findings)}

    # ── Chat Logs ────────────────────────────────────────────────────────

    async def add_chat_log(self, session_id: str, role: str, content: str,
                           msg_type: str = "text", data: dict = None):
        async with async_session() as db:
            log_entry = ChatLog(
                session_id=session_id,
                role=role,
                content=content,
                msg_type=msg_type,
                data=data or {},
            )
            db.add(log_entry)
            await db.commit()

    async def get_chat_logs(self, session_id: str, limit: int = 200, offset: int = 0, msg_types: Optional[List[str]] = None) -> list:
        async with async_session() as db:
            query=select(ChatLog).where(ChatLog.session_id == session_id, ChatLog.msg_type.is_distinct_from(HAR_CAPTURE_TYPE))
            if msg_types:
                query=query.where(ChatLog.msg_type.in_(msg_types))
            result = await db.execute(
                query.order_by(ChatLog.created_at.desc(), ChatLog.id.desc())
                .offset(max(0, offset)).limit(min(max(1, limit), 201))
            )
            logs = result.scalars().all()
            return [{
                "id": l.id,
                "turn_id": (l.data or {}).get("turn_id"),
                "role": l.role,
                "content": l.content,
                "type": l.msg_type,
                "data": l.data or {},
                "ts": l.created_at.timestamp() if l.created_at else 0,
            } for l in reversed(logs)]

    # ── Audit Logs ───────────────────────────────────────────────────────

    async def add_audit_log(self, user_id: str, session_id: str, action: AuditAction,
                            agent: str = "", input_data: dict = None, output_data: dict = None,
                            reasoning: str = "", human_status: str = "",
                            risk_level: RiskLevel = None, ip_address: str = ""):
        async with async_session() as db:
            entry = AuditLog(
                user_id=user_id,
                session_id=session_id,
                action=action,
                agent=agent,
                input_data=input_data or {},
                output_data=output_data or {},
                reasoning=reasoning,
                human_status=human_status,
                risk_level=risk_level,
                ip_address=ip_address,
            )
            db.add(entry)
            await db.commit()

    async def get_audit_logs(self, session_id: str = None, user_id: str = None,
                             limit: int = 100) -> list:
        async with async_session() as db:
            q = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
            if session_id:
                q = q.where(AuditLog.session_id == session_id)
            if user_id:
                q = q.where(AuditLog.user_id == user_id)
            result = await db.execute(q)
            logs = result.scalars().all()
            return [{
                "id": l.id,
                "user_id": l.user_id,
                "session_id": l.session_id,
                "action": l.action.value if l.action else "",
                "agent": l.agent,
                "input_data": l.input_data,
                "output_data": l.output_data,
                "reasoning": l.reasoning,
                "human_status": l.human_status,
                "risk_level": l.risk_level.value if l.risk_level else "",
                "created_at": l.created_at.isoformat() if l.created_at else "",
            } for l in logs]


session_manager = SessionManager()
