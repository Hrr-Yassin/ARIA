"""Authenticated tool discovery and engagement restrictions."""
import asyncio
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from api.auth import TokenData, get_current_user
from config.security_tool_registry import RegistryError, load_registry
from config.settings import settings
from memory.worker_jobs import worker_jobs
from memory.database_models import DecisionLog, async_session
from memory.program_policy import owned_engagement
from security_tools.adapters import ADAPTERS

router = APIRouter()


class BlockCapability(BaseModel):
    model_config = ConfigDict(extra='forbid')
    capability: str = Field(min_length=1, max_length=100)


@router.get('/sessions/{session_id}/tool-restrictions')
async def tool_restrictions(session_id: str, user: TokenData = Depends(get_current_user)) -> dict:
    async with async_session() as db:
        session = await owned_engagement(db, session_id, user.user_id, read_only=True)
        scope = session.scope if session.scope is not None else {}
        if not isinstance(scope, dict):
            raise HTTPException(409, 'Stored engagement scope is invalid')
        blocked = scope.get('blocked_typed_capabilities', [])
        if not isinstance(blocked, list) or any(not isinstance(item, str) for item in blocked):
            raise HTTPException(409, 'Stored capability restrictions are invalid')
        state = session.status.value if session.status is not None else 'unknown'
        blockers = []
        if state != 'active':
            blockers.append('engagement_inactive')
        if isinstance(session.metadata_, dict) and session.metadata_.get('worker_blocked'):
            blockers.append('worker_execution_fenced')
        if 'program_policy' in scope:
            blockers.append('program_policy')
        elif session.attack_mode == 'bug_bounty' or scope.get('mode') == 'bug_bounty':
            blockers.append('bug_bounty_mode')
        if not isinstance(scope.get('targets'), list) or not scope['targets']:
            blockers.append('missing_scope')
        audit = {}
        known_blocked = {adapter.capability for adapter in ADAPTERS.values()}.intersection(blocked)
        if known_blocked:
            capability = DecisionLog.metadata_['capability'].as_string()
            query = select(DecisionLog.id, DecisionLog.created_at, capability).where(
                DecisionLog.session_id == session_id, DecisionLog.user_id == user.user_id,
                DecisionLog.decision_type == 'tool_capability_blocked', capability.in_(sorted(known_blocked))
            ).order_by(DecisionLog.created_at.desc(), DecisionLog.id.desc()).limit(100)
            for record_id, created, name in (await db.execute(query)).all():
                if name not in audit and created is not None:
                    timestamp = created.astimezone(timezone.utc) if created.tzinfo else created.replace(tzinfo=timezone.utc)
                    audit[name] = {'record_id': record_id, 'recorded_at': timestamp.isoformat()}
        return {'session_id': session_id, 'engagement_state': state, 'engagement_blockers': blockers,
                'blocked': blocked, 'audit': audit}


@router.post('/sessions/{session_id}/tool-restrictions')
async def block_capability(session_id: str, body: BlockCapability,
                           user: TokenData = Depends(get_current_user)) -> dict:
    if body.capability not in {adapter.capability for adapter in ADAPTERS.values()}:
        raise HTTPException(422, 'Unknown typed capability')
    async with async_session() as db:
        session = await owned_engagement(db, session_id, user.user_id)
        scope = dict(session.scope or {})
        blocked = scope.get('blocked_typed_capabilities', [])
        if not isinstance(blocked, list) or any(not isinstance(item, str) for item in blocked):
            raise HTTPException(409, 'Stored capability restrictions are invalid')
        if body.capability not in blocked:
            blocked = sorted({*blocked, body.capability})
            session.scope = {**scope, 'blocked_typed_capabilities': blocked}
            db.add(DecisionLog(session_id=session_id, user_id=user.user_id, decision_type='tool_capability_blocked',
                               human_involved=True, metadata_={'capability': body.capability}))
            await db.commit()
        return {'session_id': session_id, 'blocked': blocked}


@router.get("/tool-registry")
async def tool_registry(user: TokenData = Depends(get_current_user)) -> dict:
    try:
        registry = load_registry()
        catalog = registry.catalog()
    except RegistryError:
        raise HTTPException(503, "Tool registry unavailable") from None
    status = "not_configured"
    contract_status = "unavailable"
    worker_digest = None
    if settings.KALI_AGENT_URL:
        status = "unreachable"
        try:
            async with asyncio.timeout(3):
                advertised = await worker_jobs.client.capabilities()
            if not isinstance(advertised, dict):
                raise RegistryError("Invalid worker capabilities")
            catalog = registry.catalog(advertised)
            status = "online"
            digest = advertised.get("typed_registry_sha256")
            if "typed_registry_sha256" not in advertised:
                contract_status = "not_reported"
            elif isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest):
                worker_digest = digest
                contract_status = "matched" if digest == catalog["typed_registry_sha256"] else "mismatch"
            elif digest is not None:
                contract_status = "invalid"
        except Exception:
            pass  # Do not expose worker endpoints, credentials or raw transport failures.
    return {
        **catalog,
        "worker": {"status": status, "observed_at": datetime.now(timezone.utc).isoformat(),
                   "container_health": "not_measured", "typed_contract_status": contract_status,
                   "typed_registry_sha256": worker_digest},
    }


@router.get('/sessions/{session_id}/tool-readiness')
async def tool_readiness(session_id: str, user: TokenData = Depends(get_current_user)) -> dict:
    """Operator view: capability readiness and reasons, recommended next tools, recent outcomes.

    Recommendations are proposals from the reasoning state; every run still needs
    the existing command-bound owner approval.
    """
    from memory.team_tasks import team_store
    from security_tools.adapters import contract_digest
    from security_tools.intelligence import readiness, select_tools
    async with async_session() as db:
        session = await owned_engagement(db, session_id, user.user_id, read_only=True)
        scope = session.scope if isinstance(session.scope, dict) else {}
        target = session.target or ''
    blocked = scope.get('blocked_typed_capabilities', [])
    blocked = [item for item in blocked if isinstance(item, str)] if isinstance(blocked, list) else []
    advertised, status = None, 'not_configured'
    if settings.KALI_AGENT_URL:
        status = 'unreachable'
        try:
            async with asyncio.timeout(3):
                advertised = await worker_jobs.client.capabilities()
            status = 'online' if isinstance(advertised, dict) else 'unreachable'
        except Exception:
            advertised = None  # Do not expose worker endpoints or transport failures.
    ledger = await team_store.view(session_id, user.user_id)
    state = (next(iter(ledger.get('investigation_reasoning', [])), {}) or {}).get('state') or {}
    report = readiness(advertised if status == 'online' else None, local_digest=contract_digest(),
                       blocked=blocked, worker_status=status,
                       recent_outcomes=state.get('verification_results', {}).values())
    report['recommendations'] = select_tools(state, report, target=target, scope=scope)
    report['recent_outcomes'] = list(state.get('verification_results', {}).values())[-20:]
    report['session_id'] = session_id
    report['observed_at'] = datetime.now(timezone.utc).isoformat()
    return report
