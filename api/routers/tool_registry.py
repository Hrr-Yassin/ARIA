"""Authenticated, read-only registry discovery. No operation submission route."""
import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from api.auth import TokenData, get_current_user
from config.security_tool_registry import RegistryError, load_registry
from config.settings import settings
from memory.worker_jobs import worker_jobs

router = APIRouter()


@router.get("/tool-registry")
async def tool_registry(user: TokenData = Depends(get_current_user)) -> dict:
    try:
        registry = load_registry()
        catalog = registry.catalog()
    except RegistryError:
        raise HTTPException(503, "Tool registry unavailable") from None
    status = "not_configured"
    if settings.KALI_AGENT_URL:
        status = "unreachable"
        try:
            async with asyncio.timeout(3):
                advertised = await worker_jobs.client.capabilities()
            if not isinstance(advertised, dict):
                raise RegistryError("Invalid worker capabilities")
            catalog = registry.catalog(advertised)
            status = "online"
        except Exception:
            pass  # Do not expose worker endpoints, credentials or raw transport failures.
    return {
        **catalog,
        "worker": {"status": status, "observed_at": datetime.now(timezone.utc).isoformat(),
                   "container_health": "not_measured"},
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
