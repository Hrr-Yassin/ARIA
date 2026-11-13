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
