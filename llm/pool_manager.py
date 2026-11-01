"""
PentestAI v10 — Intelligent LLM Pool Manager (Tiered Routing)
=============================================================

Per-user API key management with smart rotation, quota tracking, failover,
AND task-based model selection so cheap tasks don't waste expensive tokens.

Routing tiers:

  Tier 1 — NO LLM (pure code):
    intent_classification, kb_query, dedup_check
    (These are handled by config/rules — the pool manager returns
     {success: False, error: "no_llm_needed"} to signal the caller.)

  Tier 2 — Small & fast (cheap):
    output_analysis, next_step_suggestion, vuln_validation
    → Groq llama-3.1-8b-instant or llama-3.3-70b-versatile

  Tier 3 — Best available (complex reasoning):
    exploit_reasoning, attack_planning, post_exploit_strategy, report_generation
    → OpenRouter (Claude) > Gemini > Groq 70B

Graceful degradation: if the preferred tier's keys are exhausted, we fall
through to whatever the user has available — better to answer on a smaller
model than fail.
"""
import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass, field

import structlog
from cryptography.fernet import Fernet, MultiFernet, InvalidToken

from config.settings import settings
from llm.groq_client import GroqClient
from llm.gemini_client import GeminiClient
from llm.openrouter_client import OpenRouterClient

log = structlog.get_logger(__name__)

PROVIDER_CLIENTS = {
    "groq": GroqClient,
    "gemini": GeminiClient,
    "openrouter": OpenRouterClient,
}

PROVIDER_DEFAULTS = {
    "groq":       {"model": "llama-3.3-70b-versatile", "limit": 30, "cooldown": 60},
    "gemini":     {"model": "gemini-2.0-flash",        "limit": 15, "cooldown": 60},
    "openrouter": {"model": "anthropic/claude-sonnet-4-5", "limit": 10, "cooldown": 60},
}


# ─────────────────────────────────────────────────────────────────────────────
#  TASK → (provider preferences, model override, tier label)
# ─────────────────────────────────────────────────────────────────────────────
# `preferred_providers`: ordered list — try in this order
# `model`: specific model override (None = use provider default)
# `tier`: 0 = no LLM, 1 = small/fast, 2 = medium, 3 = best
TASK_MODEL_MAP: Dict[str, dict] = {
    # Tier 0 — NEVER use LLM (handled deterministically)
    "intent_classification": {"tier": 0},
    "kb_query":              {"tier": 0},
    "dedup_check":           {"tier": 0},
    "parse_output":          {"tier": 0},

    # Tier 1 — Small & fast
    "output_analysis":       {"tier": 1,
                              "preferred_providers": ["groq", "gemini"],
                              "model_override": {"groq": "llama-3.3-70b-versatile"}},
    "next_step_suggestion":  {"tier": 1,
                              "preferred_providers": ["groq", "gemini"],
                              "model_override": {"groq": "llama-3.3-70b-versatile"}},
    "vuln_validation":       {"tier": 1,
                              "preferred_providers": ["gemini", "groq"],
                              "model_override": {}},
    "chat_reply":            {"tier": 1,
                              "preferred_providers": ["groq", "gemini"],
                              "model_override": {}},

    # Tier 2 — Reasoning (medium complexity)
    "cve_reasoning":         {"tier": 2,
                              "preferred_providers": ["openrouter", "gemini", "groq"],
                              "model_override": {}},

    # Tier 3 — Best available
    "exploit_reasoning":     {"tier": 3,
                              "preferred_providers": ["openrouter", "gemini", "groq"],
                              "model_override": {}},
    "attack_planning":       {"tier": 3,
                              "preferred_providers": ["openrouter", "gemini", "groq"],
                              "model_override": {}},
    "post_exploit_strategy": {"tier": 3,
                              "preferred_providers": ["openrouter", "gemini", "groq"],
                              "model_override": {}},
    "report_generation":     {"tier": 3,
                              "preferred_providers": ["openrouter", "gemini", "groq"],
                              "model_override": {}},
    "react_reasoning":       {"tier": 3,
                              "preferred_providers": ["openrouter", "gemini", "groq"],
                              "model_override": {}},
}

DEFAULT_TASK = "output_analysis"


@dataclass
class KeyState:
    provider: str
    key_id: str
    encrypted_key: str
    decrypted_key: str = ""
    requests_used: int = 0
    requests_limit: int = 30
    last_used: float = 0
    cooldown_until: float = 0
    last_error: str = ""
    is_active: bool = True
    label: str = ""


@dataclass
class UserPool:
    user_id: str
    keys: List[KeyState] = field(default_factory=list)
    current_provider: str = ""
    current_key_idx: int = 0


class LLMPoolManager:
    """
    Per-user key rotation with task-based tiered model selection.

    Back-compat: `query()` still works as in v9 (uses DEFAULT_TASK routing).
    """

    # Quality ranking used when no task is specified
    PROVIDER_PRIORITY = {"openrouter": 0, "gemini": 1, "groq": 2}

    def __init__(self):
        self._pools: Dict[str, UserPool] = {}
        self._locks = {}
        try:
            self._fernet = MultiFernet([Fernet(settings.FERNET_KEY.encode()),
                                        *(Fernet(k.encode()) for k in settings.FERNET_PREVIOUS_KEYS)])
        except Exception:
            raise ValueError("A persistent valid FERNET_KEY is required") from None

    def encrypt_key(self, api_key: str) -> str:
        return self._fernet.encrypt(api_key.encode()).decode()

    def decrypt_key(self, encrypted: str) -> str:
        try:
            return self._fernet.decrypt(encrypted.encode()).decode()
        except (InvalidToken, ValueError, TypeError):
            raise ValueError("Provider key decryption failed; check encryption configuration") from None

    def load_user_keys(self, user_id: str, db_keys: list):
        pool = UserPool(user_id=user_id)
        for k in db_keys:
            if not k.is_active:
                continue
            try:
                self.decrypt_key(k.encrypted_key)
                decryptable = True
            except ValueError:
                decryptable = False
            state = KeyState(
                provider=k.provider,
                key_id=k.id,
                encrypted_key=k.encrypted_key,
                decrypted_key="",
                requests_used=k.requests_used or 0,
                requests_limit=k.requests_limit or PROVIDER_DEFAULTS.get(k.provider, {}).get("limit", 30),
                cooldown_until=k.cooldown_until.timestamp() if k.cooldown_until else 0,
                last_error=(k.last_error or "") if decryptable else "key_unavailable",
                is_active=decryptable,
                label=k.label or "",
            )
            pool.keys.append(state)
        if pool.keys:
            pool.current_provider = pool.keys[0].provider
        self._pools[user_id] = pool

    def get_pool(self, user_id: str) -> Optional[UserPool]:
        return self._pools.get(user_id)

    # ── Key selection ───────────────────────────────────────────────────
    def _find_best_key(self, pool: UserPool,
                       exclude_ids: Optional[set] = None,
                       preferred_providers: Optional[List[str]] = None,
                       ) -> Optional[KeyState]:
        """
        Find the best available key. If `preferred_providers` is given, prefer
        those in order; otherwise use the quality ranking.
        """
        now = time.time()
        exclude = exclude_ids or set()
        candidates = []

        for key in pool.keys:
            if key.key_id in exclude:
                continue
            if not key.is_active:
                continue
            if key.cooldown_until > now:
                continue
            if key.requests_used >= key.requests_limit:
                if 0 < key.cooldown_until <= now:
                    key.requests_used = 0
                    key.cooldown_until = 0
                else:
                    continue

            if preferred_providers:
                try:
                    priority = preferred_providers.index(key.provider)
                except ValueError:
                    priority = len(preferred_providers) + 10  # not preferred — last
            else:
                priority = self.PROVIDER_PRIORITY.get(key.provider, 10)

            remaining = key.requests_limit - key.requests_used
            candidates.append((priority, -remaining, key))

        if not candidates:
            for key in pool.keys:
                if key.key_id in exclude:
                    continue
                if key.is_active and 0 < key.cooldown_until <= now:
                    key.requests_used = 0
                    key.cooldown_until = 0
                    priority = self.PROVIDER_PRIORITY.get(key.provider, 10)
                    candidates.append((priority, -key.requests_limit, key))

        if not candidates:
            return None
        candidates.sort(key=lambda x: (x[0], x[1]))
        return candidates[0][2]

    # ── Query (default, v9-compatible) ──────────────────────────────────
    async def query(self, user_id: str, prompt: str, system: str = "") -> dict:
        """Back-compat wrapper — routes through DEFAULT_TASK."""
        return await self.query_for_task(user_id, DEFAULT_TASK, prompt, system)

    # ── Query (v10 task-based) ──────────────────────────────────────────
    async def refresh_user_keys(self, user_id):
        from api.auth import current_identity
        from memory.database_models import UserAPIKey, async_session
        from sqlalchemy import select
        await current_identity(user_id)
        async with async_session() as db:
            rows = (await db.execute(select(UserAPIKey).where(UserAPIKey.user_id == user_id))).scalars().all()
            self.load_user_keys(user_id, rows)

    async def _reserve_key(self, user_id, key_id):
        from memory.database_models import UserAPIKey, async_session
        from sqlalchemy import update
        async with async_session() as db:
            result = await db.execute(update(UserAPIKey).where(
                UserAPIKey.id == key_id, UserAPIKey.user_id == user_id,
                UserAPIKey.is_active.is_(True), UserAPIKey.requests_used < UserAPIKey.requests_limit)
                .values(requests_used=UserAPIKey.requests_used + 1))
            await db.commit()
            return result.rowcount == 1

    async def query_for_task(self, user_id: str, task_type: str, prompt: str, system: str = "") -> dict:
        from security.redaction import redact, deployment_secrets
        from memory.access_scope import owned_session_ids
        from memory.attack_knowledge_base import attack_kb
        async with self._locks.setdefault(user_id, asyncio.Lock()):
            try:
                await self.refresh_user_keys(user_id)
                secrets = deployment_secrets()
                for key in self._pools.get(user_id, UserPool(user_id)).keys:
                    if not key.is_active:
                        continue
                    secrets.append(self.decrypt_key(key.encrypted_key))
                for sid in await owned_session_ids(user_id):
                    for host in attack_kb.get_all_hosts(sid):
                        for credential in host.credentials:
                            secrets.extend([credential.get('password', ''), credential.get('hash_value', '')])
                prompt = '<untrusted_engagement_data>\n' + redact(prompt, secrets) + '\n</untrusted_engagement_data>'
                system = redact(system, secrets)
                return await self._query_for_task(user_id, task_type, prompt, system)
            except Exception:
                return {'success': False, 'content': '', 'error': 'provider_authorization_or_storage_unavailable'}

    async def _query_for_task(self, user_id: str, task_type: str,
                             prompt: str, system: str = "") -> dict:
        """
        Route the query to the best model for this task type.

        Returns dict:
            {success, content, error, provider, model, task_type, tier, latency_ms}
        """
        task_config = TASK_MODEL_MAP.get(task_type, TASK_MODEL_MAP[DEFAULT_TASK])
        tier = task_config.get("tier", 1)

        # Tier 0 — caller should not have asked the LLM at all.
        if tier == 0:
            return {
                "success": False,
                "content": "",
                "error": "no_llm_needed_for_task",
                "task_type": task_type,
                "tier": 0,
                "provider": "none",
            }

        pool = self._pools.get(user_id)
        if not pool or not pool.keys:
            return {"success": False, "content": "", "error": "no_keys",
                    "provider": "none", "task_type": task_type, "tier": tier}

        preferred = task_config.get("preferred_providers", [])
        model_override = task_config.get("model_override", {})

        tried: set = set()
        last_error = ""

        # Pass 1: preferred providers
        # Pass 2: any provider (fallback)
        for pass_num in (1, 2):
            provider_filter = preferred if pass_num == 1 and preferred else None

            while len(tried) < len(pool.keys):
                key_state = self._find_best_key(
                    pool, exclude_ids=tried, preferred_providers=provider_filter,
                )
                if not key_state:
                    break

                # On pass 1, skip keys whose provider isn't in the preferred list
                if provider_filter and key_state.provider not in provider_filter:
                    tried.add(key_state.key_id)
                    continue

                tried.add(key_state.key_id)

                client_cls = PROVIDER_CLIENTS.get(key_state.provider)
                if not client_cls:
                    continue

                defaults = PROVIDER_DEFAULTS.get(key_state.provider, {})
                model = model_override.get(key_state.provider) or defaults.get("model", "")
                client = client_cls(
                    api_key=self.decrypt_key(key_state.encrypted_key),
                    model=model,
                    temperature=settings.LLM_TEMPERATURE,
                )

                if not await self._reserve_key(user_id, key_state.key_id):
                    key_state.is_active = False
                    continue
                try:
                    result = await client.query(prompt, system)
                except Exception as e:
                    key_state.last_error = "provider_request_failed"
                    log.warning("LLM exception",
                                provider=key_state.provider,
                                error="provider_request_failed")
                    continue

                if result.get("success"):
                    key_state.requests_used += 1
                    key_state.last_used = time.time()
                    key_state.last_error = ""
                    pool.current_provider = key_state.provider
                    result.update({
                        "provider": key_state.provider,
                        "model": model,
                        "key_label": key_state.label,
                        "task_type": task_type,
                        "tier": tier,
                    })
                    log.info("LLM ok",
                             provider=key_state.provider, model=model,
                             task=task_type, tier=tier,
                             user=user_id,
                             remaining=key_state.requests_limit - key_state.requests_used,
                             pass_num=pass_num)
                    return result

                # Failure → mark + continue
                raw_error = str(result.get("error", "unknown"))
                error = "rate_limited" if "429" in raw_error or "rate_limited" in raw_error else "invalid_key" if "401" in raw_error or "403" in raw_error else "provider_request_failed"
                last_error = error
                if "rate_limited" in error or "429" in error:
                    key_state.cooldown_until = time.time() + defaults.get("cooldown", 60)
                    key_state.requests_used = key_state.requests_limit
                    key_state.last_error = "rate_limited"
                elif "401" in error or "403" in error or "invalid" in error.lower():
                    key_state.is_active = False
                    key_state.last_error = "invalid_key"
                else:
                    key_state.last_error = error

            # Don't re-run the pass with the same tried set on pass 2 if
            # pass 1 already consumed everything
            if provider_filter is None:
                break

        return {
            "success": False, "content": "",
            "error": f"all_exhausted ({last_error})",
            "provider": "none", "task_type": task_type, "tier": tier,
        }

    # ── Status (for /api/status UI) ─────────────────────────────────────
    def get_status(self, user_id: str) -> list:
        pool = self._pools.get(user_id)
        if not pool:
            return []
        now = time.time()
        status = []
        for key in pool.keys:
            remaining = max(0, key.requests_limit - key.requests_used)
            cooldown_remaining = max(0, int(key.cooldown_until - now))
            state = "active"
            if cooldown_remaining > 0:
                state = f"cooldown ({cooldown_remaining}s)"
            elif remaining <= 0:
                state = "exhausted"
            elif not key.is_active:
                state = "disabled"
            status.append({
                "key_id": key.key_id,
                "provider": key.provider,
                "label": key.label,
                "state": state,
                "remaining": remaining,
                "limit": key.requests_limit,
                "used": key.requests_used,
                "last_error": key.last_error,
                "is_current": key.provider == pool.current_provider,
            })
        return status

    def all_offline(self, user_id: str) -> bool:
        pool = self._pools.get(user_id)
        if not pool or not pool.keys:
            return True
        now = time.time()
        for key in pool.keys:
            if key.is_active and key.cooldown_until <= now \
               and key.requests_used < key.requests_limit:
                return False
        return True


# Global singleton
pool_manager = LLMPoolManager()
