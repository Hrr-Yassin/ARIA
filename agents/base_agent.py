"""
PentestAI v10 — Base Agent
Abstract base class for all specialized agents.
Handles skill-level adaptation, shared memory, LLM interaction, and v10's
task-based tiered LLM routing.
"""
import json
import re
import uuid
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

import structlog

from llm.pool_manager import pool_manager
from memory.knowledge_cache import knowledge_cache
from memory.vector_store import vector_store

log = structlog.get_logger(__name__)

SKILL_INSTRUCTIONS = {
    "beginner": (
        "The pentester is a BEGINNER. Explain EVERY command in detail: what it does, "
        "each flag, expected output, what to look for. Provide educational context. "
        "Example: 'nmap -sS means SYN scan — it sends SYN packets and waits for SYN-ACK. "
        "This is stealthier than a full TCP connect scan because...'"
    ),
    "intermediate": (
        "The pentester is INTERMEDIATE. Explain only uncommon options and non-obvious commands. "
        "Skip basics like -sV for nmap but explain -sC --script=vuln or unusual nuclei templates."
    ),
    "expert": (
        "The pentester is an EXPERT. Advanced assistance only. Suggest attack chains, pivoting "
        "strategies, custom payloads, evasion techniques. No basic explanations."
    ),
}


class BaseAgent(ABC):
    """Abstract base for all pentesting agents."""

    agent_name: str = "base"
    agent_role: str = "Base Agent"

    def __init__(self):
        self.log = structlog.get_logger(self.agent_name)

    @abstractmethod
    def get_system_prompt(self, skill_level: str = "intermediate") -> str:
        """Return the system prompt for this agent."""
        pass

    @abstractmethod
    async def process(self, session_id: str, user_id: str, input_data: dict,
                      skill_level: str = "intermediate") -> dict:
        """Process input and return agent response."""
        pass

    # ── LLM access ──────────────────────────────────────────────────────

    async def query_llm(self, user_id: str, prompt: str, system: str = "") -> dict:
        """Legacy v9-style LLM query. Uses the default task routing."""
        return await pool_manager.query(user_id, prompt, system)

    async def query_llm_smart(self, user_id: str, prompt: str, system: str = "",
                              task_type: str = "output_analysis") -> dict:
        """
        v10 task-routed LLM query.

        task_type values (see llm.pool_manager.TASK_MODEL_MAP):
            - "intent_classification"   (no-LLM, handled by caller)
            - "output_analysis"         (small, fast)
            - "next_step_suggestion"    (small, fast)
            - "vuln_validation"         (medium)
            - "exploit_reasoning"       (best)
            - "attack_planning"         (best)
            - "post_exploit_strategy"   (best)
            - "report_generation"       (best)
            - "react_reasoning"         (best)
            - "chat_reply"              (small)
        """
        return await pool_manager.query_for_task(user_id, task_type, prompt, system)

    # ── JSON parsing helper ─────────────────────────────────────────────

    def parse_json(self, content: str) -> Optional[dict]:
        """Safely parse JSON from LLM response."""
        content = re.sub(r"```(?:json)?\s*", "", content)
        content = re.sub(r"```\s*", "", content).strip()
        m = re.search(r"\{.*\}", content, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return None

    # ── Shared memory access ────────────────────────────────────────────

    def get_context(self, session_id: str, query: str = "") -> str:
        """Get shared context from vector store."""
        return vector_store.build_context(session_id, query)

    async def get_similar_cases(self, query: str, top_k: int = 3,
                                 exclude_session: str = "") -> str:
        """v10: cross-session semantic context for LLM prompts."""
        try:
            results = await vector_store.search_similar(
                query, top_k=top_k, exclude_session=exclude_session or None,
            )
            return vector_store.similar_cases_block(results)
        except Exception as exc:  # noqa: BLE001
            log.debug("similar-cases lookup failed", error=str(exc))
            return ""

    def get_skill_instruction(self, skill_level: str) -> str:
        return SKILL_INSTRUCTIONS.get(skill_level, SKILL_INSTRUCTIONS["intermediate"])

    def store_discovery(self, session_id: str, content: str,
                         metadata: dict = None, entry_type: str = "discovery"):
        """Store a discovery in shared memory (semantic if available)."""
        vector_store.add(session_id, content, metadata, self.agent_name, entry_type)

    def generate_action_id(self) -> str:
        return str(uuid.uuid4())
