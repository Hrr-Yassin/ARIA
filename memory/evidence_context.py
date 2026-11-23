"""Deterministic, relevance-based evidence context for model prompts.

Evidence is untrusted data: it is redacted, length-bounded and explicitly
marked as data. Selection never touches the trusted authorization/scope block.
The selector is deterministic for a given input so prompt regressions can be
asserted offline.
"""
from __future__ import annotations

import json
import re
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Iterable, Optional

from config.settings import settings
from security.redaction import deployment_secrets, redact

# Optional collector scoped to one passive reviewer run. Only catalog IDs are retained.
review_evidence_context: ContextVar[dict[str, set[str]] | None] = ContextVar('review_evidence_context', default=None)

GOAL_KEYWORDS = {
    "discovery": ("nmap", "port", "tcp", "service", "version", "banner", "scan"),
    "http_check": ("http", "https", "curl", "header", "response", "status", "server", "tls"),
    "initial_access": ("shell", "session", "exploit", "access", "rce"),
    "dump_creds": ("credential", "password", "hash", "secret", "cred"),
    "privilege_escalation": ("privilege", "root", "admin", "sudo", "escalation"),
    "full_compromise": ("shell", "credential", "root", "admin", "compromise"),
}

_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.:-]{2,}")
UNTRUSTED = "untrusted_data"


def estimate_tokens(text: str) -> int:
    """Conservative, provider-independent estimate (four characters per token)."""
    return (len(text) + 3) // 4


@dataclass(frozen=True)
class EvidenceSelection:
    items: list[dict]
    total_candidates: int
    excluded_foreign: int
    truncated_items: int
    chars: int
    estimated_tokens: int
    limits: dict

    def metadata(self) -> dict:
        """Auditable selection report; goes into the trusted context block."""
        return {
            "trust": UNTRUSTED,
            "total_candidates": self.total_candidates,
            "selected": len(self.items),
            "omitted": self.total_candidates - len(self.items),
            "excluded_foreign": self.excluded_foreign,
            "truncated_items": self.truncated_items,
            "chars": self.chars,
            "estimated_tokens": self.estimated_tokens,
            "limits": dict(self.limits),
        }


def _entry_field(entry: dict, name: str, default=""):
    value = entry.get(name)
    if value in (None, "") and isinstance(entry.get("data"), dict):
        value = entry["data"].get(name)
    if value in (None, "") and name == "summary":
        value = entry.get("content")
    if value in (None, "") and name == "provenance" and isinstance(entry.get("data"), dict):
        value = entry["data"].get("source")
    return default if value is None else value


def _owner_value(entry: dict, name: str) -> str:
    return str(_entry_field(entry, name, "") or "")


def is_owned_evidence(entry, *, session_id: str = "", owner_id: str = "") -> bool:
    """Reject entries that declare a different session or owner."""
    if not isinstance(entry, dict):
        return False
    declared_session = _owner_value(entry, "session_id")
    if session_id and declared_session and declared_session != str(session_id):
        return False
    declared_owner = _owner_value(entry, "owner_id")
    if owner_id and declared_owner and declared_owner != str(owner_id):
        return False
    return True


def filter_owned_evidence(entries: Iterable, *, session_id: str = "",
                          owner_id: str = "") -> list[dict]:
    return [entry for entry in entries if is_owned_evidence(
        entry, session_id=session_id, owner_id=owner_id)]


def _text(value, limit: int) -> str:
    if not isinstance(value, (str, int, float)):
        return ""
    text = " ".join(str(value).split())
    return redact(text, deployment_secrets())[:limit]


def _query_tokens(*values) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        if isinstance(value, str):
            tokens.update(_TOKEN.findall(value.lower()))
    return tokens


def _relevance(entry: dict, *, target: str, goal: str, query_tokens: set[str]) -> int:
    summary = str(_entry_field(entry, "summary", "") or "")
    command = str(_entry_field(entry, "command", "") or "")
    haystack = f"{summary} {command}".lower()
    score = 0
    target_lower = target.lower().strip()
    if target_lower and target_lower in haystack:
        score += 100
    for keyword in GOAL_KEYWORDS.get(goal.lower(), ()):
        if keyword in haystack:
            score += 15
    for token in query_tokens:
        if token in haystack:
            score += 10
    return score


def select_evidence(entries: Iterable, *, session_id: str = "", owner_id: str = "",
                    target: str = "", goal: str = "", query: str = "",
                    max_items: Optional[int] = None, max_chars: Optional[int] = None,
                    max_tokens: Optional[int] = None,
                    item_chars: Optional[int] = None,
                    command_chars: Optional[int] = None) -> EvidenceSelection:
    """Select the most relevant owned evidence within count/char/token budgets.

    Ordering is deterministic: relevance first, then most recent input position,
    then identifier. Every selected item keeps its evidence ID and provenance;
    truncated summaries are flagged rather than silently shortened.
    """
    max_items = settings.EVIDENCE_CONTEXT_MAX_ITEMS if max_items is None else max_items
    max_chars = settings.EVIDENCE_CONTEXT_MAX_CHARS if max_chars is None else max_chars
    max_tokens = settings.EVIDENCE_CONTEXT_MAX_TOKENS if max_tokens is None else max_tokens
    item_chars = settings.EVIDENCE_CONTEXT_ITEM_CHARS if item_chars is None else item_chars
    command_chars = (settings.EVIDENCE_CONTEXT_COMMAND_CHARS
                     if command_chars is None else command_chars)
    limits = {
        "max_items": int(max_items),
        "max_chars": int(max_chars),
        "max_tokens": int(max_tokens),
        "item_chars": int(item_chars),
        "command_chars": int(command_chars),
    }

    source = list(entries or [])
    owned = filter_owned_evidence(source, session_id=session_id, owner_id=owner_id)
    excluded_foreign = len(source) - len(owned)
    query_tokens = _query_tokens(query, goal)

    scored = []
    for index, entry in enumerate(owned):
        if not isinstance(entry, dict):
            continue
        evidence_id = str(entry.get("id") or "").strip()
        if not evidence_id or len(evidence_id) > 100:
            continue
        scored.append((_relevance(entry, target=target, goal=goal,
                                  query_tokens=query_tokens), index, entry, evidence_id))
    # Stable and deterministic: highest relevance, then latest input entry.
    scored.sort(key=lambda item: (-item[0], -item[1], item[3]))

    items: list[dict] = []
    truncated_items = 0
    for _, _, entry, evidence_id in scored:
        if len(items) >= max_items:
            break
        cleaned_summary = _text(_entry_field(entry, "summary", ""), 100000)
        cleaned_command = _text(_entry_field(entry, "command", ""), 100000)
        summary = cleaned_summary[:item_chars]
        command = cleaned_command[:command_chars]
        provenance = _text(_entry_field(entry, "provenance", "") or "saved_tool_output_unverified", 100)
        item = {
            "id": evidence_id,
            "summary": summary,
            "command": command,
            "provenance": provenance,
        }
        item_truncated = (len(summary) < len(cleaned_summary)
                          or len(command) < len(cleaned_command))
        if item_truncated:
            item["truncated"] = True
        candidates = [*items, item]
        block = json.dumps(candidates, separators=(",", ":"), ensure_ascii=False)
        while (item["summary"]
               and (len(block) > max_chars or estimate_tokens(block) > max_tokens)):
            overflow = max(len(block) - max_chars,
                           (estimate_tokens(block) - max_tokens) * 4)
            keep = max(0, len(item["summary"]) - max(1, overflow))
            if keep == len(item["summary"]):
                break
            item["summary"] = item["summary"][:keep]
            item_truncated = True
            item["truncated"] = True
            block = json.dumps([*items, item], separators=(",", ":"), ensure_ascii=False)
        if len(block) > max_chars or estimate_tokens(block) > max_tokens:
            break
        if item_truncated:
            truncated_items += 1
        items.append(item)

    block = json.dumps(items, separators=(",", ":"), ensure_ascii=False)
    return EvidenceSelection(
        items=items,
        total_candidates=len(scored),
        excluded_foreign=excluded_foreign,
        truncated_items=truncated_items,
        chars=len(block),
        estimated_tokens=estimate_tokens(block),
        limits=limits,
    )
