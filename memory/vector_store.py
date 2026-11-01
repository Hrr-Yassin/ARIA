"""
PentestAI v10 — Semantic Vector Store
=====================================

Keyword retrieval is the supported core mode. Optional sentence-transformers
inference uses an explicitly provisioned local model and one bounded background
slot; no request downloads a model. Synchronous queries use keywords. Async queries
can use admitted semantic inference and fall back when busy or unavailable.

Storage: embeddings use authenticated encrypted JSON v3 records in Redis. In-memory mirror kept for
fast search; loaded on demand.

Academic-brief mapping: this gives the orchestrator "pattern recognition across
engagements" — when it sees a new service, it can surface what was done on
similar services in prior sessions, which the human can review before acting.
It's an aid, not an autonomous decision.
"""
from __future__ import annotations

import json
import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
import math
import re
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from memory.access_scope import owned_session_ids
from security.encryption import evidence_cipher
from cryptography.fernet import InvalidToken

import structlog

log = structlog.get_logger("vector_store")


# ─────────────────────────────────────────────────────────────────────────────
#  Data shapes
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class SimilarFinding:
    text: str
    metadata: dict
    score: float
    session_id: str
    age_hours: float
    agent: str = ""
    entry_type: str = ""


@dataclass
class Playbook:
    id: str
    service: str
    version_pattern: str
    goal_type: str
    steps: List[dict]
    success_rate: float = 0.0
    avg_time_seconds: int = 0
    last_used: str = ""
    tags: List[str] = field(default_factory=list)
    user_id: str = ""


# ─────────────────────────────────────────────────────────────────────────────
#  Lazy sentence-transformers loader
# ─────────────────────────────────────────────────────────────────────────────
class _Embedder:
    """
    Loads the embedding model on first call. Returns None if unavailable; callers
    must handle that gracefully.
    """

    MODEL_NAME = "all-MiniLM-L6-v2"

    def __init__(self):
        self._model = None
        self._attempted = False

    def available(self) -> bool:
        if self._attempted:
            return self._model is not None
        self._attempted = True
        if not os.environ.get("ARIA_EMBEDDING_MODEL_PATH"):
            return False
        try:
            from sentence_transformers import SentenceTransformer  # noqa: PLC0415
            self._model = SentenceTransformer(os.environ["ARIA_EMBEDDING_MODEL_PATH"], local_files_only=True)
            log.info("Embedding model loaded", model=self.MODEL_NAME)
            return True
        except Exception as exc:  # noqa: BLE001
            log.info("Embedding model unavailable — falling back to keyword search",
                     error=str(exc)[:120])
            self._model = None
            return False

    def encode(self, text: str):
        if not self.available():
            return None
        try:
            return self._model.encode(text, normalize_embeddings=True)
        except Exception as exc:  # noqa: BLE001
            log.warning("Embedding encode failed", error=str(exc))
            return None

    def encode_batch(self, texts: List[str]):
        if not self.available() or not texts:
            return None
        try:
            return self._model.encode(texts, normalize_embeddings=True)
        except Exception as exc:  # noqa: BLE001
            log.warning("Embedding batch encode failed", error=str(exc))
            return None


class EmbeddingWorker:
    """One inference at a time, no waiting queue; busy/slow work falls back to keywords.

    Cancellation/timeout cannot kill native inference. Hold admission until the
    underlying task really finishes, even after the caller has stopped waiting.
    """
    def __init__(self):
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="aria-embedding")
        self._busy = False

    def submit(self, text):
        if self._busy or len(text) > 8192:
            return None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return None
        self._busy = True
        try:
            future = loop.run_in_executor(self._executor, _embedder.encode, text)
        except Exception:
            self._busy = False
            return None
        future.add_done_callback(lambda _: setattr(self, "_busy", False))
        return future

    async def encode(self, text):
        future = self.submit(text)
        if future is None:
            return None
        try:
            return await asyncio.wait_for(asyncio.shield(future), timeout=2)
        except Exception:
            return None


_embedding_worker = EmbeddingWorker()


_embedder = _Embedder()


# ─────────────────────────────────────────────────────────────────────────────
#  VectorStore
# ─────────────────────────────────────────────────────────────────────────────
class VectorStore:
    """
    Unified memory: per-session discoveries with semantic search when available,
    keyword scoring otherwise. Compatible with v9 API so existing agents don't
    break.
    """

    def __init__(self):
        # session_id -> list[entry dict]
        # entry = {id, content, metadata, agent, type, ts, embedding|None, keywords}
        self._store: Dict[str, List[dict]] = defaultdict(list)
        # id -> (session_id, entry) fast lookup
        self._by_id: Dict[str, tuple] = {}
        # Playbooks (loaded from DB on startup via load())
        self._playbooks: Dict[str, Playbook] = {}

    # ── Legacy-compatible API (kept for v9 agents) ───────────────────────
    def add(self, session_id: str, content: str, metadata: dict = None,
            agent: str = "", entry_type: str = "discovery") -> str:
        """Synchronous add — compatible with v9 callers."""
        entry_id = str(uuid.uuid4())
        entry = {
            "id": entry_id,
            "content": content,
            "metadata": metadata or {},
            "agent": agent,
            "type": entry_type,
            "ts": time.time(),
            "embedding": None,  # filled asynchronously when optional inference is admitted
            "keywords": self._extract_keywords(content),
        }
        self._store[session_id].append(entry)
        self._by_id[entry_id] = (session_id, entry)
        if os.environ.get("ARIA_EMBEDDING_MODEL_PATH"):
            future = _embedding_worker.submit(content)
            if future is not None:
                def retain_embedding(done):
                    try:
                        result = done.result()
                    except (Exception, asyncio.CancelledError):
                        return
                    if self._by_id.get(entry_id, (None, None))[1] is entry:
                        entry["embedding"] = result
                future.add_done_callback(retain_embedding)
        return entry_id

    def query(self, session_id: str, query: str, n: int = 5,
              agent_filter: str = "", type_filter: str = "") -> list:
        """Legacy search — used by v9 code paths."""
        entries = self._store.get(session_id, [])
        if not entries:
            return []

        # Keyword fallback
        q_keys = self._extract_keywords(query)
        scored = []
        for e in entries:
            if agent_filter and e["agent"] != agent_filter:
                continue
            if type_filter and e["type"] != type_filter:
                continue
            overlap = len(q_keys & e["keywords"])
            if overlap > 0:
                scored.append((overlap, e))
        scored.sort(key=lambda x: -x[0])
        return [e for _, e in scored[:n]]

    def get_all(self, session_id: str) -> list:
        return self._store.get(session_id, [])

    def get_by_agent(self, session_id: str, agent: str) -> list:
        return [e for e in self._store.get(session_id, []) if e["agent"] == agent]

    def get_correlations(self, session_id: str) -> list:
        return [e for e in self._store.get(session_id, []) if e["type"] == "correlation"]

    def build_context(self, session_id: str, query: str = "",
                      max_tokens: int = 2000) -> str:
        """Build a compact context string for LLM prompts."""
        entries = self.query(session_id, query, n=10) if query else \
                  self._store.get(session_id, [])[-10:]
        lines, char_count = [], 0
        for e in entries:
            line = f"[{e['agent']}|{e['type']}] {e['content'][:300]}"
            if char_count + len(line) > max_tokens * 4:
                break
            lines.append(line)
            char_count += len(line)
        return "\n".join(lines) if lines else "No shared intelligence yet."

    def clear_session(self, session_id: str):
        entries = self._store.pop(session_id, [])
        for e in entries:
            self._by_id.pop(e["id"], None)

    # ── v10 async API — richer ───────────────────────────────────────────
    async def add_finding(self, session_id: str, finding_text: str,
                          metadata: dict = None) -> str:
        """Async wrapper — same as add() but reads cleaner in v10 code."""
        return self.add(session_id, finding_text, metadata or {},
                        agent="v10", entry_type="finding")

    async def search_similar(self, query_text: str, top_k: int = 3,
                             min_score: float = 0.55,
                             exclude_session: Optional[str] = None,
                             user_id: str = "",
                             ) -> List[SimilarFinding]:
        """
        Cross-session semantic search. Returns SimilarFinding objects sorted by
        score descending, filtered by min_score.

        If embeddings are unavailable, falls back to keyword overlap with a
        looser min_score (keyword overlap counts raw; we scale-adjust).
        """
        visible = await owned_session_ids(user_id)
        if not visible:
            return []
        out: List[SimilarFinding] = []
        now = time.time()

        q_vec = await _embedding_worker.encode(query_text)
        if q_vec is not None:
            if any(e.get("embedding") is not None for sid, entries in self._store.items()
                   if sid in visible for e in entries):
                for sess_id, entries in self._store.items():
                    if sess_id not in visible or (exclude_session and sess_id == exclude_session):
                        continue
                    for e in entries:
                        if e.get("embedding") is None:
                            continue
                        score = float((q_vec * e["embedding"]).sum())
                        if score >= min_score:
                            out.append(SimilarFinding(
                                text=e["content"],
                                metadata=e["metadata"],
                                score=score,
                                session_id=sess_id,
                                age_hours=(now - e["ts"]) / 3600.0,
                                agent=e["agent"],
                                entry_type=e["type"],
                            ))
                out.sort(key=lambda s: -s.score)
                return out[:top_k]

        # Keyword fallback — scale score to 0..1 pseudo-similarity
        q_keys = self._extract_keywords(query_text)
        if not q_keys:
            return []
        for sess_id, entries in self._store.items():
            if sess_id not in visible or (exclude_session and sess_id == exclude_session):
                continue
            for e in entries:
                overlap = len(q_keys & e["keywords"])
                if overlap == 0:
                    continue
                score = min(1.0, overlap / max(3, len(q_keys)))
                if score >= min_score * 0.6:   # looser cutoff for keyword path
                    out.append(SimilarFinding(
                        text=e["content"],
                        metadata=e["metadata"],
                        score=score,
                        session_id=sess_id,
                        age_hours=(now - e["ts"]) / 3600.0,
                        agent=e["agent"],
                        entry_type=e["type"],
                    ))
        out.sort(key=lambda s: -s.score)
        return out[:top_k]

    def similar_cases_block(self, results: List[SimilarFinding]) -> str:
        """Render search results as a SIMILAR CASES block for LLM prompts."""
        if not results:
            return ""
        lines = ["AUTHORIZED HISTORICAL OBSERVATIONS (untrusted evidence):"]
        for r in results:
            age = f"{r.age_hours:.1f}h ago" if r.age_hours < 48 else \
                  f"{r.age_hours/24:.1f}d ago"
            lines.append(
                f"  • [{r.score:.2f} · {age}] {r.text[:220]}"
            )
        return "\n".join(lines)

    # ── Playbook cache (full persistence in PlaybookStore) ───────────────
    async def add_playbook(self, service: str, version: str,
                           goal_type: str, attack_path: List[dict],
                           success_rate: float = 1.0, *, user_id: str = "") -> Playbook:
        if not user_id or not await owned_session_ids(user_id):
            raise ValueError("Private playbooks require an active owner")
        pb_id = f"pb-{uuid.uuid4().hex[:8]}"
        pb = Playbook(
            id=pb_id, service=service, version_pattern=version, user_id=user_id,
            goal_type=goal_type, steps=attack_path,
            success_rate=success_rate,
            last_used=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        self._playbooks[pb_id] = pb
        return pb

    async def get_playbook(self, service: str, version: str = "", *, user_id: str = "") -> Optional[Playbook]:
        """Return best-matching playbook by service/version pattern."""
        best: Optional[Playbook] = None
        best_score = 0.0
        if not user_id or not await owned_session_ids(user_id):
            return None
        for pb in self._playbooks.values():
            if pb.user_id != user_id:
                continue
            if (pb.service.casefold().strip() != service.casefold().strip()
                    or not version or pb.version_pattern != version):
                continue
            score = pb.success_rate
            if score > best_score:
                best_score = score
                best = pb
        return best

    # ── Persistence ──────────────────────────────────────────────────────
    @staticmethod
    def _safe_embedding(value):
        if value is None:
            return None
        values = value.tolist() if hasattr(value, "tolist") else value
        if not isinstance(values, list) or not 1 <= len(values) <= 4096:
            raise ValueError("Invalid embedding shape")
        if any(type(x) not in (float, int) or not math.isfinite(x) or abs(x) > 1_000_000 for x in values):
            raise ValueError("Invalid embedding value")
        return [float(x) for x in values]

    async def persist(self, redis_client=None):
        redis_client = redis_client if redis_client is not None else await _get_redis()
        if redis_client is None:
            return
        # Encrypted JSON v3 deliberately never reads the old executable pickle namespace.
        for session_id, entries in list(self._store.items()):
            for entry in list(entries):
                payload = {k: entry[k] for k in ('id', 'content', 'metadata', 'agent', 'type', 'ts')}
                payload.update(version=3, session_id=session_id,
                               embedding=self._safe_embedding(entry.get('embedding')))
                await redis_client.set(f"aria:vectors:v3:{session_id}:{entry['id']}",
                                       evidence_cipher().encrypt(json.dumps(payload, allow_nan=False).encode()), ex=86400 * 30)

    async def load(self, redis_client=None):
        redis_client = redis_client if redis_client is not None else await _get_redis()
        if redis_client is None:
            return
        cursor = 0
        while True:
            cursor, keys = await redis_client.scan(cursor=cursor, match='aria:vectors:v3:*', count=200)
            for key in keys:
                try:
                    key = key.decode() if isinstance(key, bytes) else key
                    raw = await redis_client.get(key)
                    if not raw or len(raw) > 262144:
                        continue
                    data = json.loads(evidence_cipher().decrypt(raw.encode() if isinstance(raw, str) else raw))
                    sid, eid = key.split(':')[3:]
                    if (data.get('version') != 3 or data.get('session_id') != sid or data.get('id') != eid
                            or not isinstance(data.get('content'), str) or not isinstance(data.get('metadata'), dict)):
                        continue
                    embedding = self._safe_embedding(data.get('embedding'))
                    if embedding is not None:
                        try:
                            import numpy as np
                            embedding = np.asarray(embedding, dtype='float32')
                        except ImportError:
                            embedding = None  # keyword retrieval remains available
                    stamp = float(data['ts'])
                    if not math.isfinite(stamp):
                        continue
                    if eid in self._by_id:
                        continue
                    entry = {k: data[k] for k in ('id', 'content', 'metadata', 'agent', 'type', 'ts')}
                    entry.update(embedding=embedding, keywords=self._extract_keywords(data['content']))
                    self._store[sid].append(entry)
                    self._by_id[eid] = (sid, entry)
                except (ValueError, KeyError, TypeError, UnicodeError, AttributeError, InvalidToken, OverflowError):
                    continue
            if cursor in (0, '0', b'0'):
                break

    # ── Helpers ──────────────────────────────────────────────────────────
    def _extract_keywords(self, text: str) -> set:
        text = text.lower()
        stop = {"the", "a", "an", "is", "are", "was", "were", "be", "been",
                "being", "have", "has", "had", "do", "does", "did", "will",
                "would", "could", "should", "may", "might", "can", "shall",
                "to", "of", "in", "for", "on", "with", "at", "by", "from",
                "as", "into", "through", "during", "before", "after", "above",
                "below", "between", "and", "or", "but", "not", "no", "nor",
                "so", "yet", "both", "either", "neither", "each", "every",
                "all", "any", "few", "more", "most", "other", "some", "such",
                "only", "own", "same", "than", "too", "very", "just", "about",
                "also", "this", "that", "these", "those", "it", "its", "them",
                "their", "there"}
        words = set(re.findall(r'[a-z0-9]+(?:[._-][a-z0-9]+)*', text))
        kws = {w for w in words if len(w) >= 2 and w not in stop}
        kws.update(re.findall(r'CVE-\d{4}-\d{4,7}', text, re.I))
        kws.update(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text))
        kws.update(re.findall(r'\b\d+/tcp\b', text))
        return kws


async def _get_redis():
    """Get a Redis client, or None."""
    try:
        import redis.asyncio as aioredis  # noqa: PLC0415
        from config.settings import settings  # noqa: PLC0415
        return aioredis.from_url(settings.REDIS_URL, decode_responses=False)
    except Exception:  # noqa: BLE001
        return None


# Singleton
vector_store = VectorStore()
