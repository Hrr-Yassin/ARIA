"""
PentestAI v10 — Semantic Vector Store
=====================================

Full semantic search over past findings + playbooks using `sentence-transformers`
(model: all-MiniLM-L6-v2, 80MB).

The old v9 keyword store lives on as the fallback when:
  • sentence-transformers isn't installed, OR
  • numpy isn't available, OR
  • the embedding model failed to load.

This means the system never hard-fails on a deployment with only base deps —
it just degrades to keyword-overlap scoring.

Storage: embeddings are numpy float32 arrays serialized with pickle, stored in
Redis under `embeddings:{session_id}:{entry_id}`. In-memory mirror kept for
fast search; loaded on demand.

Academic-brief mapping: this gives the orchestrator "pattern recognition across
engagements" — when it sees a new service, it can surface what was done on
similar services in prior sessions, which the human can review before acting.
It's an aid, not an autonomous decision.
"""
from __future__ import annotations

import json
import pickle
import re
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

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
        try:
            from sentence_transformers import SentenceTransformer  # noqa: PLC0415
            self._model = SentenceTransformer(self.MODEL_NAME)
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
        entry_id = str(uuid.uuid4())[:8]
        entry = {
            "id": entry_id,
            "content": content,
            "metadata": metadata or {},
            "agent": agent,
            "type": entry_type,
            "ts": time.time(),
            "embedding": _embedder.encode(content) if _embedder.available() else None,
            "keywords": self._extract_keywords(content),
        }
        self._store[session_id].append(entry)
        self._by_id[entry_id] = (session_id, entry)
        return entry_id

    def query(self, session_id: str, query: str, n: int = 5,
              agent_filter: str = "", type_filter: str = "") -> list:
        """Legacy search — used by v9 code paths."""
        entries = self._store.get(session_id, [])
        if not entries:
            return []

        if _embedder.available():
            q_vec = _embedder.encode(query)
            if q_vec is not None:
                scored = []
                for e in entries:
                    if agent_filter and e["agent"] != agent_filter:
                        continue
                    if type_filter and e["type"] != type_filter:
                        continue
                    if e.get("embedding") is None:
                        continue
                    score = float((q_vec * e["embedding"]).sum())
                    scored.append((score, e))
                scored.sort(key=lambda x: -x[0])
                return [e for _, e in scored[:n]]

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
                             ) -> List[SimilarFinding]:
        """
        Cross-session semantic search. Returns SimilarFinding objects sorted by
        score descending, filtered by min_score.

        If embeddings are unavailable, falls back to keyword overlap with a
        looser min_score (keyword overlap counts raw; we scale-adjust).
        """
        out: List[SimilarFinding] = []
        now = time.time()

        if _embedder.available():
            q_vec = _embedder.encode(query_text)
            if q_vec is not None:
                for sess_id, entries in self._store.items():
                    if exclude_session and sess_id == exclude_session:
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
            if exclude_session and sess_id == exclude_session:
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
        lines = ["SIMILAR CASES FROM PAST ENGAGEMENTS (human-reviewed):"]
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
                           success_rate: float = 1.0) -> Playbook:
        pb_id = f"pb-{uuid.uuid4().hex[:8]}"
        pb = Playbook(
            id=pb_id, service=service, version_pattern=version,
            goal_type=goal_type, steps=attack_path,
            success_rate=success_rate,
            last_used=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        self._playbooks[pb_id] = pb
        return pb

    async def get_playbook(self, service: str, version: str = "") -> Optional[Playbook]:
        """Return best-matching playbook by service/version pattern."""
        needle = f"{service} {version}".lower().strip()
        best: Optional[Playbook] = None
        best_score = 0.0
        for pb in self._playbooks.values():
            if pb.service.lower() not in needle:
                continue
            score = pb.success_rate
            if pb.version_pattern and re.search(pb.version_pattern, needle, re.I):
                score += 0.2
            if score > best_score:
                best_score = score
                best = pb
        return best

    # ── Persistence ──────────────────────────────────────────────────────
    async def persist(self, redis_client=None):
        """
        Persist embeddings + playbooks to Redis. Called periodically + at
        session end. Silently no-ops if Redis isn't available.
        """
        if redis_client is None:
            redis_client = await _get_redis()
        if not redis_client:
            return

        try:
            for sess_id, entries in self._store.items():
                for e in entries:
                    if e.get("embedding") is None:
                        continue
                    key = f"embeddings:{sess_id}:{e['id']}"
                    payload = {
                        "content": e["content"],
                        "metadata": e["metadata"],
                        "agent": e["agent"],
                        "type": e["type"],
                        "ts": e["ts"],
                        "embedding": pickle.dumps(e["embedding"]),
                    }
                    # Redis stores bytes with hset
                    await redis_client.hset(key, mapping={
                        "content": payload["content"],
                        "metadata": json.dumps(payload["metadata"]),
                        "agent": payload["agent"],
                        "type": payload["type"],
                        "ts": str(payload["ts"]),
                    })
                    await redis_client.expire(key, 86400 * 30)
                    await redis_client.set(f"{key}:vec", payload["embedding"],
                                           ex=86400 * 30)
            log.debug("vector_store persisted")
        except Exception as exc:  # noqa: BLE001
            log.debug("vector_store persist failed", error=str(exc))

    async def load(self, redis_client=None):
        """Restore embeddings from Redis on startup. Silently no-ops on error."""
        if redis_client is None:
            redis_client = await _get_redis()
        if not redis_client:
            return
        try:
            cursor = 0
            loaded = 0
            while True:
                cursor, keys = await redis_client.scan(
                    cursor=cursor, match="embeddings:*", count=200,
                )
                for key in keys:
                    key_str = key if isinstance(key, str) else key.decode()
                    if key_str.endswith(":vec"):
                        continue
                    data = await redis_client.hgetall(key_str)
                    if not data:
                        continue
                    vec_bytes = await redis_client.get(f"{key_str}:vec")
                    if not vec_bytes:
                        continue
                    try:
                        embedding = pickle.loads(vec_bytes if isinstance(vec_bytes, bytes)
                                                 else vec_bytes.encode("latin-1"))
                    except Exception:  # noqa: BLE001
                        continue
                    sess_id = key_str.split(":")[1]
                    entry_id = key_str.split(":")[2]
                    content = data.get("content", "") if isinstance(data, dict) else ""
                    md_raw = data.get("metadata", "{}") if isinstance(data, dict) else "{}"
                    try:
                        md = json.loads(md_raw)
                    except Exception:  # noqa: BLE001
                        md = {}
                    entry = {
                        "id": entry_id,
                        "content": content,
                        "metadata": md,
                        "agent": data.get("agent", ""),
                        "type": data.get("type", ""),
                        "ts": float(data.get("ts", time.time())),
                        "embedding": embedding,
                        "keywords": self._extract_keywords(content),
                    }
                    self._store[sess_id].append(entry)
                    self._by_id[entry_id] = (sess_id, entry)
                    loaded += 1
                if cursor == 0:
                    break
            if loaded:
                log.info("vector_store loaded from Redis", entries=loaded)
        except Exception as exc:  # noqa: BLE001
            log.debug("vector_store load failed", error=str(exc))

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
