"""Durable, owner-bound knowledge observations.

Observations are append-only ``DecisionLog`` rows with deterministic identifiers.
Only bounded structured facts and SHA-256 evidence hashes are stored; raw tool
output, commands, credentials and shells are deliberately excluded. Every
observation must match a terminal worker-job receipt before it can be persisted
or restored.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Optional

import structlog
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from memory.attack_knowledge_base import AttackKnowledgeBase, attack_kb
from memory.database_models import DecisionLog, PentestSession, async_session
from security.redaction import deployment_secrets, redact

log = structlog.get_logger("knowledge_store")

OBSERVATION_DECISION_TYPE = "knowledge_observation"
SCHEMA = "aria.knowledge.observation.v1"
MAX_HOSTS = 100
MAX_PORTS = 500
MAX_VULNS = 200
MAX_TEXT = 300
MAX_IP = 100
MAX_SERVICE = 100
MAX_VERSION = 200
MAX_TARGET = 500
MAX_JOB = 100
MAX_RUN = 100
MAX_TOOL = 50
MAX_OBSERVATION = 50
MAX_CVES = 20
MAX_CVE = 50
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,49}$")


class KnowledgeError(Exception):
    """Base class for durable-knowledge failures."""


class KnowledgeAccessError(KnowledgeError):
    """The session does not exist or is not owned by the requested principal."""


class KnowledgeIntegrityError(KnowledgeError):
    """Stored knowledge or its evidence is missing, malformed or inconsistent."""


class KnowledgePersistenceError(KnowledgeError):
    """The knowledge record could not be written durably."""


class KnowledgeConflict(Exception):
    """Internal backend signal: the deterministic observation ID already exists."""


@dataclass(frozen=True)
class SessionIdentity:
    session_id: str
    owner_id: str
    scope_digest: str


def canonical_digest(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def scope_identity_digest(scope, target) -> str:
    """Bind observations to the session's persisted scope and target."""
    try:
        canonical = json.dumps(
            {"scope": scope if isinstance(scope, dict) else {}, "target": str(target or "")},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        )
    except (TypeError, ValueError):
        raise KnowledgeIntegrityError("Engagement scope is not serializable") from None
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def observation_key(session_id: str, job_id: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"aria-knowledge-observation:{session_id}:{job_id}"))


def _sha256(value) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _safe_text(value, limit: int) -> str:
    if value is None or not isinstance(value, (str, int, float)):
        return ""
    text = redact(str(value), deployment_secrets())
    text = " ".join(text.split())
    return text[:limit]


def _write_name(value, limit: int, field: str) -> str:
    text = _safe_text(value, limit).lower()
    if not text or not SAFE_NAME.fullmatch(text):
        raise KnowledgePersistenceError(f"Invalid {field}")
    return text


def _write_text(value, limit: int, field: str, *, required: bool = False) -> str:
    text = _safe_text(value, limit)
    if required and not text:
        raise KnowledgePersistenceError(f"Invalid {field}")
    return text


def _validate_text(value, limit: int, field: str, *, required: bool = True) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise KnowledgeIntegrityError(f"Invalid stored {field}")
    if required and not value:
        raise KnowledgeIntegrityError(f"Invalid stored {field}")
    if value and value != " ".join(value.split()):
        raise KnowledgeIntegrityError(f"Invalid stored {field}")
    return value


def _validate_digest(value, field: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise KnowledgeIntegrityError(f"Invalid stored {field}")
    return value


def _normalize_payload(hosts_updated: Iterable, ports_added: Iterable, vulns_added: Iterable) -> dict:
    if not all(isinstance(item, (list, tuple)) for item in (hosts_updated, ports_added, vulns_added)):
        raise KnowledgePersistenceError("Parser facts must be lists")

    hosts: list[str] = []
    for raw in hosts_updated:
        ip = _safe_text(raw, MAX_IP)
        if ip and ip not in hosts:
            hosts.append(ip)
        if len(hosts) >= MAX_HOSTS:
            break

    ports: dict[tuple[str, int], dict] = {}
    for item in ports_added:
        if not isinstance(item, dict):
            continue
        ip = _safe_text(item.get("ip"), MAX_IP)
        port = item.get("port")
        if not ip or type(port) is not int or not 1 <= port <= 65535:
            continue
        ports[(ip, port)] = {
            "ip": ip,
            "port": port,
            "service": _safe_text(item.get("service"), MAX_SERVICE),
            "version": _safe_text(item.get("version"), MAX_VERSION),
        }
        if len(ports) >= MAX_PORTS:
            break

    vulns: list[dict] = []
    seen_vulns: set[tuple] = set()
    for item in vulns_added:
        if not isinstance(item, dict):
            continue
        ip = _safe_text(item.get("ip"), MAX_IP)
        title = _safe_text(item.get("title"), MAX_TEXT)
        if not ip or not title:
            continue
        port = item.get("port", 0)
        if type(port) is not int or not 0 <= port <= 65535:
            port = 0
        cves: list[str] = []
        raw_cves = item.get("cve_ids") or []
        if isinstance(raw_cves, (list, tuple)):
            for cve in raw_cves:
                cve = _safe_text(cve, MAX_CVE).upper()
                if cve and cve not in cves:
                    cves.append(cve)
        cves = cves[:MAX_CVES]
        severity = _safe_text(item.get("severity"), 20) or "info"
        cvss = item.get("cvss", 0.0)
        if type(cvss) not in (int, float) or not 0 <= cvss <= 10:
            cvss = 0.0
        key = (ip, title.lower(), port, tuple(sorted(cves)))
        if key in seen_vulns:
            continue
        seen_vulns.add(key)
        vulns.append({"ip": ip, "title": title, "severity": severity,
                      "cve_ids": cves, "port": port, "cvss": float(cvss)})
        if len(vulns) >= MAX_VULNS:
            break

    return {"hosts_updated": hosts, "ports_added": list(ports.values()), "vulns_added": vulns}


def _validate_payload(payload) -> dict:
    if not isinstance(payload, dict) or set(payload) != {"hosts_updated", "ports_added", "vulns_added"}:
        raise KnowledgeIntegrityError("Invalid stored observation payload")
    hosts = payload["hosts_updated"]
    ports = payload["ports_added"]
    vulns = payload["vulns_added"]
    if not isinstance(hosts, list) or len(hosts) > MAX_HOSTS:
        raise KnowledgeIntegrityError("Invalid stored host list")
    for host in hosts:
        _validate_text(host, MAX_IP, "host")
    if not isinstance(ports, list) or len(ports) > MAX_PORTS:
        raise KnowledgeIntegrityError("Invalid stored port list")
    for entry in ports:
        if not isinstance(entry, dict) or set(entry) != {"ip", "port", "service", "version"}:
            raise KnowledgeIntegrityError("Invalid stored port entry")
        _validate_text(entry["ip"], MAX_IP, "port ip")
        if type(entry["port"]) is not int or not 1 <= entry["port"] <= 65535:
            raise KnowledgeIntegrityError("Invalid stored port number")
        _validate_text(entry["service"], MAX_SERVICE, "service", required=False)
        _validate_text(entry["version"], MAX_VERSION, "version", required=False)
    if not isinstance(vulns, list) or len(vulns) > MAX_VULNS:
        raise KnowledgeIntegrityError("Invalid stored vulnerability list")
    for entry in vulns:
        if not isinstance(entry, dict) or set(entry) != {"ip", "title", "severity", "cve_ids", "port", "cvss"}:
            raise KnowledgeIntegrityError("Invalid stored vulnerability entry")
        _validate_text(entry["ip"], MAX_IP, "vulnerability ip")
        _validate_text(entry["title"], MAX_TEXT, "vulnerability title")
        _validate_text(entry["severity"], 20, "vulnerability severity")
        cves = entry["cve_ids"]
        if not isinstance(cves, list) or len(cves) > MAX_CVES:
            raise KnowledgeIntegrityError("Invalid stored CVE list")
        for cve in cves:
            _validate_text(cve, MAX_CVE, "CVE")
        if type(entry["port"]) is not int or not 0 <= entry["port"] <= 65535:
            raise KnowledgeIntegrityError("Invalid stored vulnerability port")
        if type(entry["cvss"]) not in (int, float) or not 0 <= entry["cvss"] <= 10:
            raise KnowledgeIntegrityError("Invalid stored CVSS value")
    return payload


def _validate_evidence(evidence) -> dict:
    if not isinstance(evidence, dict) or set(evidence) != {"job_id", "exit_code", "output_sha256", "stderr_sha256"}:
        raise KnowledgeIntegrityError("Evidence reference is missing or malformed")
    job_id = evidence["job_id"]
    if not isinstance(job_id, str) or not job_id or len(job_id) > MAX_JOB:
        raise KnowledgeIntegrityError("Evidence job reference is invalid")
    if type(evidence["exit_code"]) is not int:
        raise KnowledgeIntegrityError("Evidence exit code is invalid")
    _validate_digest(evidence["output_sha256"], "output hash")
    _validate_digest(evidence["stderr_sha256"], "stderr hash")
    return evidence


def _validate_receipt(evidence: dict, receipt) -> None:
    if not isinstance(receipt, dict):
        raise KnowledgeIntegrityError("Evidence references a missing worker receipt")
    if receipt.get("state") != "succeeded":
        raise KnowledgeIntegrityError("Evidence references a non-successful worker receipt")
    if receipt.get("exit_code") != evidence["exit_code"]:
        raise KnowledgeIntegrityError("Evidence exit code does not match the worker receipt")
    output_hash = receipt.get("output_hash")
    stderr_hash = receipt.get("stderr_hash")
    if not isinstance(output_hash, str) or not isinstance(stderr_hash, str):
        raise KnowledgeIntegrityError("Evidence hashes are missing from the worker receipt")
    if not hmac.compare_digest(output_hash, evidence["output_sha256"]):
        raise KnowledgeIntegrityError("Evidence output hash does not match the worker receipt")
    if not hmac.compare_digest(stderr_hash, evidence["stderr_sha256"]):
        raise KnowledgeIntegrityError("Evidence stderr hash does not match the worker receipt")


def _row_view(row) -> dict:
    return {
        "id": row.id,
        "session_id": row.session_id,
        "owner_id": row.user_id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "metadata": dict(row.metadata_) if isinstance(row.metadata_, dict) else row.metadata_,
    }


class SQLKnowledgeBackend:
    """Database access for durable knowledge observations."""

    def __init__(self, session_factory=None):
        self._session_factory = session_factory or async_session

    async def identity(self, session_id: str, owner_id: str) -> SessionIdentity:
        async with self._session_factory() as db:
            session = (await db.execute(select(PentestSession).where(
                PentestSession.id == session_id,
                PentestSession.user_id == owner_id,
            ))).scalar_one_or_none()
            if not session:
                raise KnowledgeAccessError("Engagement knowledge is unavailable")
            return SessionIdentity(session_id, owner_id,
                                   scope_identity_digest(session.scope, session.target))

    async def insert(self, *, row_id: str, session_id: str, owner_id: str, metadata: dict,
                     created_at: datetime, scope_digest: str) -> None:
        async with self._session_factory() as db:
            session = (await db.execute(select(PentestSession).where(
                PentestSession.id == session_id,
                PentestSession.user_id == owner_id,
            ).with_for_update())).scalar_one_or_none()
            if not session:
                raise KnowledgeAccessError("Engagement knowledge is unavailable")
            if not hmac.compare_digest(scope_identity_digest(session.scope, session.target), scope_digest):
                raise KnowledgeIntegrityError("Engagement scope changed before the observation was stored")
            db.add(DecisionLog(id=row_id, session_id=session_id, user_id=owner_id,
                               decision_type=OBSERVATION_DECISION_TYPE, metadata_=metadata,
                               created_at=created_at))
            try:
                await db.commit()
            except IntegrityError:
                await db.rollback()
                raise KnowledgeConflict() from None

    async def get(self, row_id: str, session_id: str, owner_id: str) -> Optional[dict]:
        async with self._session_factory() as db:
            row = (await db.execute(select(DecisionLog).where(
                DecisionLog.id == row_id,
                DecisionLog.session_id == session_id,
                DecisionLog.user_id == owner_id,
                DecisionLog.decision_type == OBSERVATION_DECISION_TYPE,
            ))).scalar_one_or_none()
            return _row_view(row) if row else None

    async def list(self, session_id: str, owner_id: str) -> list[dict]:
        async with self._session_factory() as db:
            rows = (await db.execute(select(DecisionLog).where(
                DecisionLog.session_id == session_id,
                DecisionLog.user_id == owner_id,
                DecisionLog.decision_type == OBSERVATION_DECISION_TYPE,
            ).order_by(DecisionLog.created_at, DecisionLog.id))).scalars().all()
            return [_row_view(row) for row in rows]

    async def receipts(self, session_id: str, job_ids: set[str]) -> dict[str, dict]:
        if not job_ids:
            return {}
        from memory.worker_jobs import SQLJobStore  # noqa: PLC0415
        keys = [SQLJobStore.key(job_id) for job_id in job_ids]
        async with self._session_factory() as db:
            rows = (await db.execute(select(DecisionLog).where(
                DecisionLog.session_id == session_id,
                DecisionLog.decision_type == "worker_job",
                DecisionLog.id.in_(keys),
            ))).scalars().all()
            return {row.metadata_["job_id"]: dict(row.metadata_)
                    for row in rows if isinstance(row.metadata_, dict) and row.metadata_.get("job_id") in job_ids}


class KnowledgeStore:
    def __init__(self, backend=None):
        self._backend = backend or SQLKnowledgeBackend()

    async def _require_receipt(self, session_id: str, evidence: dict) -> None:
        receipts = await self._backend.receipts(session_id, {evidence["job_id"]})
        _validate_receipt(evidence, receipts.get(evidence["job_id"]))

    def _validate_row(self, row: dict, identity: SessionIdentity) -> dict:
        if not isinstance(row, dict) or not isinstance(row.get("metadata"), dict):
            raise KnowledgeIntegrityError("Observation row is malformed")
        metadata = row["metadata"]
        if row.get("session_id") != identity.session_id or row.get("owner_id") != identity.owner_id:
            raise KnowledgeIntegrityError("Observation is bound to another engagement or owner")
        if metadata.get("schema") != SCHEMA:
            raise KnowledgeIntegrityError("Observation schema is unsupported")
        if metadata.get("session_id") != identity.session_id or metadata.get("owner_id") != identity.owner_id:
            raise KnowledgeIntegrityError("Observation metadata is bound to another engagement or owner")
        if not isinstance(metadata.get("scope_digest"), str) or not hmac.compare_digest(
                metadata["scope_digest"], identity.scope_digest):
            raise KnowledgeIntegrityError("Observation scope does not match the current engagement scope")

        obs_id = _validate_digest_text(metadata.get("observation_id"), 36, "observation id")
        if row.get("id") != obs_id:
            raise KnowledgeIntegrityError("Observation row identity is inconsistent")
        job_id = _validate_text(metadata.get("job_id"), MAX_JOB, "job id")
        if not observation_key(identity.session_id, job_id) == obs_id:
            raise KnowledgeIntegrityError("Observation identifier is not derived from its job reference")
        run_id = _validate_text(metadata.get("run_id"), MAX_RUN, "run id")
        tool = _validate_text(metadata.get("tool"), MAX_TOOL, "tool")
        observation = _validate_text(metadata.get("observation"), MAX_OBSERVATION, "observation type")
        target = _validate_text(metadata.get("target"), MAX_TARGET, "target", required=False)
        observed_at = metadata.get("observed_at")
        if not isinstance(observed_at, str):
            raise KnowledgeIntegrityError("Observation timestamp is missing")
        try:
            datetime.fromisoformat(observed_at)
        except ValueError:
            raise KnowledgeIntegrityError("Observation timestamp is invalid") from None
        if row.get("created_at"):
            try:
                datetime.fromisoformat(row["created_at"])
            except (TypeError, ValueError):
                raise KnowledgeIntegrityError("Observation row timestamp is invalid") from None

        payload = _validate_payload(metadata.get("payload"))
        evidence = _validate_evidence(metadata.get("evidence"))
        if evidence["job_id"] != job_id:
            raise KnowledgeIntegrityError("Evidence reference does not match the observation job")
        content = {
            "schema": SCHEMA,
            "session_id": identity.session_id,
            "owner_id": identity.owner_id,
            "run_id": run_id,
            "job_id": job_id,
            "tool": tool,
            "observation": observation,
            "target": target,
            "scope_digest": identity.scope_digest,
            "payload": payload,
            "evidence": evidence,
        }
        content_digest = canonical_digest(content)
        stored_digest = metadata.get("content_digest")
        if not isinstance(stored_digest, str) or not hmac.compare_digest(stored_digest, content_digest):
            raise KnowledgeIntegrityError("Observation content digest does not match its stored facts")
        return {
            "observation_id": obs_id,
            "session_id": identity.session_id,
            "owner_id": identity.owner_id,
            "run_id": run_id,
            "job_id": job_id,
            "tool": tool,
            "observation": observation,
            "target": target,
            "observed_at": observed_at,
            "payload": payload,
            "evidence": evidence,
            "content_digest": content_digest,
        }

    async def record_observation(self, *, session_id: str, owner_id: str, run_id: str,
                                 job_id: str, tool: str, observation: str, target: str,
                                 stdout: str, stderr: str, exit_code: int,
                                 hosts_updated=(), ports_added=(), vulns_added=()) -> dict:
        identity = await self._backend.identity(session_id, owner_id)
        job_id = _write_text(job_id, MAX_JOB, "job id", required=True)
        run_id = _write_text(run_id, MAX_RUN, "run id", required=True)
        tool = _write_name(tool, MAX_TOOL, "tool")
        observation = _write_name(observation or tool, MAX_OBSERVATION, "observation type")
        target = _write_text(target, MAX_TARGET, "target")
        if type(exit_code) is not int:
            raise KnowledgePersistenceError("Invalid evidence exit code")
        evidence = {
            "job_id": job_id,
            "exit_code": exit_code,
            "output_sha256": _sha256(stdout),
            "stderr_sha256": _sha256(stderr),
        }
        _validate_evidence(evidence)
        await self._require_receipt(session_id, evidence)
        payload = _normalize_payload(hosts_updated, ports_added, vulns_added)
        observed_at = datetime.utcnow().isoformat()
        content = {
            "schema": SCHEMA,
            "session_id": identity.session_id,
            "owner_id": identity.owner_id,
            "run_id": run_id,
            "job_id": job_id,
            "tool": tool,
            "observation": observation,
            "target": target,
            "scope_digest": identity.scope_digest,
            "payload": payload,
            "evidence": evidence,
        }
        content_digest = canonical_digest(content)
        obs_id = observation_key(identity.session_id, job_id)
        metadata = {
            **content,
            "observation_id": obs_id,
            "observed_at": observed_at,
            "content_digest": content_digest,
        }
        try:
            await self._backend.insert(
                row_id=obs_id, session_id=identity.session_id, owner_id=identity.owner_id,
                metadata=metadata, created_at=datetime.utcnow(), scope_digest=identity.scope_digest,
            )
        except KnowledgeConflict:
            existing = await self._backend.get(obs_id, identity.session_id, identity.owner_id)
            if existing is None:
                raise KnowledgePersistenceError("Observation write conflicted without a durable record") from None
            record = self._validate_row(existing, identity)
            await self._require_receipt(session_id, record["evidence"])
            if not hmac.compare_digest(record["content_digest"], content_digest):
                raise KnowledgeIntegrityError("Observation identifier is already bound to other evidence") from None
            return {**record, "duplicate": True}
        return {**metadata, "duplicate": False}

    async def restore(self, session_id: str, owner_id: str, *,
                      kb: Optional[AttackKnowledgeBase] = None) -> dict:
        identity = await self._backend.identity(session_id, owner_id)
        rows = await self._backend.list(session_id, owner_id)
        records = [self._validate_row(row, identity) for row in rows]
        records.sort(key=lambda item: (item["observed_at"], item["observation_id"]))
        seen: set[str] = set()
        for record in records:
            if record["observation_id"] in seen:
                raise KnowledgeIntegrityError("Duplicate stored observation identifier")
            seen.add(record["observation_id"])
        if records:
            receipts = await self._backend.receipts(session_id, {item["job_id"] for item in records})
            for record in records:
                _validate_receipt(record["evidence"], receipts.get(record["job_id"]))
        target_kb = kb or attack_kb
        try:
            applied = target_kb.restore_observations(session_id, records)
        except ValueError:
            raise KnowledgeIntegrityError("Knowledge base rejected a stored observation") from None
        log.info("knowledge observations restored", session=session_id,
                 observations=len(records), restored=applied["restored"],
                 skipped=applied["skipped"])
        return {
            "session_id": session_id,
            "observations": len(records),
            **applied,
            # Receipt index used by durable checkpoint validation.  Keys are
            # worker job IDs; values are the stored observation facts.
            "job_ids": sorted(record["job_id"] for record in records),
            "job_observations": {record["job_id"]: record["observation"]
                                 for record in records},
            "job_runs": {record["job_id"]: record["run_id"] for record in records},
        }


def _validate_digest_text(value, limit: int, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise KnowledgeIntegrityError(f"Invalid stored {field}")
    return value


knowledge_store = KnowledgeStore()
