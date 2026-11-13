"""Evidence-driven specialist investigations for durable campaigns.

SPEC-13 reuses the existing team ledger and team coordinator.  Specialist
tasks are selected from durable worker observations, saved application-map
captures and the current authorized scope.  Selection only proposes review
work: it never authorizes execution, and a specialist result is always an
unverified hypothesis until a human records reviewed coverage and independent
reproduction evidence.

Task identity is deterministic.  The same campaign, specialty and evidence
sources therefore map to the same ``TeamStore`` task across retries, crashes
and checkpoint restores.  A separate semantic identity (campaign, specialty
and question, without evidence sources) prevents a changed evidence set from
starting a second investigation while the first is still unresolved.  Once a
human resolves that review, changed evidence may create a legitimate follow-up.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Iterable

from fastapi import HTTPException

from config.settings import settings
from memory.team_tasks import (
    CreateTask,
    EvidenceInput,
    TaskBudget,
    TaskSpec,
    team_store,
)
from orchestrator.campaign_execution import CampaignExecutionDenied
from orchestrator.specialist_investigations import (
    TEMPLATES,
    InvestigationRequest,
    investigation_capabilities,
    plan_investigation,
)
from orchestrator.team_coordinator import team_coordinator

SPECIALTY_ORDER = {
    "exposure": 0,
    "authentication": 1,
    "authorization": 2,
    "input_validation": 3,
    "business_logic": 4,
}
ROLE_BY_SPECIALTY = {
    "authorization": "web_intel",
    "authentication": "web_intel",
    "exposure": "web_intel",
    "input_validation": "vuln",
    "business_logic": "correlation",
}
MAX_SOURCES = 5
MAX_CONTEXT_ITEMS = 20
MAX_TEXT = 500
# A task remains authoritative until a human or the coordinator resolves it.
UNRESOLVED_TASK_STATES = frozenset({
    "queued", "running", "awaiting_review", "blocked",
})


class SpecialistIntegrationError(Exception):
    """A durable specialist phase cannot proceed safely."""

    code = "specialist_integration_failed"

    def __init__(self, message: str = "", *, code: str | None = None):
        super().__init__(message or self.code)
        if code:
            self.code = code


class SpecialistBudgetExhausted(SpecialistIntegrationError):
    code = "specialist_budget_exhausted"


@dataclass(frozen=True)
class InvestigationCandidate:
    """A deterministic review candidate; sources are durable evidence inputs."""

    key: str
    identity: str
    specialty: str
    role: str
    hypothesis: str
    question: str
    # Each source is (store kind, durable source id): worker receipt or chat.
    sources: tuple[tuple[str, str], ...]
    dependencies: tuple[str, ...] = ()


def _digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()


def _clean(value, limit: int = MAX_TEXT) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return " ".join(value.replace("\x00", " ").split())[:limit]


def investigation_request_id(key: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL,
                      f"aria-specialist-investigation:{key}")


def investigation_task_id(session_id: str, key: str) -> str:
    request_id = investigation_request_id(key)
    return str(uuid.uuid5(uuid.NAMESPACE_URL,
                         f"aria-task:{session_id}:{request_id}"))


def _candidate(*, campaign_id: str, scope_digest: str, specialty: str,
               hypothesis: str, question: str,
               sources: Iterable[tuple[str, str]],
               dependencies: Iterable[str] = ()) -> InvestigationCandidate:
    ordered: list[tuple[str, str]] = []
    for kind, source_id in sources:
        item = (_clean(kind, 20), _clean(source_id, 100))
        if item[0] in {"worker", "chat"} and item[1] and item not in ordered:
            ordered.append(item)
        if len(ordered) >= MAX_SOURCES:
            break
    dependencies = tuple(sorted(set(dependencies)))
    campaign_id = _clean(campaign_id, 100)
    scope_digest = _clean(scope_digest, 64)
    question = _clean(question, 100)
    key = _digest({
        "schema": "aria.specialist.investigation.v1",
        "campaign_id": campaign_id,
        "scope_digest": scope_digest,
        "specialty": specialty,
        "question": question,
        "sources": [f"{kind}:{source_id}" for kind, source_id in ordered],
    })
    # Evidence-insensitive identity for duplicate suppression across a crash
    # whose evidence set changed.  It still distinguishes campaigns, scopes,
    # specialties and reviewed questions.
    identity = _digest({
        "schema": "aria.specialist.investigation-identity.v1",
        "campaign_id": campaign_id,
        "scope_digest": scope_digest,
        "specialty": specialty,
        "question": question,
    })
    return InvestigationCandidate(
        key=key, identity=identity, specialty=specialty,
        role=ROLE_BY_SPECIALTY[specialty],
        hypothesis=_clean(hypothesis, 2000), question=question,
        sources=tuple(ordered), dependencies=dependencies)


def _plan_allows(hypothesis: str, specialty: str, capabilities: dict) -> bool:
    try:
        plan = plan_investigation(
            InvestigationRequest(specialty=specialty, hypothesis=hypothesis),
            capabilities)
    except (ValueError, TypeError):
        return False
    return plan.get("status") == "requires_review"


def _healthy_captures(application: dict) -> dict[str, dict]:
    captures = application.get("captures") if isinstance(application, dict) else None
    if not isinstance(captures, dict):
        return {}
    return {capture_id: capture for capture_id, capture in captures.items()
            if isinstance(capture, dict) and not capture.get("expired")
            and isinstance(capture.get("evidence_id"), str)
            and capture.get("evidence_id")}


def _active_identities(application: dict) -> dict[str, dict]:
    identities = application.get("identities") if isinstance(application, dict) else None
    if not isinstance(identities, dict):
        return {}
    return {identity_id: identity for identity_id, identity in identities.items()
            if isinstance(identity, dict) and identity.get("active") is True
            and identity.get("researcher_controlled") is True}


def select_candidates(*, campaign_id: str, scope_digest: str, scope: dict,
                      advertised: dict, observation_job_ids: dict,
                      application: dict | None = None,
                      limit: int | None = None) -> list[InvestigationCandidate]:
    """Select a small, deterministic set of review-only investigations.

    Required capabilities come from ``investigation_capabilities`` and are
    exact: lab scope opt-ins plus integer worker protocol versions.  Saved
    evidence alone never grants authentication, input-profile or state-change
    capability.
    """
    campaign_id = _clean(campaign_id, 100)
    if not campaign_id:
        return []
    capabilities = investigation_capabilities(advertised or {}, scope or {})
    limit = min(limit or settings.SPECIALIST_MAX_INVESTIGATIONS,
                settings.SPECIALIST_MAX_INVESTIGATIONS)
    candidates: list[InvestigationCandidate] = []

    jobs = observation_job_ids if isinstance(observation_job_ids, dict) else {}
    http_jobs = sorted({_clean(job, 100)
                        for job in jobs.get("http_response", [])
                        if isinstance(job, str) and job})
    http_sources = [("worker", job) for job in http_jobs[:MAX_SOURCES]]

    def add(specialty: str, hypothesis: str, question: str,
            sources, dependencies=()):
        if not sources or not _plan_allows(hypothesis, specialty, capabilities):
            return None
        candidate = _candidate(
            campaign_id=campaign_id, scope_digest=scope_digest,
            specialty=specialty, hypothesis=hypothesis, question=question,
            sources=sources, dependencies=dependencies)
        if candidate.sources:
            candidates.append(candidate)
            return candidate
        return None

    exposure = None
    if http_sources:
        exposure = add(
            "exposure",
            "Saved HTTP response evidence may disclose content or metadata "
            "beyond its intended audience.",
            "exposure:http-response", http_sources)

    authentication = None
    if http_sources:
        authentication = add(
            "authentication",
            "Saved HTTP evidence may show protected content that is "
            "accessible without a valid controlled session.",
            "authentication:http-response", http_sources)

    if isinstance(application, dict):
        captures = _healthy_captures(application)
        identities = _active_identities(application)
        objects = application.get("objects")
        objects = objects if isinstance(objects, dict) else {}
        permissions = application.get("permissions")
        permissions = permissions if isinstance(permissions, dict) else {}

        authorized_objects: dict[str, list[str]] = {}
        if len(identities) >= 2:
            for permission in sorted(permissions.values(),
                                     key=lambda item: str(item.get("id", ""))):
                if not isinstance(permission, dict):
                    continue
                if permission.get("expected") not in {"allow", "deny"}:
                    continue
                obj = objects.get(permission.get("object_id"))
                if not isinstance(obj, dict):
                    continue
                owner_id = obj.get("owner_identity_id")
                other_id = permission.get("identity_id")
                if (owner_id not in identities or other_id not in identities
                        or owner_id == other_id):
                    continue
                evidence_ids = []
                for evidence_id in obj.get("evidence_ids") or []:
                    capture = next((item for item in captures.values()
                                    if item.get("evidence_id") == evidence_id), None)
                    if capture and evidence_id not in evidence_ids:
                        evidence_ids.append(evidence_id)
                if len(evidence_ids) >= 2:
                    authorized_objects[str(obj.get("id", ""))] = sorted(evidence_ids)

        for object_id, evidence_ids in sorted(authorized_objects.items()):
            if not object_id:
                continue
            add(
                "authorization",
                f"Recorded controlled object {object_id} may permit access "
                "contrary to the reviewed permission.",
                f"authorization:{object_id}",
                [("chat", evidence_id) for evidence_id in evidence_ids],
                (authentication.key,) if authentication else ())

        object_evidence: dict[str, list[str]] = {}
        for object_id, obj in sorted(objects.items()):
            if not isinstance(obj, dict):
                continue
            evidence_ids = []
            for evidence_id in obj.get("evidence_ids") or []:
                if any(capture.get("evidence_id") == evidence_id
                       for capture in captures.values()):
                    if evidence_id not in evidence_ids:
                        evidence_ids.append(evidence_id)
            if evidence_ids:
                object_evidence[str(obj.get("id", object_id))] = sorted(evidence_ids)
        for object_id, evidence_ids in sorted(object_evidence.items()):
            add(
                "input_validation",
                f"Recorded input handling for controlled object {object_id} "
                "may violate the documented boundary.",
                f"input_validation:{object_id}",
                [("chat", evidence_id) for evidence_id in evidence_ids],
                (exposure.key,) if exposure else ())

        workflows = application.get("workflows")
        workflows = workflows if isinstance(workflows, dict) else {}
        for workflow_id, workflow in sorted(workflows.items()):
            if not isinstance(workflow, dict):
                continue
            evidence_ids = []
            for evidence_id in workflow.get("evidence_ids") or []:
                if any(capture.get("evidence_id") == evidence_id
                       for capture in captures.values()):
                    if evidence_id not in evidence_ids:
                        evidence_ids.append(evidence_id)
            if not evidence_ids:
                continue
            add(
                "business_logic",
                f"Recorded workflow {workflow.get('id', workflow_id)} may "
                "violate its documented invariant.",
                f"business_logic:{workflow.get('id', workflow_id)}",
                [("chat", evidence_id) for evidence_id in evidence_ids],
                (authentication.key,) if authentication else ())

    unique = {candidate.key: candidate for candidate in candidates}
    ordered = sorted(unique.values(),
                     key=lambda item: (SPECIALTY_ORDER[item.specialty], item.key))
    return ordered[:limit]


def _task_spec(candidate: InvestigationCandidate,
               evidence_refs: list[str], dependencies: list[str]) -> TaskSpec:
    template = TEMPLATES[candidate.specialty]
    objective = (
        f"{candidate.hypothesis} Review only saved, cataloged evidence. "
        f"Minimum test concept (not an authorization): {template['minimum_test']} "
        f"Disconfirming evidence to consider: {template['disconfirming_evidence']}"
    )[:4000]
    return TaskSpec(
        owner_role=candidate.role,
        objective=objective,
        dependencies=dependencies,
        evidence_inputs=evidence_refs,
        budget=TaskBudget(max_attempts=1,
                          max_model_calls=settings.SPECIALIST_TASK_MODEL_CALLS,
                          max_tokens=settings.SPECIALIST_TASK_MAX_TOKENS),
        expected_output=("Evidence-linked observations and explicitly "
                         "unverified hypotheses for human review; no target "
                         "traffic and no verified finding."),
        completion_criteria=[
            "Every observation and hypothesis cites only this task's evidence inputs.",
            "No target request is dispatched by this investigation.",
            "Human review, tested coverage and independent reproduction remain required.",
        ],
        security_questions=[candidate.question],
        phase="vulnerability_analysis",
        specialty=candidate.specialty,
    )


def _http_error_code(error: HTTPException) -> str:
    detail = error.detail
    if isinstance(detail, dict):
        return _clean(detail.get("code"), 100) or f"http_{error.status_code}"
    return _clean(detail, 100) or f"http_{error.status_code}"


def _budget_failure(error: HTTPException) -> bool:
    if error.status_code != 429:
        return False
    text = json.dumps(error.detail, sort_keys=True) if isinstance(
        error.detail, (dict, list)) else str(error.detail)
    return "budget" in text.lower() or "exhaust" in text.lower()


class SpecialistIntegration:
    """Select, persist, execute and summarize campaign specialist reviews."""

    def __init__(self, store=None, coordinator=None, application_loader=None):
        self.store = store
        self.coordinator = coordinator
        self.application_loader = application_loader

    def _store(self):
        return self.store or team_store

    def _coordinator(self):
        return self.coordinator or team_coordinator

    async def application_view(self, session_id: str, owner_id: str) -> dict:
        if self.application_loader is not None:
            return await self.application_loader(session_id, owner_id)
        from memory.application_map import ApplicationMap  # noqa: PLC0415
        return await ApplicationMap().view(session_id, owner_id)

    async def candidates(self, *, session_id: str, owner_id: str,
                         campaign_id: str, scope_digest: str, scope: dict,
                         advertised: dict, observation_job_ids: dict) -> dict:
        """Return selected candidates plus bounded selection limitations."""
        capabilities = investigation_capabilities(advertised or {}, scope or {})
        application = None
        limitations: list[str] = []
        if any(capabilities.get(name) is True for name in (
                "authenticated_http", "reviewed_input_profile",
                "reviewed_state_change")):
            try:
                application = await self.application_view(session_id, owner_id)
            except Exception:  # noqa: BLE001 - no map means no mapped candidates.
                limitations.append(
                    "Application-map evidence was unavailable; mapped "
                    "specialties were not selected.")
        selected = select_candidates(
            campaign_id=campaign_id, scope_digest=scope_digest, scope=scope,
            advertised=advertised, observation_job_ids=observation_job_ids,
            application=application)
        return {"candidates": selected, "limitations": limitations}

    async def ensure(self, *, session_id: str, owner_id: str,
                     campaign_id: str, scope_digest: str,
                     candidates: list[InvestigationCandidate]) -> dict:
        """Create deterministic team tasks for candidates, never duplicates.

        The durable team ledger is the investigation store: task identity,
        status, dependencies, evidence inputs and collected outcomes all live
        in its immutable events.  A checkpoint only needs to carry the task
        ids so the planner can consume the same ledger after a restart.

        Exact evidence-derived task ids deduplicate identical inputs.  A
        semantic investigation identity additionally blocks a second task for
        the same campaign question while the first is unresolved, which covers
        a crash whose saved evidence changed.  New evidence remains available
        and creates a follow-up only after the prior review is resolved.
        """
        if not campaign_id:
            return {"task_ids": [], "created": 0, "duplicates": 0,
                    "deferred": [],
                    "limitations": ["No durable campaign bound this run."]}
        try:
            view = await self._store().view(session_id, owner_id)
        except Exception:  # noqa: BLE001
            raise SpecialistIntegrationError(
                "Specialist task ledger is unavailable") from None
        existing = {task.get("id"): task for task in view.get("tasks", [])
                    if isinstance(task, dict) and task.get("id")}
        by_identity: dict[str, list[dict]] = {}
        for task in sorted(existing.values(), key=lambda item: str(item.get("id"))):
            if (task.get("campaign_id") == campaign_id
                    and isinstance(task.get("investigation_key"), str)):
                by_identity.setdefault(task["investigation_key"], []).append(task)

        candidates = sorted(candidates, key=lambda item: (
            SPECIALTY_ORDER.get(item.specialty, 99), item.key))
        known = {candidate.key for candidate in candidates}
        task_ids: list[str] = []
        created = duplicates = 0
        limitations: list[str] = []
        deferred: list[dict] = []
        processed: dict[str, str | None] = {}

        while True:
            ready = [candidate for candidate in candidates
                     if candidate.key not in processed
                     and all(dep in known for dep in candidate.dependencies)
                     and all(processed.get(dep) for dep in candidate.dependencies)]
            if not ready:
                break
            for candidate in sorted(ready, key=lambda item: (
                    SPECIALTY_ORDER.get(item.specialty, 99), item.key)):
                task_id = investigation_task_id(session_id, candidate.key)
                if task_id in existing:
                    processed[candidate.key] = task_id
                    task_ids.append(task_id)
                    continue

                prior = [task for task in by_identity.get(candidate.identity, ())
                         if task.get("state") in UNRESOLVED_TASK_STATES]
                if prior:
                    prior_id = str(prior[0]["id"])
                    processed[candidate.key] = prior_id
                    task_ids.append(prior_id)
                    deferred.append({
                        "investigation_key": candidate.identity,
                        "task_id": prior_id,
                        "specialty": candidate.specialty,
                        "question": candidate.question,
                        "sources": [f"{kind}:{source_id}"
                                    for kind, source_id in candidate.sources],
                        "state": prior[0].get("state"),
                    })
                    continue

                evidence_refs: list[str] = []
                missing = False
                for kind, source_id in candidate.sources:
                    request_id = str(uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        f"aria-specialist-evidence:{session_id}:{kind}:{source_id}"))
                    try:
                        event = await self._store().catalog(
                            session_id, owner_id,
                            EvidenceInput(request_id=uuid.UUID(request_id),
                                          source_kind=kind, source_id=source_id))
                    except HTTPException as error:
                        if error.status_code in {404, 409, 410, 422}:
                            limitations.append(
                                f"Saved evidence {kind}:{source_id} could not be "
                                "cataloged; this investigation was not created.")
                            missing = True
                            break
                        raise SpecialistIntegrationError(
                            "Saved evidence catalog is unavailable") from None
                    except Exception:  # noqa: BLE001
                        raise SpecialistIntegrationError(
                            "Saved evidence catalog is unavailable") from None
                    evidence_id = (event.get("data") or {}).get("id")
                    if not isinstance(evidence_id, str) or not evidence_id:
                        raise SpecialistIntegrationError(
                            "Saved evidence catalog returned an invalid reference")
                    if evidence_id not in evidence_refs:
                        evidence_refs.append(evidence_id)
                if missing:
                    processed[candidate.key] = None
                    continue

                dependencies = [processed[dep] for dep in candidate.dependencies
                                if processed.get(dep)]
                creator = getattr(self._store(), "create_investigation", None)
                if creator is None:
                    raise SpecialistIntegrationError(
                        "Specialist task storage cannot bind a campaign identity")
                try:
                    spec = _task_spec(candidate, evidence_refs, dependencies)
                    event = await creator(
                        session_id, owner_id,
                        CreateTask(
                            request_id=investigation_request_id(candidate.key),
                            task=spec),
                        campaign_id=campaign_id,
                        investigation_key=candidate.identity)
                except HTTPException as error:
                    raise SpecialistIntegrationError(
                        "Specialist task could not be durably recorded "
                        f"({error.status_code})") from None
                except (ValueError, TypeError):
                    raise SpecialistIntegrationError(
                        "Specialist task contract is invalid") from None
                if event.get("entity_id") != task_id:
                    raise SpecialistIntegrationError(
                        "Specialist task identity is inconsistent")
                duplicates += int(bool(event.get("duplicate")))
                created += int(not event.get("duplicate"))
                processed[candidate.key] = task_id
                task_ids.append(task_id)

        if deferred:
            limitations.append(
                f"{len(deferred)} investigation(s) already have an unresolved "
                "review; new saved evidence was not attached to them and "
                "remains available for a later review.")
        unresolved = [candidate for candidate in candidates
                      if candidate.key not in processed]
        if unresolved:
            limitations.append(
                f"{len(unresolved)} investigation(s) were not created because "
                "a dependency was unavailable.")
        return {"task_ids": sorted(set(task_ids)), "created": created,
                "duplicates": duplicates, "deferred": deferred,
                "limitations": limitations}

    async def run_pending(self, *, session_id: str, owner_id: str,
                          task_ids: list[str], skill_level: str,
                          max_tasks: int, campaign_id: str = "",
                          campaign_supervisor_token: str = "",
                          scope_digest: str = "",
                          auth_revision: int | None = None,
                          worker_epoch: int | None = None) -> dict:
        """Run at most ``max_tasks`` queued, dependency-ready investigations.

        Campaign-bound tasks require an explicit campaign identity and live
        supervisor lease.  The coordinator revalidates that lease, the
        engagement authorization revision and the scope immediately before
        each specialist dispatch, so a lease takeover stops the batch at the
        next safe boundary rather than at the end of the run.
        """
        try:
            view = await self._store().view(session_id, owner_id)
        except Exception:  # noqa: BLE001
            raise SpecialistIntegrationError(
                "Specialist task ledger is unavailable") from None
        tasks = {task.get("id"): task for task in view.get("tasks", [])
                 if isinstance(task, dict) and task.get("id")}
        executed: list[str] = []
        skipped: list[dict] = []
        errors: list[dict] = []
        for task_id in task_ids:
            task = tasks.get(task_id)
            if task is None:
                raise SpecialistIntegrationError(
                    "Specialist task is missing from the durable ledger")
            state = task.get("state")
            if state in {"awaiting_review", "completed", "failed", "blocked",
                         "cancelled"}:
                continue
            if state == "running":
                # Restart reconciliation owns an interrupted run.  Never
                # reclaim it here and never start a second investigation.
                skipped.append({"task_id": task_id,
                                "reason": "interrupted_run_requires_review"})
                continue
            dependencies = task.get("dependencies") or []
            if any(tasks.get(dep, {}).get("state") != "completed"
                   for dep in dependencies):
                skipped.append({"task_id": task_id,
                                "reason": "dependencies_not_human_completed"})
                continue
            if len(executed) >= max(0, max_tasks):
                break
            # Fail closed before claiming a campaign task, even if a custom
            # coordinator is injected.  The real coordinator performs the full
            # durable lease and authorization check immediately before the
            # specialist call.
            campaign_bound = task.get("campaign_id")
            if campaign_bound and (
                    not isinstance(campaign_id, str) or not campaign_id
                    or campaign_id != campaign_bound
                    or not isinstance(campaign_supervisor_token, str)
                    or not campaign_supervisor_token):
                raise SpecialistIntegrationError(
                    "Campaign-bound specialist work requires its campaign "
                    "supervisor", code="campaign_supervisor_required")
            attempt = int(task.get("attempts", 0) or 0) + 1
            run_id = str(uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"aria-specialist-run:{task_id}:{attempt}"))
            run_kwargs = {}
            if campaign_id or campaign_supervisor_token:
                run_kwargs = {
                    "campaign_id": campaign_id,
                    "campaign_supervisor_token": campaign_supervisor_token,
                    "scope_digest": scope_digest,
                    "auth_revision": auth_revision,
                    "worker_epoch": worker_epoch,
                }
            try:
                event = await self._coordinator().run(
                    session_id, owner_id, task_id, run_id, skill_level,
                    **run_kwargs)
            except CampaignExecutionDenied as error:
                raise SpecialistIntegrationError(
                    "Campaign execution boundary is no longer valid",
                    code=error.code) from None
            except HTTPException as error:
                if _budget_failure(error):
                    raise SpecialistBudgetExhausted(
                        "Specialist model budget is exhausted") from None
                errors.append({"task_id": task_id,
                               "code": _http_error_code(error)})
                # A failed provider or worker path must not burn the remaining
                # task budget on further specialist calls.
                break
            if event.get("duplicate"):
                # A delivery retry returned the claim; the specialist was not
                # called a second time.
                skipped.append({"task_id": task_id,
                                "reason": "delivery_retry"})
                continue
            executed.append(task_id)
        return {"executed": executed, "skipped": skipped, "errors": errors,
                "task_ids": list(task_ids)}

    async def planner_context(self, *, session_id: str, owner_id: str,
                              task_ids: list[str],
                              verified_observations: list[dict]) -> dict:
        """Classify specialist outcomes for the planner without upgrading them."""
        try:
            view = await self._store().view(session_id, owner_id)
        except Exception:  # noqa: BLE001
            raise SpecialistIntegrationError(
                "Specialist task ledger is unavailable") from None
        tasks = {task.get("id"): task for task in view.get("tasks", [])
                 if isinstance(task, dict) and task.get("id")}

        confirmed = []
        for observation in (verified_observations or [])[:MAX_CONTEXT_ITEMS]:
            if not isinstance(observation, dict):
                continue
            job_id = _clean(observation.get("job_id"), 100)
            name = _clean(observation.get("observation"), 50)
            if not job_id or not name:
                continue
            confirmed.append({
                "observation": name, "job_id": job_id,
                "source": "durable_worker_receipt", "verified": True,
                "basis": "successful worker receipt recorded in the run checkpoint",
            })

        hypotheses: list[dict] = []
        observations: list[dict] = []
        failed: list[dict] = []
        pending: list[dict] = []
        for task_id in task_ids:
            task = tasks.get(task_id)
            if task is None:
                raise SpecialistIntegrationError(
                    "Specialist task ledger is incomplete")
            state = str(task.get("state") or "")
            result = task.get("result") if isinstance(task.get("result"), dict) else {}
            base = {
                "investigation_id": task_id,
                "specialty": task.get("specialty"),
                "status": state,
                "review_state": state,
                "verified": False,
                "evidence_references": [
                    _clean(ref, 100) for ref
                    in (result.get("evidence_references")
                        or task.get("evidence_inputs") or [])[:MAX_CONTEXT_ITEMS]
                    if isinstance(ref, str)],
            }
            if state in {"failed", "blocked"}:
                failed.append({**base,
                               "reason": _clean(task.get("reason"), MAX_TEXT)})
                continue
            if result:
                for hypothesis in (result.get("hypotheses") or [])[:MAX_CONTEXT_ITEMS]:
                    if not isinstance(hypothesis, dict):
                        continue
                    hypotheses.append({
                        **base,
                        "description": _clean(
                            hypothesis.get("description"), MAX_TEXT),
                        "verified": False,
                    })
                for observation in (result.get("observations") or [])[:MAX_CONTEXT_ITEMS]:
                    if not isinstance(observation, dict):
                        continue
                    observations.append({
                        **base,
                        "description": _clean(
                            observation.get("observation")
                            or observation.get("description"), MAX_TEXT),
                        "verified": False,
                    })
            if state in {"queued", "running", "awaiting_review"}:
                pending.append({**base,
                                "objective": _clean(task.get("objective"), MAX_TEXT)})

        return {
            "confirmed_evidence": confirmed,
            "unverified_observations": observations,
            "hypotheses": hypotheses,
            "failed_investigations": failed,
            "pending_investigations": pending,
            "limitations": [
                "Only durable worker receipts are confirmed evidence.",
                "Specialist observations and hypotheses are unverified and "
                "remain so until human review and independent reproduction.",
            ],
        }


specialist_integration = SpecialistIntegration()
