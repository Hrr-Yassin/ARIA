"""Owner-only durable tasks, evidence, coverage, events and model accounting."""
import uuid
import asyncio
from fastapi import APIRouter, Depends, Query, Response
from pydantic import Field
from api.auth import TokenData, get_current_user
from llm.engagement_budget import ModelLimits, model_accounting
from memory.team_tasks import (
    Strict, Reference, CreateTask, MigrateTask, Transition, EvidenceInput, KnowledgeInput, CoverageInput, team_store,
)
from agents.coordinator_agent import coordinator_agent
from memory.finding_verification import Candidate, FindingHistory, Review, verification_store
from orchestrator.specialist_investigations import InvestigationRequest, plan_investigation
from orchestrator.team_coordinator import team_coordinator
from memory.research import ApplicationModel, CreateHypothesis, ResearchTransition, research_store
from orchestrator.collaboration import DelegationPlan

router = APIRouter()


@router.get('/{session_id}/research')
async def research_view(session_id: str, user: TokenData = Depends(get_current_user)):
    return await research_store.view(session_id, user.user_id)


@router.post('/{session_id}/research/hypotheses')
async def research_create(session_id: str, body: CreateHypothesis, user: TokenData = Depends(get_current_user)):
    return await research_store.create(session_id, user.user_id, body)


@router.post('/{session_id}/research/hypotheses/{hypothesis_id}/transition')
async def research_transition(session_id: str, hypothesis_id: str, body: ResearchTransition,
                              user: TokenData = Depends(get_current_user)):
    return await research_store.transition(session_id, user.user_id, hypothesis_id, body)


@router.put('/{session_id}/research/application-model')
async def research_application_model(session_id: str, body: ApplicationModel, user: TokenData = Depends(get_current_user)):
    return await research_store.save_model(session_id, user.user_id, body)


class RunRequest(Strict):
    request_id: uuid.UUID


class InternalRunRequest(Strict):
    task_ids: list[Reference] = Field(min_length=1, max_length=8)


@router.get('/{session_id}')
async def team_view(session_id: str, user: TokenData = Depends(get_current_user)):
    return await team_store.view(session_id, user.user_id)


@router.get('/{session_id}/events')
async def team_events(session_id: str, after: int = Query(default=0, ge=0), user: TokenData = Depends(get_current_user)):
    return await team_store.events(session_id, user.user_id, after)


@router.post('/{session_id}/tasks')
async def create_task(session_id: str, body: CreateTask, user: TokenData = Depends(get_current_user)):
    return await team_store.create(session_id, user.user_id, body)


@router.get('/{session_id}/tasks/{task_id}/completion-readiness')
async def task_completion_readiness(session_id: str, task_id: str, user: TokenData = Depends(get_current_user)):
    return await team_store.completion_readiness(session_id, user.user_id, task_id)


@router.get('/{session_id}/tasks/{task_id}/trace')
async def task_trace(session_id: str, task_id: str, response: Response,
                     user: TokenData = Depends(get_current_user)) -> dict:
    response.headers['Cache-Control'] = 'no-store'
    return await team_store.task_trace(session_id, user.user_id, task_id)


@router.post('/{session_id}/tasks/{task_id}/migrate')
async def migrate_task(session_id: str, task_id: str, body: MigrateTask, user: TokenData = Depends(get_current_user)):
    return await team_store.migrate_task(session_id, user.user_id, task_id, body)


@router.post('/{session_id}/tasks/{task_id}/transition')
async def transition_task(session_id: str, task_id: str, body: Transition, user: TokenData = Depends(get_current_user)):
    event = await team_store.transition(session_id, user.user_id, task_id, body)
    if not event.get('duplicate') and body.state == 'cancelled' and event['data'].get('internal_review'):
        team_coordinator.cancel_internal(session_id, user.user_id, task_id)
    return event


@router.post('/{session_id}/tasks/run-internal')
async def run_internal_tasks(session_id: str, body: InternalRunRequest,
                             user: TokenData = Depends(get_current_user)) -> dict:
    return await team_coordinator.run_internal(session_id, user.user_id, body.task_ids)


@router.post('/{session_id}/tasks/{task_id}/run')
async def run_task(session_id: str, task_id: str, body: RunRequest, user: TokenData = Depends(get_current_user)):
    return await coordinator_agent.delegate_task(session_id, user.user_id, task_id, str(body.request_id), user.skill_level)


@router.post('/{session_id}/evidence')
async def catalog_evidence(session_id: str, body: EvidenceInput, user: TokenData = Depends(get_current_user)):
    return await team_store.catalog(session_id, user.user_id, body)


@router.post('/{session_id}/knowledge')
async def save_knowledge(session_id: str, body: KnowledgeInput, user: TokenData = Depends(get_current_user)):
    return await team_store.knowledge(session_id, user.user_id, body)


@router.post('/{session_id}/coverage')
async def save_coverage(session_id: str, body: CoverageInput, user: TokenData = Depends(get_current_user)):
    return await team_store.coverage(session_id, user.user_id, body)


@router.get('/{session_id}/model-budget')
async def model_status(session_id: str, user: TokenData = Depends(get_current_user)):
    return await model_accounting.status(session_id, user.user_id)


@router.put('/{session_id}/model-budget')
async def configure_model_budget(session_id: str, body: ModelLimits, user: TokenData = Depends(get_current_user)):
    return await model_accounting.configure(session_id, user.user_id, body)


class ReconcileAttempt(Strict):
    attempt_id: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=2000)
    evidence: dict = Field(default_factory=dict)


@router.post('/{session_id}/model-budget/reconcile')
async def reconcile_model_attempt(session_id: str, body: ReconcileAttempt, user: TokenData = Depends(get_current_user)):
    """Owner settles an unknown-usage attempt at its full reservation; audited."""
    return await model_accounting.reconcile_unknown(session_id, user.user_id, body.attempt_id, body.reason, body.evidence)


@router.post('/{session_id}/model-tariff/refresh')
async def refresh_model_tariff(session_id: str, user: TokenData = Depends(get_current_user)):
    from config.settings import settings
    from llm.provider_tariffs import fetch_quote
    from memory.database_models import async_session, DecisionLog
    from memory.program_policy import owned_engagement
    # Check ownership before provider I/O; reacquire the row for persistence.
    async with async_session() as db:
        await owned_engagement(db, session_id, user.user_id)
        quote = await fetch_quote(db, user.user_id, settings.OPENROUTER_MODEL)
        session = await owned_engagement(db, session_id, user.user_id)
        metadata = dict(session.metadata_ or {})
        metadata['model_tariffs'] = {**metadata.get('model_tariffs', {}), quote['model']: quote}
        session.metadata_ = metadata
        db.add(DecisionLog(session_id=session_id, user_id=user.user_id,
                           decision_type='model_tariff', human_involved=False, metadata_=quote))
        await db.commit()
        return quote


@router.post('/{session_id}/investigation-plan')
async def investigation_plan(session_id: str, body: InvestigationRequest, user: TokenData = Depends(get_current_user)):
    # Ownership is checked before contacting the worker or returning a plan.
    engagement = await team_store.view(session_id, user.user_id)
    from config.settings import settings
    from memory.worker_jobs import worker_jobs
    advertised = {}
    if settings.KALI_AGENT_URL:
        try:
            async with asyncio.timeout(3):
                advertised = await worker_jobs.client.capabilities()
            if not isinstance(advertised, dict):
                advertised = {}
        except Exception:
            advertised = {}
    if settings.KALI_WORKER_PROTOCOL != 'jobs-v1':
        advertised = {}
    from orchestrator.specialist_investigations import investigation_capabilities
    return plan_investigation(body, investigation_capabilities(advertised, engagement.get('scope', {})))


# Explicit human review endpoints; specialist collection never advances findings.
@router.get('/{session_id}/findings')
async def verification_findings(session_id: str, user: TokenData = Depends(get_current_user)):
    return await verification_store.view(session_id, user.user_id)


@router.get('/{session_id}/findings/{finding_id}/history')
async def verification_history(session_id: str, finding_id: str, response: Response,
                               before_sequence: int | None = Query(None, ge=1, le=2_147_483_647),
                               limit: int = Query(20, ge=1, le=50),
                               user: TokenData = Depends(get_current_user)) -> FindingHistory:
    response.headers['Cache-Control'] = 'no-store'
    return await verification_store.history(session_id, user.user_id, finding_id, before_sequence, limit)


@router.post('/{session_id}/findings')
async def create_verification_finding(session_id: str, body: Candidate, user: TokenData = Depends(get_current_user)):
    return await verification_store.create(session_id, user.user_id, body)


@router.post('/{session_id}/findings/{finding_id}/review')
async def review_verification_finding(session_id: str, finding_id: str, body: Review, user: TokenData = Depends(get_current_user)):
    return await verification_store.review(session_id, user.user_id, finding_id, body)


@router.post('/{session_id}/collaboration-plans')
async def collaboration_plan_create(session_id: str, body: DelegationPlan,
                                    user: TokenData = Depends(get_current_user)):
    from orchestrator.collaboration import collaboration
    return await collaboration.create_plan(session_id, user.user_id, body)


@router.post('/{session_id}/collaboration-plans/{plan_id}/advance')
async def collaboration_plan_advance(session_id: str, plan_id: str, user: TokenData = Depends(get_current_user)):
    """Interpret, supervise, replan and dispatch ready analysis tasks; never dispatches tools."""
    from orchestrator.collaboration import collaboration
    return await collaboration.advance(session_id, user.user_id, plan_id, skill=user.skill_level)
