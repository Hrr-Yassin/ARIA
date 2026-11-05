"""Owner-only durable tasks, evidence, coverage, events and model accounting."""
import uuid
from fastapi import APIRouter, Depends, Query
from api.auth import TokenData, get_current_user
from llm.engagement_budget import ModelLimits, model_accounting
from memory.team_tasks import (
    Strict, CreateTask, Transition, EvidenceInput, KnowledgeInput, CoverageInput, team_store,
)
from agents.coordinator_agent import coordinator_agent

router = APIRouter()


class RunRequest(Strict):
    request_id: uuid.UUID


@router.get('/{session_id}')
async def team_view(session_id: str, user: TokenData = Depends(get_current_user)):
    return await team_store.view(session_id, user.user_id)


@router.get('/{session_id}/events')
async def team_events(session_id: str, after: int = Query(default=0, ge=0), user: TokenData = Depends(get_current_user)):
    return await team_store.events(session_id, user.user_id, after)


@router.post('/{session_id}/tasks')
async def create_task(session_id: str, body: CreateTask, user: TokenData = Depends(get_current_user)):
    return await team_store.create(session_id, user.user_id, body)


@router.post('/{session_id}/tasks/{task_id}/transition')
async def transition_task(session_id: str, task_id: str, body: Transition, user: TokenData = Depends(get_current_user)):
    return await team_store.transition(session_id, user.user_id, task_id, body)


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
