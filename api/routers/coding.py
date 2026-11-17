"""Authenticated artifact generation only; no code execution or deployment routes."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from agents.coding_agent import CodeArtifact, coding_agent
from api.auth import TokenData, get_current_user

router = APIRouter()


class CodingRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    objective: str = Field(min_length=1, max_length=4000)
    supplied_artifacts: list[CodeArtifact] = Field(default_factory=list, max_length=4)


@router.post('/{session_id}/proposals')
async def propose_artifacts(session_id: str, body: CodingRequest,
                            user: TokenData = Depends(get_current_user)):
    """BaseAgent rechecks session access and binds the existing model accounting."""
    return await coding_agent.process(session_id, user.user_id, {
        'objective': body.objective, 'user_input': body.objective,
        'supplied_artifacts': [f.model_dump() for f in body.supplied_artifacts]}, user.skill_level)
