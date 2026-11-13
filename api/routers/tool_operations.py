"""Typed proposals/execution, sharing the ordinary approval and cancellation APIs."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field
from api.auth import TokenData, get_current_user
from security_tools.models import ClosedModel, AdapterRequest
from security_tools.adapters import AdapterError
from security_tools.service import tool_operations

router = APIRouter()


class ProposalRequest(ClosedModel):
    session_id: str = Field(min_length=1, max_length=100)
    operation: AdapterRequest


class ExecuteRequest(ProposalRequest):
    action_id: str = Field(min_length=1, max_length=100)


@router.post('/tool-operations/proposals')
async def propose(body: ProposalRequest, user: TokenData = Depends(get_current_user)) -> dict:
    try:
        return await tool_operations.propose(user.user_id, body.session_id, body.operation.model_dump())
    except AdapterError:
        raise HTTPException(422, 'Invalid tool operation') from None


@router.post('/tool-operations/execute')
async def execute(body: ExecuteRequest, user: TokenData = Depends(get_current_user)) -> dict:
    try:
        return await tool_operations.execute(user.user_id, body.session_id, body.operation.model_dump(), body.action_id)
    except AdapterError:
        raise HTTPException(422, 'Invalid tool operation') from None
