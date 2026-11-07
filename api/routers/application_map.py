"""Human-reviewed application map; no browser, replay or model dispatch."""
from fastapi import APIRouter, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from starlette.responses import JSONResponse
from api.auth import TokenData, get_current_user
from memory.application_map import (
    application_map, Strict, Change, IdentityInput, RequestInput, CaptureInput, ObjectInput,
    WorkflowInput, PermissionInput, DataPolicy, ComparisonInput, AuthorizationReview, AuthenticationReview, ExposureReview, BusinessLogicReview, InputValidationReview,
)

class PrivateRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()
        async def private_handler(request):
            try:
                return await handler(request)
            except RequestValidationError:
                # Pydantic errors include raw input, including write-only secrets.
                return JSONResponse({'detail': 'Invalid application mapping request'}, status_code=422)
        return private_handler


router = APIRouter(route_class=PrivateRoute)


@router.get('/{session_id}')
async def view(session_id: str, user: TokenData = Depends(get_current_user)):
    return await application_map.view(session_id, user.user_id)


@router.post('/{session_id}/identities')
async def identity(session_id: str, body: IdentityInput, user: TokenData = Depends(get_current_user)):
    return await application_map.change(session_id, user.user_id, 'identities', body)


@router.post('/{session_id}/identities/{identity_id}/revoke')
async def revoke(session_id: str, identity_id: str, body: Change, user: TokenData = Depends(get_current_user)):
    return await application_map.revoke(session_id, user.user_id, identity_id, body)


@router.post('/{session_id}/captures')
async def capture(session_id: str, body: CaptureInput, user: TokenData = Depends(get_current_user)):
    return await application_map.change(session_id, user.user_id, 'captures', body)


@router.post('/{session_id}/objects')
async def object_record(session_id: str, body: ObjectInput, user: TokenData = Depends(get_current_user)):
    return await application_map.change(session_id, user.user_id, 'objects', body)


@router.post('/{session_id}/workflows')
async def workflow(session_id: str, body: WorkflowInput, user: TokenData = Depends(get_current_user)):
    return await application_map.change(session_id, user.user_id, 'workflows', body)


@router.post('/{session_id}/permissions')
async def permission(session_id: str, body: PermissionInput, user: TokenData = Depends(get_current_user)):
    return await application_map.change(session_id, user.user_id, 'permissions', body)


@router.put('/{session_id}/data-policy')
async def data_policy(session_id: str, body: DataPolicy, user: TokenData = Depends(get_current_user)):
    return await application_map.change(session_id, user.user_id, 'policy', body)


@router.post('/{session_id}/authorization-review')
async def authorization_review(session_id: str, body: AuthorizationReview, user: TokenData = Depends(get_current_user)):
    return await application_map.review_authorization(session_id, user.user_id, body)


@router.post('/{session_id}/authentication-review')
async def authentication_review(session_id: str, body: AuthenticationReview, user: TokenData = Depends(get_current_user)):
    return await application_map.review_authentication(session_id, user.user_id, body)


@router.post('/{session_id}/exposure-review')
async def exposure_review(session_id: str, body: ExposureReview, user: TokenData = Depends(get_current_user)):
    return await application_map.review_exposure(session_id, user.user_id, body)


@router.post('/{session_id}/business-logic-review')
async def business_logic_review(session_id: str, body: BusinessLogicReview, user: TokenData = Depends(get_current_user)):
    return await application_map.review_business_logic(session_id, user.user_id, body)


@router.post('/{session_id}/compare')
async def compare(session_id: str, body: ComparisonInput, user: TokenData = Depends(get_current_user)):
    return await application_map.compare(session_id, user.user_id, body)


@router.post('/{session_id}/identities/{identity_id}/requests/{capture_id}/replay-proposal')
@router.post('/{session_id}/identities/{identity_id}/captures/{capture_id}/replay-proposal')
async def replay_proposal(session_id: str, identity_id: str, capture_id: str,
                          user: TokenData = Depends(get_current_user)):
    return await application_map.replay_proposal(session_id, user.user_id, identity_id, capture_id)


@router.get('/{session_id}/replays/{job_id}/comparison')
async def replay_comparison(session_id: str, job_id: str, user: TokenData = Depends(get_current_user)):
    return await application_map.replay_comparison(session_id, user.user_id, job_id)


class BrowserPreview(Strict):
    identity_id: str
    action_id: str


@router.post('/{session_id}/browser-preview')
async def browser_preview(session_id: str, body: BrowserPreview, user: TokenData = Depends(get_current_user)):
    from orchestrator.browser_mapping import browser_mapping
    from starlette.responses import Response
    image = await browser_mapping.preview(user.user_id, session_id, body.identity_id, body.action_id)
    return Response(image, media_type='image/png', headers={'Cache-Control': 'no-store'})


@router.post('/{session_id}/replays/{job_id}/catalog')
async def catalog_replay(session_id: str, job_id: str, user: TokenData = Depends(get_current_user)):
    return await application_map.catalog_replay(session_id, user.user_id, job_id)


@router.post('/{session_id}/requests')
async def planned_request(session_id: str, body: RequestInput, user: TokenData = Depends(get_current_user)):
    return await application_map.change(session_id, user.user_id, 'requests', body)


@router.post('/{session_id}/input-validation-review')
async def input_validation_review(session_id: str, body: InputValidationReview, user: TokenData = Depends(get_current_user)):
    return await application_map.review_input_validation(session_id, user.user_id, body)
