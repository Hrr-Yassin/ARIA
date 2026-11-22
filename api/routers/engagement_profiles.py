"""Owner-only operational authorization profiles (P4).

Profiles are configured only by an authenticated owner. Model output, chat
intents and agents have no route here; every change is audited and invalidates
approvals bound to the previous scope digest.
"""
from fastapi import APIRouter, Depends

from api.auth import TokenData, get_current_user
from memory.engagement_profiles import (AuthorizedPentestProfile, BugBountyProfile, CTFProfile,
                                        PrivateLabProfile, ProfileUpdate, profile_store)

router = APIRouter()
_KINDS = {'private_lab': PrivateLabProfile, 'ctf': CTFProfile,
          'authorized_pentest': AuthorizedPentestProfile, 'bug_bounty': BugBountyProfile}


@router.get('/profile-kinds')
async def profile_kinds(user: TokenData = Depends(get_current_user)) -> dict:
    """Requirements per profile, taken from the same models the backend enforces."""
    from memory.engagement_profiles import known_capabilities
    return {'kinds': {kind: {'required': model.model_json_schema().get('required', []),
                             'schema': model.model_json_schema()} for kind, model in _KINDS.items()},
            'capabilities': sorted(known_capabilities())}


@router.get('/{session_id}/profile')
async def get_profile(session_id: str, user: TokenData = Depends(get_current_user)) -> dict:
    return await profile_store.view(session_id, user.user_id)


@router.put('/{session_id}/profile')
@router.post('/{session_id}/profile')
async def put_profile(session_id: str, body: ProfileUpdate, user: TokenData = Depends(get_current_user)) -> dict:
    return await profile_store.update(session_id, user.user_id, body)
