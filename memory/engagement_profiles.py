"""Operational authorization profiles: Private Lab, CTF, Authorized Pentest, Bug Bounty (P4).

A profile is an owner-declared, persisted authorization record. It is stored in
the engagement ``scope`` so every existing approval, which binds a digest of the
scope, is invalidated by any profile change. Enforcement happens only in
``memory.execution_authorization`` (the single path to the worker); this module
validates profiles and evaluates a proposed operation against one.

Authorization is never inferred from reachability: every asset is declared,
broad ranges are refused, and each profile requires its own documentation.
Profiles can restrict model sharing but never enable it beyond the
application-map data policy (the most restrictive setting wins).
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, time, timezone
from typing import Annotated, Any, ClassVar, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ProfileKind = Literal['private_lab', 'ctf', 'authorized_pentest', 'bug_bounty']
ApprovalLevel = Literal['red_only', 'sensitive', 'all']
_RANK = {'red_only': 0, 'sensitive': 1, 'all': 2}
_LEGACY_TOOLS = {'curl', 'nmap', 'aria-http', 'searchsploit'}
_HOST = re.compile(r'^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$')
_LAB_SUFFIXES = ('.test', '.lab', '.internal', '.invalid', '.localhost', '.example', '.local')
Text = Annotated[str, Field(min_length=1, max_length=4000)]
Statement = Annotated[str, Field(min_length=20, max_length=8000)]


def known_capabilities() -> set[str]:
    from security_tools.adapters import ADAPTERS
    return {a.capability for a in ADAPTERS.values()} | _LEGACY_TOOLS


def _asset(value: str) -> str:
    """Validate one declared asset: a host name, IP address or bounded CIDR."""
    value = value.strip().lower().rstrip('.')
    if not value or value in {'*', 'any', 'all'} or '*' in value:
        raise ValueError('Wildcard assets are not authorizations; declare each asset')
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        if not _HOST.match(value):
            raise ValueError(f'Invalid asset {value!r}') from None
        return value
    if network.prefixlen < (16 if network.version == 4 else 48):
        raise ValueError('Declared ranges must be /16 (IPv4) or /48 (IPv6) or narrower')
    return str(network) if network.num_addresses > 1 else str(network.network_address)


def _private_lab_asset(value: str) -> bool:
    try:
        network = ipaddress.ip_network(value, strict=False)
        return network.is_private or network.is_loopback or network.is_link_local
    except ValueError:
        return value == 'localhost' or value.endswith(_LAB_SUFFIXES)


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Window(Strict):
    """Weekly UTC execution window. Empty ``days`` means every day."""
    days: list[int] = Field(default_factory=list, max_length=7)
    start: str = Field(default='00:00', pattern=r'^\d{2}:\d{2}$')
    end: str = Field(default='23:59', pattern=r'^\d{2}:\d{2}$')

    @field_validator('days')
    @classmethod
    def weekdays(cls, value: list[int]) -> list[int]:
        if any(day < 0 or day > 6 for day in value) or len(set(value)) != len(value):
            raise ValueError('Days are distinct integers 0 (Monday) to 6 (Sunday)')
        return sorted(value)


class Limits(Strict):
    max_operations_per_hour: int = Field(default=60, ge=1, le=1000)
    max_timeout_seconds: int = Field(default=120, ge=1, le=300)


class ProfileBase(Strict):
    MINIMUM_APPROVAL: ClassVar[str] = 'red_only'
    REQUIRES_VALIDITY: ClassVar[tuple[str, ...]] = ()
    targets: list[str] = Field(min_length=1, max_length=64)
    ports: list[int] = Field(default_factory=list, max_length=64)
    exclusions: list[str] = Field(default_factory=list, max_length=64)
    permitted_capabilities: list[str] = Field(min_length=1, max_length=32)
    prohibited_capabilities: list[str] = Field(default_factory=list, max_length=32)
    approval: ApprovalLevel = 'sensitive'
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    schedule: list[Window] = Field(default_factory=list, max_length=7)
    limits: Limits = Field(default_factory=Limits)
    retention_days: int = Field(default=30, ge=1, le=365)
    model_sharing: Literal['deny', 'redacted_metadata'] = 'deny'

    @field_validator('targets', 'exclusions')
    @classmethod
    def declared_assets(cls, values: list[str]) -> list[str]:
        cleaned = [_asset(value) for value in values]
        if len(set(cleaned)) != len(cleaned):
            raise ValueError('Assets must be distinct')
        return cleaned

    @field_validator('ports')
    @classmethod
    def valid_ports(cls, values: list[int]) -> list[int]:
        if any(port < 1 or port > 65535 for port in values) or len(set(values)) != len(values):
            raise ValueError('Ports are distinct integers 1-65535')
        return sorted(values)

    @model_validator(mode='after')
    def coherent(self):
        known = known_capabilities()
        unknown = set(self.permitted_capabilities + self.prohibited_capabilities) - known
        if unknown:
            raise ValueError(f'Unknown capabilities: {sorted(unknown)}')
        if set(self.permitted_capabilities) & set(self.prohibited_capabilities):
            raise ValueError('A capability cannot be both permitted and prohibited')
        if set(self.targets) & set(self.exclusions):
            raise ValueError('An asset cannot be both a target and an exclusion')
        kind = getattr(self, 'kind', 'profile')
        if _RANK[self.approval] < _RANK[self.MINIMUM_APPROVAL]:
            raise ValueError(f'{kind} requires at least {self.MINIMUM_APPROVAL!r} approval')
        missing = [name for name in self.REQUIRES_VALIDITY if getattr(self, name) is None]
        if missing:
            raise ValueError(f'{kind} requires {", ".join(missing)}')
        for stamp in (self.valid_from, self.valid_until):
            if stamp is not None and stamp.tzinfo is None:
                raise ValueError('Validity timestamps must include a timezone')
        if self.valid_from and self.valid_until and self.valid_until <= self.valid_from:
            raise ValueError('valid_until must be after valid_from')
        return self


class Isolation(Strict):
    network_isolated: Literal[True]
    description: Text


class PrivateLabProfile(ProfileBase):
    kind: Literal['private_lab'] = 'private_lab'
    ownership_statement: Statement
    inventory: list[str] = Field(min_length=1, max_length=128)
    isolation: Isolation

    @field_validator('inventory')
    @classmethod
    def inventory_assets(cls, values: list[str]) -> list[str]:
        return [_asset(value) for value in values]

    @model_validator(mode='after')
    def lab_bounds(self):
        if set(self.targets) - set(self.inventory):
            raise ValueError('Every lab target must be in the declared lab inventory')
        public = [t for t in self.targets if not _private_lab_asset(t)]
        if public:
            raise ValueError(f'Private Lab targets must be private or lab-reserved assets: {public}')
        return self


class CTFProfile(ProfileBase):
    kind: Literal['ctf'] = 'ctf'
    challenge_name: Text
    challenge_scope: Statement
    rules_text: Statement
    rules_source: Text
    REQUIRES_VALIDITY: ClassVar[tuple[str, ...]] = ('valid_until',)


class AuthorizedPentestProfile(ProfileBase):
    kind: Literal['authorized_pentest'] = 'authorized_pentest'
    MINIMUM_APPROVAL: ClassVar[str] = 'sensitive'
    REQUIRES_VALIDITY: ClassVar[tuple[str, ...]] = ('valid_from', 'valid_until')
    authorization_reference: Text
    authorized_by: Text
    authorization_document_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    rules_of_engagement: Statement
    exclusions_reviewed: Literal[True]                # exclusions were explicitly reviewed (list may be empty)


class BugBountyProfile(ProfileBase):
    kind: Literal['bug_bounty'] = 'bug_bounty'
    MINIMUM_APPROVAL: ClassVar[str] = 'sensitive'
    program_snapshot_id: str = Field(min_length=1, max_length=100)
    testing_restrictions: Statement
    exclusions_reviewed: Literal[True]


Profile = Annotated[Union[PrivateLabProfile, CTFProfile, AuthorizedPentestProfile, BugBountyProfile],
                    Field(discriminator='kind')]


class ProfileUpdate(Strict):
    expected_revision: int = Field(ge=0)
    reason: Text
    profile: Profile


# ── Evaluation (pure; enforced by ExecutionAuthorization) ───────────────────

class ProfileDenied(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def stored_profile(scope: dict[str, Any]) -> dict[str, Any] | None:
    profile = scope.get('engagement_profile') if isinstance(scope, dict) else None
    return profile if isinstance(profile, dict) and profile.get('kind') else None


def capability_of(command: str, tool: str) -> str:
    if command.startswith('aria-tool '):
        from security_tools.adapters import decode
        return decode(command)[0].capability
    return tool


def within_schedule(profile: dict[str, Any], now: datetime) -> bool:
    windows = profile.get('schedule') or []
    if not windows:
        return True
    current = now.astimezone(timezone.utc)
    for window in windows:
        days = window.get('days') or list(range(7))
        start, end = (time.fromisoformat(window.get('start', '00:00')), time.fromisoformat(window.get('end', '23:59')))
        if current.weekday() in days and start <= current.time().replace(second=0, microsecond=0) <= end:
            return True
    return False


def check_operation(scope: dict[str, Any], command: str, tool: str, risk: str,
                    now: datetime | None = None) -> dict[str, Any] | None:
    """Raise ``ProfileDenied`` when the stored profile forbids this operation.

    Returns the profile (or None for an unprofiled legacy engagement).
    """
    profile = stored_profile(scope)
    if profile is None:
        if scope.get('profile_required'):
            raise ProfileDenied('profile_required', 'Configure an authorization profile before any execution')
        return None                     # legacy engagement created before profiles: unchanged scope rules
    now = now or datetime.now(timezone.utc)
    if profile.get('integrity') != 'valid':
        raise ProfileDenied('profile_invalid', 'The stored authorization profile failed validation')
    capability = capability_of(command, tool)
    if capability in profile.get('prohibited_capabilities', []):
        raise ProfileDenied('capability_prohibited', f'{capability} is prohibited by the {profile["kind"]} profile')
    if capability not in profile.get('permitted_capabilities', []):
        raise ProfileDenied('capability_not_permitted', f'{capability} is not permitted by the {profile["kind"]} profile')
    for key, test in (('valid_from', lambda stamp: now < stamp), ('valid_until', lambda stamp: now > stamp)):
        value = profile.get(key)
        if value and test(datetime.fromisoformat(value)):
            raise ProfileDenied('outside_validity', f'The {profile["kind"]} authorization is not valid now')
    if not within_schedule(profile, now):
        raise ProfileDenied('outside_schedule', 'Execution is outside the profile schedule')
    if profile['kind'] == 'bug_bounty':
        program = scope.get('program_policy') or {}
        if program.get('state') != 'active' or program.get('snapshot_id') != profile.get('program_snapshot_id'):
            raise ProfileDenied('program_policy_mismatch',
                                'Bug Bounty execution requires the active, reviewed program snapshot named by the profile')
    return profile


def requires_approval(profile: dict[str, Any] | None, risk: str) -> bool:
    if profile is None:
        return risk == 'red'
    level = profile.get('approval', 'sensitive')
    return level == 'all' or risk == 'red' or (level == 'sensitive' and risk == 'orange')


def apply_profile(scope: dict[str, Any], profile: BaseModel, revision: int, owner: str, reason: str,
                  provenance: dict[str, Any] | None = None) -> dict[str, Any]:
    """New scope with the profile stored and its assets made authoritative.

    Owner capability blocks and an active program policy are preserved.
    """
    data = profile.model_dump(mode='json')
    record = {**data, 'revision': revision, 'integrity': 'valid', 'changed_by': owner,
              'changed_at': datetime.now(timezone.utc).isoformat(), 'reason': reason}
    if provenance:
        record['rules_provenance'] = provenance
    updated = {key: scope[key] for key in ('blocked_typed_capabilities', 'program_policy') if key in scope}
    # Once profiled, an engagement can never return to legacy (unprofiled) rules.
    updated.update(targets=data['targets'], exclusions=data['exclusions'], engagement_profile=record,
                   profile_required=True)
    if data['ports']:
        updated['ports'] = data['ports']
    if data['kind'] == 'bug_bounty':
        updated['mode'] = 'bug_bounty'
    return updated


def describe(profile: dict[str, Any] | None, required: bool = False) -> dict[str, Any]:
    """Operator view of the restrictions the backend enforces for this profile."""
    if profile is None and required:
        return {'configured': False, 'state': 'profile_required', 'enforced': ['all execution denied'],
                'warning': 'No authorization profile: every operation is denied until the owner configures one.'}
    if profile is None:
        return {'configured': False, 'state': 'legacy', 'enforced': ['legacy engagement scope only'],
                'warning': ('Legacy engagement created before authorization profiles: execution uses its existing '
                            'scope. Configure a profile to migrate; migration cannot be undone.')}
    return {'configured': True, 'state': 'profiled', 'kind': profile['kind'], 'revision': profile['revision'],
            'enforced': {'targets': profile['targets'], 'ports': profile.get('ports') or 'any declared by worker ceiling',
                         'exclusions': profile.get('exclusions', []),
                         'permitted_capabilities': profile['permitted_capabilities'],
                         'prohibited_capabilities': profile.get('prohibited_capabilities', []),
                         'approval': profile['approval'], 'valid_from': profile.get('valid_from'),
                         'valid_until': profile.get('valid_until'), 'schedule': profile.get('schedule', []),
                         'max_operations_per_hour': profile['limits']['max_operations_per_hour'],
                         'max_timeout_seconds': profile['limits']['max_timeout_seconds'],
                         'model_sharing': profile['model_sharing'] + ' (most restrictive with the application data policy)'},
            'recorded': {'retention_days': profile['retention_days']},
            'not_enforced_here': ['retention_days is recorded for evidence handling; no automatic deletion runs']}


# ── Persistence (owner-only; never reachable from model output) ──────────────

class ProfileStore:
    async def view(self, sid: str, owner: str) -> dict[str, Any]:
        from sqlalchemy import select
        from memory.database_models import DecisionLog, async_session
        from memory.program_policy import owned_engagement
        async with async_session() as db:
            session = await owned_engagement(db, sid, owner, read_only=True)
            profile = stored_profile(session.scope or {})
            required = bool((session.scope or {}).get('profile_required'))
            rows = (await db.execute(select(DecisionLog).where(
                DecisionLog.session_id == sid,
                DecisionLog.decision_type.in_(['engagement_profile_change', 'policy_denied']))
                .order_by(DecisionLog.created_at.desc()).limit(100))).scalars().all()
        history, denied = [], []
        for row in rows:
            created = getattr(row, 'created_at', None)
            entry = {'id': row.id, 'at': created.isoformat() if isinstance(created, datetime) else None,
                     **(row.metadata_ or {})}
            (history if str(row.decision_type) == 'engagement_profile_change' else denied).append(entry)
        return {'session_id': sid, 'profile': profile, 'restrictions': describe(profile, required),
                'history': history[:50], 'denied_operations': denied[:50],
                'kinds': list(ProfileKind.__args__)}  # type: ignore[attr-defined]

    async def update(self, sid: str, owner: str, body: ProfileUpdate) -> dict[str, Any]:
        import hashlib
        import json
        from fastapi import HTTPException
        from sqlalchemy import select
        from memory.database_models import DecisionLog, WebAction, async_session
        from memory.program_policy import owned_engagement
        from memory.worker_jobs import TERMINAL
        async with async_session() as db:
            session = await owned_engagement(db, sid, owner)
            scope = dict(session.scope or {})
            current = stored_profile(scope)
            revision = int(current['revision']) if current else 0
            if body.expected_revision != revision:
                raise HTTPException(409, 'Profile changed; reload before editing')
            jobs = (await db.execute(select(DecisionLog.id).where(
                DecisionLog.session_id == sid, DecisionLog.decision_type == 'worker_job',
                DecisionLog.metadata_['state'].as_string().not_in(TERMINAL)))).scalars().all()
            web = (await db.execute(select(WebAction.id).where(WebAction.session_id == sid,
                WebAction.state.in_(['claimed', 'unknown', 'cancel_requested'])))).scalars().all()
            if jobs or web:
                raise HTTPException(409, 'Stop and reconcile active execution before changing the profile')
            profile = body.profile
            provenance = None
            if profile.kind == 'bug_bounty':
                program = scope.get('program_policy') or {}
                if program.get('state') != 'active' or program.get('snapshot_id') != profile.program_snapshot_id:
                    raise HTTPException(409, 'Bug Bounty requires the named program snapshot to be reviewed and active')
                hosts = {asset.get('host') for asset in (program.get('rules') or {}).get('assets', [])}
                if set(profile.targets) - hosts:
                    raise HTTPException(422, 'Bug Bounty targets must be assets of the active program policy')
                provenance = {key: program.get(key) for key in ('snapshot_id', 'review_id', 'content_sha256', 'activation_id')}
            digest = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()
            before = digest(scope)
            session.scope = apply_profile(scope, profile, revision + 1, owner, body.reason, provenance)
            session.attack_mode = 'bug_bounty' if profile.kind == 'bug_bounty' else 'lab'
            metadata = dict(session.metadata_ or {})
            # In-flight runs bound to the previous policy are invalidated (same as program activation).
            metadata['worker_epoch'] = int(metadata.get('worker_epoch', 0)) + 1
            session.metadata_ = metadata
            record = {'kind': profile.kind, 'previous_kind': current['kind'] if current else None,
                      'revision': revision + 1, 'reason': body.reason, 'scope_digest_before': before,
                      'scope_digest_after': digest(session.scope), 'actor': owner,
                      'approvals_invalidated': 'all approvals bound to the previous scope digest'}
            db.add(DecisionLog(session_id=sid, user_id=owner, decision_type='engagement_profile_change',
                               human_involved=True, human_decision='configure_profile', metadata_=record))
            await db.commit()
            return {'profile': session.scope['engagement_profile'], 'audit': record}


profile_store = ProfileStore()
