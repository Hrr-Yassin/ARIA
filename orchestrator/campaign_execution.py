"""Durable execution boundary for campaign-bound specialist tasks.

A task created by the autonomous campaign workflow carries the campaign id in
its immutable team-ledger event.  That binding is an execution restriction, not
just metadata: the task may only be dispatched by a process that currently owns
the campaign's durable supervisor lease, while the campaign is in a live model
state, and while the engagement's authorization revision and scope still match
the durable campaign contract.

The manual team API deliberately has no way to supply a supervisor lease token,
so it cannot execute a campaign-bound task.  The same guard is applied before
every specialist dispatch inside a run, which bounds a lease takeover or an
authorization change to the task already in flight instead of the whole batch.
"""
from __future__ import annotations

import hmac
from datetime import datetime, timezone

from fastapi import HTTPException

from memory.campaign_store import MODEL_STATES


class CampaignExecutionDenied(HTTPException):
    """A campaign-bound task cannot be dispatched in this context."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(
            409 if code == "campaign_supervisor_required" else 403,
            {"code": code, "message": message},
        )


def _deny(code: str, message: str):
    raise CampaignExecutionDenied(code, message)


def _utc_naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _same_int(actual, expected) -> bool:
    return type(actual) is int and type(expected) is int and actual == expected


async def require_campaign_execution(
        *, campaign_id: str, token: str, session_id: str, owner_id: str,
        scope_digest: str = "", auth_revision: int | None = None,
        worker_epoch: int | None = None, loader=None,
        context_loader=None) -> dict:
    """Fail closed unless this caller may dispatch a campaign-bound task.

    ``loader`` and ``context_loader`` exist so tests can use the real guard
    without a live database.  Production reads the durable campaign row and
    the authoritative engagement context.
    """
    if (not isinstance(campaign_id, str) or not campaign_id
            or len(campaign_id) > 100):
        _deny("campaign_supervisor_required",
              "Campaign execution requires a durable campaign identity")
    if (not isinstance(token, str) or not token or len(token) > 128
            or not token.isascii()):
        _deny("campaign_supervisor_required",
              "Campaign execution requires a live supervisor lease")

    if loader is None:
        from memory.campaign_store import campaign_store
        loader = campaign_store.get
    try:
        row = await loader(campaign_id)
    except Exception:  # noqa: BLE001 - an unreadable lease is not proof.
        _deny("campaign_supervisor_required",
              "Campaign supervisor state is unavailable")
    if not isinstance(row, dict):
        _deny("campaign_supervisor_required",
              "Campaign supervisor state is unavailable")
    if row.get("session_id") != session_id or row.get("owner_id") != owner_id:
        _deny("campaign_supervisor_required",
              "Campaign ownership does not match this engagement")
    if row.get("state") not in MODEL_STATES:
        _deny("campaign_supervisor_required",
              "Campaign is not in a model-executing state")

    holder = row.get("lease_holder")
    if (not isinstance(holder, str) or not holder.isascii()
            or not hmac.compare_digest(holder, token)):
        _deny("campaign_supervisor_required",
              "Campaign supervisor lease is not held by this caller")
    expires = row.get("lease_expires_at")
    if not isinstance(expires, datetime):
        _deny("campaign_supervisor_required",
              "Campaign supervisor lease expiry is unavailable")
    if _utc_naive(expires) <= datetime.now(timezone.utc).replace(tzinfo=None):
        _deny("campaign_supervisor_required",
              "Campaign supervisor lease has expired")

    if context_loader is None:
        from memory.execution_authorization import execution_authorization
        context_loader = execution_authorization._context
    try:
        context = await context_loader(owner_id, session_id)
    except HTTPException as exc:
        code = ("worker_blocked" if exc.status_code == 409
                else "authorization_expired" if exc.status_code == 403
                else "authorization_unavailable")
        _deny(code, "Engagement execution authorization is no longer valid")
    except Exception:  # noqa: BLE001
        _deny("authorization_unavailable",
              "Engagement execution authorization could not be verified")
    if not isinstance(context, dict):
        _deny("authorization_unavailable",
              "Engagement execution authorization could not be verified")
    if context.get("owner_id") != owner_id:
        _deny("authorization_expired",
              "Engagement ownership changed during the campaign")
    if context.get("worker_blocked"):
        _deny("worker_blocked",
              "Engagement execution is fenced by unresolved work")

    current_digest = context.get("scope_digest")
    if not isinstance(current_digest, str) or not current_digest:
        try:
            from memory.knowledge_store import scope_identity_digest
            current_digest = scope_identity_digest(
                context.get("scope") or {}, context.get("target", ""))
        except Exception:  # noqa: BLE001
            _deny("authorization_unavailable",
                  "Engagement scope could not be verified")
    row_digest = row.get("scope_digest")
    if (not isinstance(row_digest, str) or not row_digest
            or not hmac.compare_digest(row_digest, current_digest)):
        _deny("scope_changed",
              "Engagement scope changed during the campaign")
    if scope_digest:
        if (not isinstance(scope_digest, str)
                or not hmac.compare_digest(scope_digest, current_digest)):
            _deny("scope_changed",
                  "Run scope no longer matches the engagement")

    row_revision = row.get("auth_revision")
    context_revision = context.get("auth_revision")
    if not _same_int(row_revision, context_revision):
        _deny("authorization_changed",
              "Authorization revision changed during the campaign")
    if auth_revision is not None and not _same_int(auth_revision, context_revision):
        _deny("authorization_changed",
              "Run authorization revision is no longer current")

    row_epoch = row.get("worker_epoch")
    context_epoch = context.get("worker_epoch")
    if not _same_int(row_epoch, context_epoch):
        _deny("worker_epoch_changed",
              "Worker epoch changed during the campaign")
    if worker_epoch is not None and not _same_int(worker_epoch, context_epoch):
        _deny("worker_epoch_changed",
              "Run worker epoch is no longer current")
    return {"campaign": row, "context": context}
