"""Closed public diagnostics for denials; these projections grant no authority.

HTTP exception details may contain untrusted data. Only exact server-defined
codes/messages are classified. Unknown details are never echoed to the client.
"""
from __future__ import annotations

import re

from llm.planner_errors import MESSAGES


# code -> (component, explanation, operator action)
BLOCKERS = {
    'worker_constraints_invalid': ('worker', 'Worker policy metadata is invalid or unsupported.', 'Restore a supported constraint metadata contract; do not dispatch on an invalid compatibility claim.'),
    'worker_constraints_unavailable': ('worker', 'Independent worker policy limits are not advertised.', 'Worker admission remains pending. Ask the owner to review a metadata-only worker update; this grants no extra privileges.'),
    'worker_explicit_ports_required': ('worker', 'The proposal has no explicit numeric TCP port list for compatibility checking.', 'Replan within the already authorized scope and advertised worker limits.'),
    'worker_port_incompatible': ('worker', 'The proposed TCP ports exceed the worker policy ceiling.', 'Review the proposal against authorized scope and worker limits; do not broaden policy to satisfy a proposal.'),
    'worker_network_incompatible': ('worker', 'The proposed target exceeds the worker network ceiling.', 'Review the existing scope and worker limits; no network expansion is implied.'),
    'execution_fenced': ('authorization', 'Engagement execution is fenced.', 'Reconcile worker jobs and engagement state before explicitly resuming.'),
    'authorization_storage_unavailable': ('authorization', 'Authorization storage is unavailable.', 'Restore storage availability; no authorization was granted.'),
    'execution_policy_denied': ('authorization', 'The proposed operation is outside the engagement policy.', 'Review the proposal against the existing authorized scope; do not broaden scope to satisfy a proposal.'),
    'authorization_expired_or_invalid': ('authorization', 'Command authorization is absent, expired or invalid.', 'Review the exact proposal and obtain a new explicit approval if still authorized.'),
    'human_approval_required': ('authorization', 'The exact proposed operation requires human approval.', 'Review the pending command and approve or reject it in the workspace.'),
    'authorization_changed': ('authorization', 'Run credentials or execution authorization changed.', 'Review current authorization before explicitly resuming.'),
    'worker_epoch_changed': ('worker', 'The run was invalidated by cancellation.', 'Reconcile durable worker outcomes before considering new work.'),
    'authorization_mismatch': ('authorization', 'Authorization does not match this exact command.', 'Review a new command-bound proposal; existing approval cannot be reused.'),
    'authorization_consumed': ('authorization', 'This command authorization was already consumed.', 'Inspect its durable worker receipt; do not repeat an uncertain operation.'),
    'worker_unavailable': ('worker', 'The isolated worker is not configured or available.', 'Restore the existing authorized worker connection.'),
    'worker_capability_unavailable': ('worker', 'The worker does not advertise the required capability.', 'Review the proposal against advertised capabilities; no worker privilege change is implied.'),
    'worker_command_rejected': ('worker', 'The worker rejected the command under its independent policy.', 'Check supported flags and engagement IP/port constraints, then inspect the durable receipt before replanning.'),
    'worker_outcome_unreconciled': ('worker', 'Worker execution or cancellation has an unresolved outcome.', 'Reconcile durable job and cancellation status; do not automatically repeat it.'),
    'worker_request_budget_exhausted': ('worker', 'The engagement request budget is exhausted.', 'Review the existing request budget and recorded operations.'),
    'worker_concurrency_limit': ('worker', 'The engagement concurrency budget is exhausted.', 'Wait for existing jobs to finish and reconcile their outcomes.'),
    'worker_rate_limit': ('worker', 'An engagement rate limit or overload backoff is active.', 'Wait for the recorded backoff and inspect overload status.'),
    'operation_denied': ('authorization', 'The operation was denied by an authorization gate.', 'Review protected policy diagnostics; no automatic retry was requested.'),
    'operation_blocked': ('mission', 'A required operation could not be admitted or completed.', 'Review recorded prerequisites and protected diagnostics before explicitly resuming.'),
}
for _code, _message in MESSAGES.items():
    BLOCKERS[_code] = ('model', _message,
        'Review the recorded model configuration, authorization and accounting. Resume explicitly only after resolving this blocker.')


HTTP_MESSAGES = {
    'Engagement execution is fenced': 'execution_fenced',
    'Authorization storage unavailable': 'authorization_storage_unavailable',
    'Command is not permitted by engagement policy': 'execution_policy_denied',
    'Authorization is absent, expired or no longer valid': 'authorization_expired_or_invalid',
    'Explicit command-bound approval is required': 'human_approval_required',
    'Run credentials were revoked': 'authorization_changed',
    'Run was invalidated by cancellation': 'worker_epoch_changed',
    'Authorization does not match this command': 'authorization_mismatch',
    'Authorization already consumed': 'authorization_consumed',
    'Worker is not configured': 'worker_unavailable',
    'Worker capability information is unavailable': 'worker_capability_unavailable',
    'Worker typed adapter capability is unavailable': 'worker_capability_unavailable',
    'Worker authenticated HTTP capability is unavailable': 'worker_capability_unavailable',
    'Worker command capability cannot be determined': 'worker_capability_unavailable',
    'Worker does not advertise the requested tool': 'worker_capability_unavailable',
    'Worker must be upgraded for reviewed program policies': 'worker_capability_unavailable',
    'Worker rejected this command: check supported flags and engagement IP/port scope': 'worker_command_rejected',
    'Worker job failed; inspect durable job status': 'worker_outcome_unreconciled',
    'Job deadline exceeded; inspect cancellation status': 'worker_outcome_unreconciled',
    'Engagement has active or unresolved worker jobs': 'worker_outcome_unreconciled',
    'Worker cancellation is unresolved': 'worker_outcome_unreconciled',
    'Engagement request budget exhausted': 'worker_request_budget_exhausted',
    'Engagement concurrency budget exhausted': 'worker_concurrency_limit',
    'Engagement rate limit or overload backoff is active': 'worker_rate_limit',
    'Engagement stopped after overload; use a new engagement after review': 'worker_rate_limit',
}


def blocker_detail(code: str, state: str = 'blocked') -> dict:
    """Return safe metadata; unknown legacy codes retain only a bounded name."""
    if not isinstance(code, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,79}', code):
        code = 'operation_blocked'
    component, message, action = BLOCKERS.get(code, BLOCKERS['operation_blocked'])
    return {'reason_code': code, 'explanation': message, 'component': component,
            'operator_action': action, 'status': state}


def http_blocker(exc) -> dict:
    """Classify a failed gate without trusting its free-text detail."""
    detail = exc.detail
    code = detail.get('code') if isinstance(detail, dict) else None
    if not isinstance(code, str) or code not in BLOCKERS:
        code = HTTP_MESSAGES.get(detail) if isinstance(detail, str) else None
    if code is None:
        code = 'operation_denied' if exc.status_code in {401, 403} else 'operation_blocked'
    return blocker_detail(code)
