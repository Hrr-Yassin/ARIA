"""Truthful read model for a bounded objective and its durable team work.

This projection grants no execution authority and advances no phases. Proposed
research is not a required operation. Unknown ledgers cannot prove completion.
The scope is the current authorized objective, never all future engagement work.
"""
from __future__ import annotations

from orchestrator.blockers import blocker_detail


TASK_STATES = {'queued', 'running', 'awaiting_review', 'blocked',
               'completed', 'cancelled', 'failed'}


def mission_status(run: dict, ledger: dict | None) -> dict:
    """Combine recorded run state and an owned task-ledger snapshot."""
    raw_state = run.get('run_state') or 'not_started'
    code = run.get('reason_code') or ''
    completion = run.get('completion')
    if not isinstance(completion, dict):
        completion = {}
    tasks = ledger.get('tasks') if isinstance(ledger, dict) else None
    available = (isinstance(tasks, list)
                 and all(isinstance(task, dict) and isinstance(task.get('id'), str)
                         and task['id'] and isinstance(task.get('state'), str)
                         and task['state'] in TASK_STATES for task in tasks))
    pending = ([{key: task.get(key) for key in ('id', 'state', 'owner_role')}
                for task in tasks if task['state'] in
                {'queued', 'running', 'awaiting_review', 'blocked'}] if available else None)
    failed = ([task['id'] for task in tasks if task['state'] == 'failed']
              if available else None)
    state, reason_code = raw_state, code
    reason = run.get('reason') or ''
    if raw_state == 'completed':
        if completion.get('complete') is not True:
            state, reason_code = 'blocked', 'completion_evidence_unavailable'
            reason = 'Run is labelled completed but completion evidence is unavailable or incomplete.'
        elif not available:
            state, reason_code = 'blocked', 'task_ledger_unavailable'
            reason = 'Bounded run completed; task ledger is unavailable, so mission completion is unproven.'
        elif pending:
            state, reason_code = 'work_pending', 'pending_team_work'
            reason = 'Bounded run completed; durable team work still requires processing or review.'
        elif failed:
            state, reason_code = 'failed', 'team_task_failed'
            reason = 'Bounded run completed; failed team tasks remain recorded for operator review.'
        else:
            state, reason_code = 'completed', 'bounded_objective_completed'
            reason = 'Bounded objective completed and the recorded task ledger has no pending or failed work.'
    elif code == 'cancelled':
        state = 'cancelled' if run.get('cancellation_confirmed') is True else 'cancellation_pending'
        reason = ('Cancellation confirmed; completed evidence was retained.' if state == 'cancelled'
                  else 'Cancellation requested; worker termination has not been confirmed in this checkpoint.')
    elif raw_state == 'cancelling':
        state, reason_code = 'cancellation_pending', code or 'cancellation_requested'
        reason = reason or 'Cancellation is in progress; termination is not yet confirmed.'
    elif (raw_state in {'blocked', 'restored'} and run.get('pause_requested')
          and not run.get('active') and code in {'', 'run_interrupted', 'restart_reconciliation'}):
        state, reason_code = 'paused', code or 'run_interrupted'
        reason = reason or 'Run paused; completed and pending work were retained.'
    elif raw_state == 'awaiting_approval':
        state, reason_code = 'waiting_for_approval', code or 'human_approval_required'
        reason = reason or 'An exact proposed operation is waiting for human approval.'
    elif code in {'step_budget_exhausted', 'model_call_budget', 'specialist_budget_exhausted',
                  'model_budget_exhausted', 'campaign_budget_exhausted', 'validation_budget_exhausted',
                  'task_model_budget_exhausted', 'worker_request_budget_exhausted'}:
        state = 'budget_exhausted'
    elif raw_state in {'planning', 'executing'}:
        state = 'running'
    elif raw_state == 'not_started' and pending:
        state, reason_code = 'work_pending', 'pending_team_work'
        reason = 'Durable team work is recorded; no bounded autonomous run has started.'
    hypotheses = ledger.get('research_hypotheses') if isinstance(ledger, dict) else None
    research_states = {'OBSERVED', 'HYPOTHESIZED', 'PLANNED', 'TESTED', 'CONFIRMED', 'REJECTED', 'INCONCLUSIVE'}
    valid_hypotheses = (isinstance(hypotheses, list) and all(isinstance(h, dict)
        and isinstance(h.get('state'), str) and h['state'] in research_states for h in hypotheses))
    evidence = ledger.get('evidence') if isinstance(ledger, dict) else None
    reviews = ledger.get('verification_findings') if isinstance(ledger, dict) else None
    return {
        'scope': 'current_authorized_objective',
        'objective': run.get('original_objective') or '',
        'state': state, 'reason_code': reason_code, 'reason': reason,
        'blocker': (blocker_detail(reason_code, state) if state in {
            'blocked', 'budget_exhausted', 'waiting_for_approval', 'failed',
            'cancellation_pending', 'paused'} else None),
        'bounded_run_state': raw_state,
        'current_phase': run.get('current_phase'),
        'observations_completed': completion.get('complete') is True,
        'missing_observations': completion.get('missing'),
        'pending_tasks': pending, 'failed_task_ids': failed,
        'completed_task_ids': ([task['id'] for task in tasks if task['state'] == 'completed']
                               if available else None),
        'cancelled_task_ids': ([task['id'] for task in tasks if task['state'] == 'cancelled']
                               if available else None),
        'task_ledger_available': available,
        'task_ledger_cursor': ledger.get('cursor') if available else None,
        'recorded_evidence_count': len(evidence) if isinstance(evidence, list) else None,
        'recorded_review_count': len(reviews) if isinstance(reviews, list) else None,
        'recorded_hypothesis_count': len(hypotheses) if valid_hypotheses else None,
        'hypothesis_state_counts': ({s: sum(h['state'] == s for h in hypotheses)
            for s in sorted(research_states)} if valid_hypotheses else None),
        'proposed_hypothesis_count': (sum(h['state'] in {'OBSERVED', 'HYPOTHESIZED', 'PLANNED', 'TESTED'}
            for h in hypotheses) if valid_hypotheses else None),
        'hypothesis_counts_basis': 'recorded_states_only; independent verification is not inferred',
        'proposals_require_execution': False,
    }
