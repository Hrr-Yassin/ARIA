"""Build a current evidence checkpoint, never infer that the mission is complete.

Reads explicit retained runs, the persistent plan and source hashes. Generates
the requested HTML/JSON/CSV artifacts without provider, worker or network I/O.
Private fixture screenshots are embedded; credentials/raw source evidence are
excluded. Rerun after updating PROGRESS/PLANS and validated evidence selectors.
"""
from __future__ import annotations

import base64
import csv
from datetime import datetime, timezone
import hashlib
from html import escape
import json
import math
from pathlib import Path
import re
import statistics
import subprocess

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / '.local-lab/operational-reliability'
REGRESSION_RUN = 'resume-cycle11'
WORKER_VALIDATION = 'resume-cycle12'
CURRENT_VALIDATION = 'resume-cycle13'
FINAL_VALIDATION = 'resume-cycle14'
AUDIT_VALIDATION = 'resume-cycle15'
CLOCK_VALIDATION = 'resume-cycle16'
METADATA_VALIDATION = 'resume-cycle17'
DEFERRAL_VALIDATION = 'resume-cycle21'
INTELLIGENCE_VALIDATION = 'intelligence-v2'
DISCOVERY_VALIDATION = 'resume-cycle26'
SQL_RUN = 'sql-1906edcfae25'
VISIBLE_RUN = 'visible-e849d95f692e'
STREAM_RUN = 'visible-9e33a7a3c5ec'
LAB_RUN = 'lab-visible-1155d31fc4b2'
LAB_OBSERVATION = 'resume-cycle14/lab-readonly/durable-evidence.json'
ENDURANCE_RUNS = ['endurance-3d8e73d8ef16', 'endurance-d31a0e3f21b1', 'endurance-d1aef3ed96de', 'endurance-7acf4dc15d40']
ACTIVE_ENDURANCE = 'endurance-5080b70117b7'
INTERRUPTED_ENDURANCE = 'endurance-eeba127dc839'
REFERENCES = {
 'P00-01': ('docs/operational-reliability-baseline.md', 'integration/phase0_baseline.py'),
 'P00-02': ('docs/operational-reliability-baseline.md', 'tests/test_autonomous_intelligence.py'),
 'P00-03': ('docs/operational-reliability-baseline.md', 'tests/test_p1_agent_boundaries.py'),
 'P01-01': ('agents/autonomous_engine.py api/routers/pentest.py web/static/scripts/app.js', 'tests/test_access.py tests/test_context_integrity.py tests/test_checkpoints.py tests/frontend_contracts.cjs'),
 'P01-02': ('orchestrator/mission_status.py agents/autonomous_engine.py', 'tests/test_mission_status.py tests/test_mission_continuity.py integration/test_mission_state_postgres.py'),
 'P01-03': ('memory/autonomous_runs.py agents/autonomous_engine.py web/static/scripts/app.js', 'tests/test_checkpoint_fencing.py integration/test_checkpoint_postgres.py tests/frontend_contracts.cjs'),
 'P02-01': ('agents/base_agent.py agents/orchestrator_agent.py llm/local_client.py', 'tests/test_model_response_failures.py tests/test_autonomous_intelligence.py tests/test_local_model_reliability.py'),
 'P02-02': ('memory/investigation_reviews.py orchestrator/blockers.py agents/autonomous_engine.py', 'integration/test_review_recovery_postgres.py tests/test_mission_continuity.py tests/test_engagement_budget.py'),
 'P02-03': ('llm/request_metrics.py llm/pool_manager.py llm/engagement_budget.py llm/local_client.py llm/openrouter_client.py llm/groq_client.py llm/gemini_client.py agents/autonomous_engine.py', 'tests/test_request_metrics.py tests/test_local_model_reliability.py tests/test_openrouter_transport.py tests/test_other_provider_reliability.py tests/test_autonomous_intelligence.py tests/test_engagement_budget.py'),
 'P03-01': ('docs/operational-reliability-coordination.md orchestrator/team_coordinator.py', 'integration/test_reliability_workload_postgres.py'),
 'P03-02': ('orchestrator/team_coordinator.py memory/team_tasks.py', 'tests/test_team_tasks.py tests/test_specialist_integration.py integration/test_mission_state_postgres.py'),
 'P03-03': ('integration/reliability_workload.py docs/operational-reliability-coordination.md', 'integration/test_reliability_workload_postgres.py'),
 'P04-01': ('memory/autonomous_runs.py memory/team_tasks.py memory/investigation_reviews.py', 'integration/test_checkpoint_postgres.py integration/test_review_recovery_postgres.py integration/test_mission_state_postgres.py'),
 'P04-02': ('memory/autonomous_runs.py memory/team_tasks.py memory/worker_jobs.py memory/investigation_reviews.py', 'integration/test_review_recovery_postgres.py integration/test_mission_state_postgres.py tests/test_worker_server.py'),
 'P04-03': ('memory/research.py orchestrator/team_coordinator.py orchestrator/mission_status.py', 'tests/test_research.py tests/test_research_lab.py tests/test_mission_status.py'),
 'P05-01': ('memory/execution_authorization.py orchestrator/blockers.py orchestrator/worker_preflight.py memory/worker_jobs.py worker/app.py agents/autonomous_engine.py', 'tests/test_execution.py tests/test_authorization_store.py tests/test_worker_preflight.py tests/test_worker_server.py tests/test_approval_expiry.py integration/test_mission_state_postgres.py'),
 'P06-01': ('docs/operational-reliability-measurements.md api/main.py api/routers/pentest.py memory/worker_jobs.py worker/observability.py worker/service.py llm/request_metrics.py agents/autonomous_engine.py integration/reliability_workload.py integration/reliability_endurance.py integration/reliability_stream.py integration/reliability_tool_timing.py', 'tests/test_request_metrics.py tests/test_request_observability.py tests/test_transport_observability.py tests/test_worker_observability.py tests/test_stream_fixture_guard.py tests/test_mission_continuity.py integration/test_reliability_workload_postgres.py integration/test_worker.py'),
 'P07-01': ('web/static/scripts/app.js web/static/scripts/dashboard.js', 'tests/frontend_contracts.cjs tests/dashboard_contracts.cjs tests/dashboard_refresh.cjs integration/reliability_visible.py'),
 'P07-02': ('integration/reliability_visible.py', 'integration/reliability_visible.py'),
 'P08-01': ('tests integration', 'tests/frontend_contracts.cjs tests/dashboard_contracts.cjs tests/team_budget_button.cjs'),
 'P08-02': ('integration/reliability_workload.py', 'integration/test_reliability_workload_postgres.py'),
 'P08-03': ('integration/reliability_lab_visible.py', 'integration/reliability_lab_visible.py'),
 'P08-04': ('integration/reliability_endurance.py integration/reliability_endurance_evidence.py', 'tests/test_endurance_evidence.py integration/reliability_endurance.py'),
 'P09-01': ('integration/reliability_audit.py', 'GOALS.md PLANS.md PROGRESS.md'),
 'P10-01': ('memory/session_manager.py memory/database_models.py api/main.py deploy/lab/observe_infrastructure.py deploy/lab/aria-lab-dependencies.service.in deploy/lab/wait_dependencies.py docs/operational-infrastructure-reliability.md', 'tests/test_session_cache_recovery.py tests/test_infrastructure_observer.py tests/test_lab_startup.py tests/test_shutdown_cleanup.py integration/test_infrastructure_recovery.py'),
 'P11-01': ('evaluation/agent_intelligence.py integration/agent_intelligence.py docs/aria-agent-intelligence-evaluation.md', 'tests/test_agent_intelligence.py'),
 'P11-02': ('agents/base_agent.py agents/recon_agent.py agents/scan_agent.py llm/planner_errors.py docs/aria-agent-intelligence-evaluation.md', 'tests/test_agent_public_rejections.py tests/test_discovery_prompt_boundaries.py'),
 'P12-01': ('docs/operational-roadmap.md docs/aria-agent-intelligence-evaluation.md', ''),
 'P13-01': ('integration/supervised_lab_validation.py docs/aria-supervised-lab-run-card.md', 'tests/test_supervised_lab_validation.py'),
 'P14-01': ('docs/aria-8-5-operational-validation-program.md', ''),
 'P14-02': ('integration/reliability_endurance.py docs/operational-reliability-owner-decision.json', 'tests/test_endurance_evidence.py'),
}
OPEN_LIMITATIONS = {
 'P02-03': 'Accounting/timing contracts verified with offline transport fixtures. No paid-provider latency/availability claim; actual charges remain unavailable unless returned by the provider. P06 records bounded cross-layer cohorts;full owner end-to-end latency remains unavailable.',
 'P05-01': 'Existing gates,metadata preflight and expiry remain verified. Current controller deployment has its own source/build record. Expiry blocks without decision/dispatch/replan;no TTL,policy,tool,privilege or budget change.',
 'P06-01': 'Engineering baseline verified under the unchanged unavailable-layer/cohort criteria. Real local container stages and in-container tool wall/child CPU use private fixtures; separate graphical/API/model/SQL baselines retain their own clocks. Owner/Kali performance, isolated wire latency and physical pixel presentation remain unavailable. No global readiness or causal speedup claim.',
 'P07-01': 'Actual dashboard contracts and eight visible synthetic checks verified, including precise costs, stale refresh retirement, blockers, evidence and unavailable values. Live bounded acceptance remains separate.',
 'P08-01': 'Current offline/full SQL and lifecycle/evidence guards have their own logs. Original failing shutdown and clock-dependent SQL evidence retained. Historical actual-container,graphical and stream cohorts stay separately attributed. Fedora service correction is deployed; no Kali telemetry deployment.',
 'P08-03': 'Verified only for the unchanged objective/limit/blocker-stop criterion. Actual owner graphical start,reload,dashboard and evidence navigation stop on model_budget_denied; exact-bound durable terminal,zero new provider/tool calls and unchanged budget. Discovery completion=false. Original expired action remains untouched.',
 'P08-04': 'Only independently reconciled completed exact durations count. Original4h cancellation remains separate. Synthetic ASGI/SQL cohorts do not establish real provider/tool,deployed availability,or8hours/day5days/week capability.',
 'P09-01': 'The owner permits engineering audit closure with only the disclosed eight-hour deferral. All other original criteria,hashes and graphical evidence remain required. Full mission and operational8/5 capability remain unproven.',
 'P10-01': 'Fresh infrastructure and isolated failure/recovery evidence is required;historical successful tests are not repeated without cause.',
 'P11-01': 'The benchmark must distinguish scorer/software controls from actual model intelligence and preserve all four requested dimensions.',
 'P11-02': 'Six usable actual responses and poor engineering rubric results are retained;timeouts and the exhausted token capacity leave collaboration quality unavailable. No general agent expertise is verified.',
 'P12-01': 'Owner confirms no independent senior reviewer is available and permits continuing without waiting. Comparison remains BLOCKED;no generated substitute is accepted.',
 'P13-01': 'A reviewable one-action run card exists,but the fresh proposal expired without owner approval. Zero target submissions;no automatic renewal or approval inference.',
 'P14-01': 'Program preparation must specify concrete evidence and stop criteria;it does not demonstrate execution or readiness.',
 'P14-02': 'Explicitly DEFERRED_BY_OWNER;future28800active seconds and independent raw reconciliation remain required.',
}


def read_json(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stats(values):
    values = sorted(v for v in values if type(v) in (int, float) and math.isfinite(v) and v >= 0)
    return ({'n': len(values), 'mean': statistics.mean(values), 'median': statistics.median(values),
             'maximum': max(values), 'p95': values[math.ceil(.95 * len(values)) - 1] if len(values) >= 20 else None}
            if values else {'n': 0, 'mean': None, 'median': None, 'maximum': None, 'p95': None})


def endurance_clock_context(result: dict) -> dict:
    """Expose clock gaps without treating them as inference or availability."""
    active = result.get('elapsed_seconds')
    if type(active) not in (int,float) or not math.isfinite(active) or active < 0:
        raise ValueError('Invalid active endurance duration')
    context = {'monotonic_active_seconds':active,'utc_timestamp_span_seconds':None,
        'utc_span_minus_active_seconds':None,'boot_elapsed_seconds':None,'suspended_seconds':None,
        'scope':'UTC/monotonic difference is unattributed; only measured boottime/monotonic difference records suspension. Gaps do not prove continuous availability.'}
    for key in ('boot_elapsed_seconds','suspended_seconds'):
        value = result.get(key)
        if value is not None:
            if type(value) not in (int,float) or not math.isfinite(value) or value < 0:
                raise ValueError('Invalid endurance clock diagnostic')
            context[key] = value
    if result.get('finished_at'):
        start = datetime.fromisoformat(result['started_at'])
        finish = datetime.fromisoformat(result['finished_at'])
        if start.tzinfo is None or finish.tzinfo is None:
            raise ValueError('UTC endurance timestamps require timezone provenance')
        span = (finish-start).total_seconds()
        context['utc_timestamp_span_seconds'] = span
        context['utc_span_minus_active_seconds'] = span-active
    return context


def requirement_confidence(requirement_id: str, status: str) -> tuple[str, str]:
    """Qualitative evidence scope, never a readiness score or extra proof."""
    if status == 'DEFERRED_BY_OWNER':
        return ('Owner-deferred; eight-hour acceptance unverified',
                'The explicit owner decision changes scheduling only; completed4h evidence is separate and no8h or8/5 capability is established.')
    if status != 'VERIFIED':
        return ('Unverified for full acceptance',
                'The complete acceptance criterion remains unverified; partial and historical evidence stays separate.')
    special = {
        'P00-01': ('Qualified source provenance',
            'Retained hashes and observed startup fingerprint support source provenance; no signed loaded-code attestation.'),
        'P00-02': ('High for retained-artifact reconciliation',
            'Historical manifests and focused regressions support the recorded reconciliation, not fresh live behavior.'),
        'P00-03': ('High for source inventory',
            'Source call paths are traced; observed runtime use and unavailable components are separately labelled.'),
        'P02-03': ('High for tested accounting boundaries',
            'Transport fixtures support the stated accounting/timing contracts; provider-confirmed inference and billing are separate.'),
        'P06-01': ('Qualified by measurement availability',
            'Confidence covers measured cohorts and explicit unavailable layers only; no causal speedup or full-path latency claim.'),
        'P07-02': ('High for listed graphical interactions',
            'Actual sandboxed visible Chromium supports the listed controls; synthetic deployment and actual lab acceptance stay separate.'),
        'P08-01': ('High for the recorded regression cohorts',
            'Exact passing logs and source manifests support only their tested conditions; later focused checks remain separate.'),
        'P08-02': ('High for the twelve-operation fixture',
            'Raw lifecycle/identity/authorization evidence covers the synthetic workload, not specialist expertise or real execution.'),
        'P08-03': ('High for the observed terminal path',
            'Actual graphical blocker stop matches bound durable evidence; successful discovery remains unverified.'),
        'P08-04': ('High for completed synthetic durations',
            'Exact terminal durations and raw artifacts support synthetic ASGI/SQL endurance only; live8h/day5d/week capability is unproven.'),
        'P09-01': ('High for audited artifact consistency',
            'Confidence covers recorded criteria, hashes and graphical inspection; it never establishes broader operational readiness.'),
    }
    return special.get(requirement_id, ('High for specified controlled conditions',
        'Listed source references and retained regressions support this acceptance criterion; other deployments and execution conditions remain unverified.'))


def requirements():
    result = []
    seen = set()
    for block in re.split(r'(?=^### P)', (ROOT / 'PLANS.md').read_text(), flags=re.M)[1:]:
        rid, title = re.match(r'### (P\d+-\d+): (.*)', block).groups()
        def field(name):
            match = re.search(r'^- ' + re.escape(name) + r': (.*)', block, re.M)
            return match.group(1) if match else ''
        if rid in seen or rid not in REFERENCES:
            raise ValueError('Duplicate or unknown audit requirement: ' + rid)
        seen.add(rid)
        if field('Status') not in {'NOT_STARTED', 'IN_PROGRESS', 'IMPLEMENTED', 'VERIFIED',
                                    'FAILED', 'BLOCKED', 'NOT_TESTED', 'DEFERRED_BY_OWNER'}:
            raise ValueError('Invalid audit requirement status: ' + rid)
        if not field('Acceptance criteria').strip():
            raise ValueError('Missing audit acceptance criterion: ' + rid)
        if field('Status') in {'VERIFIED','DEFERRED_BY_OWNER'} and not field('Evidence / limitations').strip():
            raise ValueError('Verified requirement has no evidence: ' + rid)
        if field('Status') == 'DEFERRED_BY_OWNER':
            if rid not in {'P08-04','P14-02'}:
                raise ValueError('Owner deferral applies only to the recorded eight-hour requirement')
            path = ROOT / 'docs/operational-reliability-owner-decision.json'
            if not path.is_file() or path.is_symlink():
                raise ValueError('Missing explicit owner deferral evidence')
            validate_owner_deferral(read_json(path))
        implementation, tests = REFERENCES[rid]
        refs = implementation.split() + tests.split()
        for ref in refs:
            if not (ROOT / ref).exists():
                raise ValueError('Missing audit reference: ' + ref)
        confidence, confidence_basis = requirement_confidence(rid,field('Status'))
        result.append({'requirement_id': rid, 'title': title, 'status': field('Status'),
            'acceptance_criteria': field('Acceptance criteria'),
            'implementation_reference': implementation.split(), 'test_reference': tests.split(),
            'actual_evidence': field('Evidence / limitations'),
            'confidence': confidence, 'confidence_basis': confidence_basis,
            'remaining_limitations': OPEN_LIMITATIONS.get(rid,
                'Verified for the defined synthetic/source contract. Production-scale and fresh live acceptance are separate requirements.')})
    if seen != set(REFERENCES):
        raise ValueError('Audit is missing mandatory requirements: ' + ', '.join(sorted(set(REFERENCES) - seen)))
    return result


def regression_result(path):
    """Only a complete passing unittest log supports a passing regression row."""
    content = path.read_text()
    match = re.search(r'^Ran (\d+) tests? in ([\d.]+)s\s+OK\s*\Z', content, re.M)
    if not match:
        raise ValueError('Missing complete passing regression evidence: ' + str(path))
    return {'tests': int(match[1]), 'unittest_seconds': float(match[2])}


def validate_owner_deferral(decision: dict | None, durations: dict | None = None) -> dict:
    """Validate this retained scheduling exception; it grants no execution power."""
    expected = {'schema':'aria.owner-endurance-deferral.v1',
        'decision_id':'owner-2026-11-17-eight-hour-deferral',
        'decision_date':'2026-11-17','authority':'explicit_project_owner_instruction_in_conversation',
        'requirement_id':'P08-04','duration_seconds':28800,'disposition':'DEFERRED_BY_OWNER',
        'deferred_to':'P14-02','accepted_four_hour_cohort':'endurance-5080b70117b7',
        'accepted_four_hour_seconds':14400,'engineering_audit_may_close_with_disclosed_exception':True,
        'eight_hour_test_verified':False,'full_mission_complete':False,
        'operational_8_5_readiness_demonstrated':False,'additional_spending_or_target_authorization':False}
    if (not isinstance(decision,dict) or any(type(decision.get(k)) is not type(v)
            or decision.get(k) != v for k,v in expected.items())
            or not isinstance(decision.get('reason'),str) or not decision['reason'].strip()
            or not isinstance(decision.get('owner_instruction'),str) or not decision['owner_instruction'].strip()):
        raise ValueError('Missing or invalid explicit eight-hour owner deferral')
    if durations is not None and (any(durations.get(k) != 'VERIFIED' for k in ('2h','4h'))
            or durations.get('8h') != 'DEFERRED_BY_OWNER'):
        raise ValueError('Owner deferral cannot replace completed prerequisite duration evidence')
    return decision


def completion_claim(reqs, durations, live_status, owner_decision=None):
    """Reject premature plan claims before writing any passing artifact."""
    statuses = {r['requirement_id']:r['status'] for r in reqs}
    deferred = {rid for rid,status in statuses.items() if status == 'DEFERRED_BY_OWNER'}
    if deferred or durations.get('8h') == 'DEFERRED_BY_OWNER' or owner_decision is not None:
        validate_owner_deferral(owner_decision,durations)
        if (not deferred or deferred - {'P08-04','P14-02'}
                or statuses.get('P08-04') != 'DEFERRED_BY_OWNER'
                or statuses.get('P14-02') == 'VERIFIED'):
            raise ValueError('Eight-hour deferral cannot certify or hide other requirements')
    if statuses.get('P08-03') == 'VERIFIED' and live_status != 'VERIFIED':
        raise ValueError('Laboratory acceptance is not verified')
    if (statuses.get('P08-04') == 'VERIFIED'
            and any(durations.get(key) != 'VERIFIED' for key in ('2h','4h','8h'))):
        raise ValueError('Progressive endurance is not verified')
    if (statuses.get('P09-01') == 'VERIFIED'
            and any(status != 'VERIFIED' and not (rid == 'P08-04' and owner_decision is not None
                    and status == 'DEFERRED_BY_OWNER')
                for rid,status in statuses.items() if rid.startswith(tuple('P%02d-' % p for p in range(9))))):
        raise ValueError('Final audit cannot pass while mandatory requirements remain unmet')
    return all(status == 'VERIFIED' for status in statuses.values())


def verified_tool_samples(result):
    """Positive target controls and strict measurements support this fixture only."""
    import uuid
    samples = result.get('samples')
    if result.get('status') != 'VERIFIED' or not isinstance(samples, list) or len(samples) != 2:
        raise ValueError('Incomplete tool timing evidence')
    jobs = set()
    for sample in samples:
        tool = sample.get('tool')
        control = {'curl': 'http_positive_control', 'nmap': 'nmap_positive_control'}.get(tool)
        if (control is None or sample.get(control) is not True
                or sample.get('schema') != 'aria.fixture.tool-timing.v1'
                or type(sample.get('exit_code')) is not int or sample['exit_code'] != 0):
            raise ValueError('Tool identity/positive-control evidence is invalid')
        try:
            for name in ('job_id', 'session_id'):
                if str(uuid.UUID(sample[name])) != sample[name]:
                    raise ValueError()
        except (KeyError, ValueError, TypeError, AttributeError):
            raise ValueError('Tool evidence identity is invalid') from None
        if sample['job_id'] in jobs:
            raise ValueError('Duplicate tool timing job')
        jobs.add(sample['job_id'])
        for key in ('tool_wall_ms', 'child_user_cpu_ms', 'child_system_cpu_ms'):
            value = sample.get(key)
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError('Tool measurement is unavailable or invalid')
    if {sample['tool'] for sample in samples} != {'curl', 'nmap'}:
        raise ValueError('Missing tool timing cohort')
    return samples


def live_acceptance_summary(browser, observation, acceptance_status):
    """A stale graphical capture never overrides a later durable observation."""
    if browser['run_id'] != observation['run_id'] or browser['session_id'] != observation['session_id']:
        raise ValueError('Lab evidence run/session binding mismatch')
    terminal = browser.get('terminal_event') or browser.get('terminal_observation')
    if acceptance_status == 'VERIFIED':
        status = browser.get('run_status') or {}
        durable = observation.get('run') or {}
        if (browser['status'] != 'VERIFIED' or not isinstance(terminal, dict)
                or browser.get('headless') is not False or browser.get('chromium_sandbox') is not True
                or browser.get('api_interaction_substitutions') is not False
                or browser.get('page_error_types') != [] or observation.get('read_only') is not True
                or terminal.get('run_id') != browser['run_id']
                or terminal.get('run_state') not in {'completed', 'blocked', 'failed'}
                or terminal.get('run_state') != durable.get('run_state')
                or terminal.get('reason_code') != durable.get('reason_code')
                or status.get('run_id') != browser['run_id'] or status.get('active') is not False
                or status.get('run_state') != durable.get('run_state')
                or not browser.get('objective')
                or browser['objective'] != durable.get('original_objective')
                or status.get('original_objective') != browser['objective']
                or (terminal.get('type') != 'auto_complete'
                    and terminal.get('source') != 'graphical_start_response')
                or not browser.get('screenshots')):
            raise ValueError('Verified laboratory acceptance requires bound terminal graphical and durable evidence')
    observed_at = datetime.fromisoformat(observation['collected_at']).timestamp()
    expired = [item['id'] for item in observation['authorizations']
        if item['status'] == 'pending' and type(item.get('expires_at')) in (int, float)
        and item['expires_at'] <= observed_at]
    return {'status': acceptance_status, 'browser_capture_status': browser['status'],
        'run_id': browser['run_id'], 'target': browser['target'], 'server_build': browser['server_build'],
        'directory': browser['directory'], 'terminal_event': browser.get('terminal_event'),
        'terminal_observation': browser.get('terminal_observation'),
        'durable_observed_at': observation['collected_at'],
        'durable_run_state': observation['run']['run_state'], 'expired_pending_action_ids': expired,
        'worker_jobs': len(observation['jobs']), 'human_decisions': browser['human_decisions']}


def metric_rows(benchmark, endurance, visible, stream, active_checkpoint=None, intelligence=None):
    rows = []
    def row(run, scope, metric, value, unit, basis, operation='', correlation=''):
        rows.append({'run': run, 'scope': scope, 'operation': operation, 'correlation_id': correlation,
            'metric': metric, 'value': value, 'unit': unit, 'availability': 'measured' if value is not None else 'unavailable', 'basis': basis})
    for op in benchmark['operations']:
        for name in ('lifecycle_wall_ms', 'coordinator_wall_ms', 'proposal_wall_ms',
                     'synthetic_owner_decision_wall_ms', 'worker_path_wall_ms'):
            row(SQL_RUN, 'synthetic_operation', name, op.get(name), 'ms',
                'Real SQL; deterministic model/owner and ASGI worker; lifecycle state=' + op['state'],
                op['number'], op['correlation_id'])
        for value in op['json_parse_validation_ms']:
            row(SQL_RUN, 'synthetic_operation', 'generic_json_parse_validation_ms', value, 'ms',
                'BaseAgent parser; not strict Pydantic review validation', op['number'], op['correlation_id'])
    for name in ('lifecycle_wall_ms', 'coordinator_wall_ms', 'proposal_wall_ms',
                 'synthetic_owner_decision_wall_ms', 'worker_path_wall_ms'):
        summary = stats([op.get(name) for op in benchmark['operations']])
        for statistic in ('mean', 'median', 'maximum', 'p95'):
            row(SQL_RUN, 'synthetic_operation_summary', name+'_'+statistic, summary[statistic], 'ms',
                f"n={summary['n']}; heterogeneous twelve-operation fixture; p95 unavailable below20 samples")
    for key, value in benchmark['counters'].items():
        unit = 'bytes' if 'bytes' in key else 'ms' if key.endswith('_ms') else 'count'
        row(SQL_RUN, 'synthetic_workload', key, value, unit, 'Counter window excludes initial database/fixture setup; boundaries may overlap')
    for key in ('actual_external_provider_calls', 'actual_tools_executed', 'lost_operations', 'duplicate_dispatches', 'unauthorized_dispatches'):
        row(SQL_RUN, 'synthetic_workload', key, benchmark[key], 'count', 'Observed/asserted fixture contract')
    fixture_directory = EVIDENCE / 'provider-timing-cycle8'
    for index, line in enumerate((fixture_directory / 'provider-transport-fixtures.jsonl').read_text().splitlines(), 1):
        item = json.loads(line)
        for key, value in item['timings'].items():
            row('provider-timing-cycle8', item['provider_fixture'], key, value,
                'count' if key == 'http_attempts' else 'ms',
                'Offline MockTransport sample; error=' + item.get('error', 'none') + '; no inference/billing', index)
    for index, line in enumerate((fixture_directory / 'review-timing-fixtures.jsonl').read_text().splitlines(), 1):
        item = json.loads(line)
        for key in ('structured_validation_ms', 'result_preparation_ms', 'projection_persistence_ms'):
            row('provider-timing-cycle8', 'strict_review_fixture', key, item['metrics'].get(key),
                'ms', item['case'] + '; no provider call; missing stages remain unavailable', index)
    for item in endurance:
        name, result = item['run'], item['result']
        for key in ('elapsed_seconds', 'cpu_seconds', 'recorded_operations', 'availability_samples',
                    'availability_failures', 'batch_failures', 'current_rss_kb', 'rss_growth_kb', 'maximum_database_connections'):
            row(name, 'synthetic_endurance', key, result.get(key), 'seconds' if key.endswith('seconds') else 'KiB' if key.endswith('_kb') else 'count', result['status'])
        for metric, summary in item['statistics'].items():
            for statistic in ('mean', 'median', 'maximum', 'p95'):
                row(name, 'synthetic_endurance', metric + '_' + statistic, summary[statistic],
                    'seconds' if metric.startswith('batch') else 'ms', f"{result['status']}; n={summary['n']}; p95 nearest rank only for n>=20")
        clock = endurance_clock_context(result)
        for key in ('utc_timestamp_span_seconds','utc_span_minus_active_seconds','suspended_seconds'):
            row(name,'endurance_clock_diagnostic',key,clock[key],'seconds',
                clock['scope']+' Active duration is separate from UTC span.')
    if active_checkpoint is not None:
        clock = endurance_clock_context(active_checkpoint['result'])
        for key in ('monotonic_active_seconds','boot_elapsed_seconds','suspended_seconds'):
            row(active_checkpoint['run'],'unfinished_endurance_clock_diagnostic',key,clock[key],
                'seconds',active_checkpoint['result']['status']+
                ' incomplete-duration evidence only;not a completed acceptance duration or continuous availability claim')
    for key, value in (visible.get('navigation_timings_ms') or {}).items():
        row(VISIBLE_RUN, 'visible_chromium_navigation', key, value, 'ms', 'Single browser-clock navigation sample, not complete asynchronous data rendering')
    for index, sample in enumerate(visible.get('browser_measurements', []), 1):
        detail = sample.get('detail') or {}
        row(VISIBLE_RUN, 'visible_chromium_measurement', sample['name'], sample['duration_ms'], 'ms',
            'Single local browser-clock interval; no clock-domain subtraction or causal comparison', index,
            detail.get('request_id') or detail.get('run_id') or '')
        if sample['name'] == 'aria.http.headers':
            row(VISIBLE_RUN, 'server_http_handler', 'handler_ms', detail.get('server_handler_ms'), 'ms',
                'Server monotonic request handling to response headers; excludes browser/network/body consumption',
                index, detail.get('request_id') or '')
    samples = (EVIDENCE / REGRESSION_RUN / 'controller-transport-fixtures.jsonl').read_text().splitlines()
    for index, line in enumerate(samples, 1):
        sample = json.loads(line)
        if sample['clock'] != 'local_monotonic_MockTransport':
            continue  # Injected boundary values are test evidence, never real latency.
        for metric, value in sample['timings'].items():
            row(REGRESSION_RUN, 'controller_worker_MockTransport', metric, value, 'ms',
                'Local monotonic offline fixture; case=' + sample['case'] + '; outcome=' + sample['outcome']
                + '; no tool/remote worker; unstarted phases unavailable', index, sample['worker_request_id'])
    for sample in stream['server_sends']:
        row(STREAM_RUN, 'visible_websocket_server_send', 'websocket_asgi_send_ms',
            sample['websocket_asgi_send_ms'], 'ms', 'Real isolated Uvicorn; serialization/ASGI send/flow control only',
            sample['event_sequence'], sample['run_id']+':'+str(sample['event_sequence']))
    for sample in stream['browser_events']:
        for name in ('observer_microtask_ms', 'frame_opportunity_ms'):
            row(STREAM_RUN, 'visible_websocket_browser', name, sample[name], 'ms',
                'Browser-local observer microtask / two-frame opportunity; not proof of application processing or pixels',
                sample['event_sequence'], sample['run_id']+':'+str(sample['event_sequence']))
    stream_cohorts = {'websocket_asgi_send_ms': [s['websocket_asgi_send_ms'] for s in stream['server_sends']],
        **{key: [s[key] for s in stream['browser_events']] for key in ('observer_microtask_ms', 'frame_opportunity_ms')}}
    for name, values in stream_cohorts.items():
        summary = stats(values)
        for statistic in ('mean', 'median', 'maximum', 'p95'):
            row(STREAM_RUN, 'visible_websocket_summary', name+'_'+statistic, summary[statistic], 'ms',
                'n=4 passive fixture events; descriptive only; p95 unavailable; no cross-clock subtraction')
    for layer in ('worker_communication_isolated', 'owner_container_lifecycle', 'owner_real_tool_execution',
                  'accepted_human_decision_for_expired_action', 'websocket_delivery',
                  'owner_deployment_websocket_asgi_send', 'browser_actual_pixel_presentation'):
        row('current_audit', 'missing_layer', layer, None, 'ms', 'Not measured; no zero or cross-machine clock subtraction inferred')
    worker = read_json(EVIDENCE / WORKER_VALIDATION / 'worker-runtime-fixtures.json')
    for index, sample in enumerate(worker['records'], 1):
        for name in ('duration_ms', 'queue_wait_ms', 'lock_held_ms'):
            if name in sample:
                row(WORKER_VALIDATION, 'worker_in_memory_runtime', name, sample[name], 'ms',
                    'Real local monotonic clock; in-memory runtime, zero containers/tools; '
                    + sample.get('stage', sample.get('operation', 'unknown')), index, sample['job_id'])
    for cohort, filename in (('unmodified_private_fixture', 'real-worker-stages.jsonl'),
                             ('observed_tool_private_fixture', 'tool-spans/runtime-stages.jsonl')):
        records = [json.loads(line) for line in (EVIDENCE / CURRENT_VALIDATION / filename).read_text().splitlines()]
        for index, sample in enumerate(records, 1):
            for name in ('duration_ms', 'queue_wait_ms', 'lock_held_ms'):
                if name in sample:
                    row(CURRENT_VALIDATION, cohort, name, sample[name], 'ms',
                        'Real rootless Podman/private HTTP fixture; includes CLI/backend overhead; '
                        + sample.get('stage', sample.get('operation', 'unknown')),
                        index, sample.get('job_id') or '')
        if cohort == 'unmodified_private_fixture':
            for stage in ('create', 'start', 'inspect', 'output', 'stop'):
                summary = stats([r['duration_ms'] for r in records if r.get('stage') == stage])
                for statistic in ('mean', 'median', 'maximum', 'p95'):
                    row(CURRENT_VALIDATION, 'real_runtime_stage_summary', stage+'_'+statistic,
                        summary[statistic], 'ms', f"n={summary['n']}; descriptive CLI stage cohort; p95 unavailable below20")
    tool_result = read_json(EVIDENCE / CURRENT_VALIDATION / 'tool-spans/result.json')
    for sample in tool_result['samples']:
        for name in ('tool_wall_ms', 'child_user_cpu_ms', 'child_system_cpu_ms'):
            row(CURRENT_VALIDATION, 'in_container_tool_observer', name, sample[name], 'ms',
                'Unprivileged validated argv on synthetic target; tool='+sample['tool']
                + '; n=1 per tool; subprocess creation/output collection included; no inference or Kali claim',
                sample['tool'], sample['job_id'])
    if intelligence is not None:
        for cohort in intelligence['cohorts']:
            for case in cohort['cases']:
                basis='Actual '+cohort['model']+';controlled evidence;case='+case['case_id']
                row(cohort['directory'],'actual_agent_case','case_wall_seconds',case.get('wall_seconds'),
                    'seconds',basis+';includes ownership,context,accounting and provider work')
                for attempt in case.get('provider_records',[]):
                    identity=attempt.get('attempt_id') or ''
                    for metric in ('tokens_used','cost_microusd'):
                        row(cohort['directory'],'actual_local_model',metric,attempt.get(metric),
                            'tokens' if metric=='tokens_used' else 'microUSD',
                            basis+';error='+str(attempt.get('error') or 'none')+';missing usage remains unavailable',
                            case['case_id'],identity)
                    for metric,value in (attempt.get('timings') or {}).items():
                        row(cohort['directory'],'actual_local_model_timing',metric,value,
                            'count' if metric=='http_attempts' else 'ms',basis+';not isolated inference time',
                            case['case_id'],identity)
        for dimension,summary in intelligence['scores']['dimensions'].items():
            for metric in ('passed','assessed','unassessed','opportunities','pass_rate'):
                row(INTELLIGENCE_VALIDATION,'engineering_quality_rubric',dimension+'_'+metric,
                    summary[metric],'ratio' if metric=='pass_rate' else 'checks',
                    'Engineering-agent grading;small heterogeneous cases;not independent human references or readiness')
    return rows


def table(headers, rows):
    return '<div class="scroll"><table><thead><tr>' + ''.join('<th>' + escape(h) + '</th>' for h in headers) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td>' + str(v) + '</td>' for v in r) + '</tr>' for r in rows) + '</tbody></table></div>'


def main():
    output = ROOT / 'reports'
    output.mkdir(exist_ok=True)
    benchmark = read_json(EVIDENCE / SQL_RUN / 'twelve-operation-benchmark.json')
    visible = read_json(EVIDENCE / VISIBLE_RUN / 'result.json')
    stream = read_json(EVIDENCE / STREAM_RUN / 'result.json')
    identity = lambda event: (event['session_id'], event['run_id'], event['event_sequence'])
    if (stream['status'] != 'VERIFIED' or stream['source_unchanged_during_acceptance'] is not True
            or len(stream['server_sends']) != 4
            or [identity(e) for e in stream['server_sends']] != [identity(e) for e in stream['browser_events']]
            or len({identity(e) for e in stream['server_sends']}) != 4):
        raise ValueError('Incomplete or unbound graphical stream evidence')
    from integration.reliability_endurance_evidence import validate_endurance
    selection = read_json(EVIDENCE / FINAL_VALIDATION / 'endurance-cohorts.json')
    selected = {duration: selection.get(duration) for duration in ('4h','8h')}
    active_name = selected['8h'] or selected['4h']
    duration_status = {'2h':'VERIFIED','4h':'NOT_TESTED','8h':'NOT_TESTED'}
    validations = {}
    for duration, name in selected.items():
        if name:
            path = EVIDENCE/name
            result = read_json(path/('result.json' if (path/'result.json').exists() else 'checkpoint.json'))
            duration_status[duration] = result['status']
            if result['status'] == 'VERIFIED':
                validations[name] = validate_endurance(path, {'4h':14400,'8h':28800}[duration])
    owner_decision = validate_owner_deferral(read_json(ROOT / 'docs/operational-reliability-owner-decision.json'))
    if duration_status['8h'] == 'VERIFIED':
        raise ValueError('The current owner-deferred audit must not relabel a completed eight-hour result')
    duration_status['8h'] = 'DEFERRED_BY_OWNER'
    validate_owner_deferral(owner_decision,duration_status)
    endurance = []
    for name in ENDURANCE_RUNS + list(validations):
        path = EVIDENCE / name
        result = read_json(path / ('result.json' if (path / 'result.json').exists() else 'checkpoint.json'))
        if name in ENDURANCE_RUNS:
            duration = (900,1800,3600,7200)[ENDURANCE_RUNS.index(name)]
            validations[name] = validate_endurance(path,duration)
        batches = [json.loads(line)['wall_seconds'] for line in (path / 'batches.jsonl').read_text().splitlines()]
        samples = [json.loads(line) for line in (path / 'samples.jsonl').read_text().splitlines()]
        endurance.append({'run': name, 'result': result, 'statistics': {
            'batch_wall_seconds': stats(batches), 'readiness_wall_ms': stats([s.get('api_readiness_wall_ms') for s in samples])}})
    reqs = requirements()
    active_endurance = read_json(EVIDENCE / active_name / 'checkpoint.json')
    if (next(r['status'] for r in reqs if r['requirement_id']=='P08-04') == 'VERIFIED'
            and any(value != 'VERIFIED' for value in duration_status.values())):
        raise ValueError('Progressive endurance cannot be verified before every completed duration is evidenced')
    interrupted_endurance = read_json(EVIDENCE / INTERRUPTED_ENDURANCE / 'result.json')
    lab = read_json(EVIDENCE / LAB_RUN / 'result.json')
    observation = read_json(EVIDENCE / LAB_OBSERVATION)
    live = live_acceptance_summary(lab, observation, next(r['status'] for r in reqs if r['requirement_id'] == 'P08-03'))
    real_worker = read_json(EVIDENCE / CURRENT_VALIDATION / 'real-worker-result.json')
    tool_spans = read_json(EVIDENCE / CURRENT_VALIDATION / 'tool-spans/result.json')
    verified_tool_samples(tool_spans)
    baseline_audit = read_json(EVIDENCE / CURRENT_VALIDATION / 'p06-requirement-audit.json')
    if (baseline_audit['status'] != 'VERIFIED'
            or baseline_audit['acceptance_criteria_unchanged'] != next(r['acceptance_criteria'] for r in reqs if r['requirement_id']=='P06-01')
            or not all(value is True for value in baseline_audit['criteria'].values())):
        raise ValueError('Engineering measurement baseline audit is incomplete')
    if (real_worker['status'] != 'VERIFIED' or real_worker['tests_run'] != 1
            or tool_spans['status'] != 'VERIFIED' or len(tool_spans['samples']) != 2
            or any(s['exit_code'] != 0 for s in tool_spans['samples'])):
        raise ValueError('Incomplete actual-container fixture evidence')
    regressions = {'offline': regression_result(EVIDENCE / DISCOVERY_VALIDATION / 'python-full.log'),
                   'historical_intelligence_output_offline': regression_result(EVIDENCE / INTELLIGENCE_VALIDATION / 'python-full.log'),
                   'discovery_contract_focused': regression_result(EVIDENCE / DISCOVERY_VALIDATION / 'discovery-after.log'),
                   'discovery_audit_metadata_focused': regression_result(EVIDENCE / DISCOVERY_VALIDATION / 'audit-focused.log'),
                   'discovery_audit_metadata_final': regression_result(EVIDENCE / DISCOVERY_VALIDATION / 'audit-final-focused.log'),
                   'historical_infrastructure_offline': regression_result(EVIDENCE / DEFERRAL_VALIDATION / 'python-full.log'),
                   'historical_cycle14_offline': regression_result(EVIDENCE / FINAL_VALIDATION / 'python-final.log'),
                   'sql': regression_result(EVIDENCE / SQL_RUN / 'tests.log'),
                   'worker_sql': regression_result(EVIDENCE / 'sql-eebb26a5a65b/tests.log'),
                   'later_audit_focused': regression_result(EVIDENCE / AUDIT_VALIDATION / 'audit-focused.log'),
                   'later_clock_audit_focused': regression_result(EVIDENCE / CLOCK_VALIDATION / 'clock-audit-focused.log'),
                   'later_metadata_audit_focused': regression_result(EVIDENCE / METADATA_VALIDATION / 'metadata-contracts.log'),
                   'owner_deferral_audit_focused': regression_result(EVIDENCE / DEFERRAL_VALIDATION / 'deferral-audit.log'),
                   'infrastructure_focused': regression_result(EVIDENCE / DEFERRAL_VALIDATION / 'infrastructure-focused-fixed.log'),
                   'later_infrastructure_observer': regression_result(EVIDENCE / DEFERRAL_VALIDATION / 'observer-focused.log'),
                   'agent_output_focused': regression_result(EVIDENCE / INTELLIGENCE_VALIDATION / 'partial-rejection-after.log'),
                   'later_supervised_approval_gates': regression_result(EVIDENCE / INTELLIGENCE_VALIDATION / 'supervised-gates.log'),
                   'historical_cycle14_audit_focused': regression_result(EVIDENCE / FINAL_VALIDATION / 'evidence-final-focused.log'),
                   'historical_cycle13_offline': regression_result(EVIDENCE / CURRENT_VALIDATION / 'python-full.log'),
                   'historical_cycle11_sql': regression_result(EVIDENCE / 'sql-ef611e70dcb1/tests.log')}
    deployment = read_json(EVIDENCE / FINAL_VALIDATION / 'owner-recovery.json')
    current_owner = read_json(EVIDENCE / DISCOVERY_VALIDATION / 'owner-discovery-deployment.json')
    from evaluation.agent_intelligence import score as intelligence_score
    plan=read_json(EVIDENCE / INTELLIGENCE_VALIDATION / 'protocol.json')
    composite=read_json(EVIDENCE / INTELLIGENCE_VALIDATION / 'composite-run.json')
    assessment=read_json(EVIDENCE / INTELLIGENCE_VALIDATION / 'engineering-assessment.json')
    scores=intelligence_score(plan,composite,assessment)
    if scores!=read_json(EVIDENCE / INTELLIGENCE_VALIDATION / 'engineering-scores.json'):
        raise ValueError('Intelligence scores do not match response-bound engineering assessments')
    cohort_names=('local-qwen4b-v1','local-qwen08b-v1','local-qwen08b-remaining-v1')
    cohorts=[{**read_json(EVIDENCE / INTELLIGENCE_VALIDATION / name / 'run.json'),
              'directory':name} for name in cohort_names]
    attempts=[a for cohort in cohorts for a in cohort['durable_attempts']]
    if (len({a['id'] for a in attempts})!=len(attempts)
            or composite['accounting_after']['calls']-cohorts[0]['accounting_before']['calls']!=len(attempts)
            or composite['accounting_after']['reserved_tokens']-cohorts[0]['accounting_before']['reserved_tokens']
                !=sum(a['reserved_tokens'] for a in attempts)):
        raise ValueError('Actual-model attempt identities or conservative reservations do not reconcile')
    intelligence={'protocol':plan,'scores':scores,'cohorts':cohorts,
        'composite':composite,'independent_senior_comparison':'BLOCKED',
        'supervised_lab':read_json(EVIDENCE / 'p13-supervised-head-v1/expiry-validation.json'),
        'operational_program_prepared':True,'operational_8_5_readiness_demonstrated':False}
    provenance_paths = [EVIDENCE / REGRESSION_RUN / 'source-final-manifest.json', EVIDENCE / SQL_RUN / 'tests.log',
        EVIDENCE / REGRESSION_RUN / 'python-final.log', EVIDENCE / VISIBLE_RUN / 'result.json',
        EVIDENCE / VISIBLE_RUN / 'source-manifest.json',
        EVIDENCE / REGRESSION_RUN / 'controller-transport-fixtures.jsonl',
        EVIDENCE / 'provider-timing-cycle8/provider-transport-fixtures.jsonl',
        EVIDENCE / 'provider-timing-cycle8/review-timing-fixtures.jsonl',
        EVIDENCE / LAB_OBSERVATION, EVIDENCE / REGRESSION_RUN / 'owner-health-readonly.json',
        EVIDENCE / 'controller-deployment-cycle10.json', EVIDENCE / LAB_RUN / 'result.json',
        ROOT / 'GOALS.md', ROOT / 'PLANS.md', ROOT / 'docs/operational-reliability-measurements.md',
        ROOT / 'integration/reliability_audit.py', ROOT / 'tests/test_reliability_audit.py']
    provenance_paths += [EVIDENCE / VISIBLE_RUN / name for name in visible['screenshots']]
    provenance_paths += [EVIDENCE / STREAM_RUN / name for name in ('result.json', 'source-manifest.json',
        'websocket-sends.jsonl', 'stream-workspace.png')]
    provenance_paths += [ROOT / 'integration/reliability_stream.py', ROOT / 'integration/reliability_visible.py',
        ROOT / 'tests/test_stream_fixture_guard.py']
    provenance_paths += [EVIDENCE / WORKER_VALIDATION / name for name in ('source-manifest.json',
        'python-full.log', 'worker-focused-final.log', 'worker-runtime-fixtures.json', 'worker-telemetry-review.json')]
    provenance_paths += [ROOT / 'worker/service.py', ROOT / 'worker/observability.py',
        ROOT / 'tests/test_worker_observability.py', EVIDENCE / 'sql-eebb26a5a65b/tests.log']
    provenance_paths += [EVIDENCE / 'endurance-7acf4dc15d40/result.json',
        EVIDENCE / WORKER_VALIDATION / 'two-hour-validation.json',
        EVIDENCE / WORKER_VALIDATION / 'four-hour-database.json', EVIDENCE / ACTIVE_ENDURANCE / 'source-manifest.json']
    provenance_paths += [EVIDENCE / WORKER_VALIDATION / 'owner-current-observation.json']
    provenance_paths += [EVIDENCE / CURRENT_VALIDATION / name for name in ('python-full.log',
        'deployment-mechanics.log', 'source-observation.json', 'real-worker-result.json',
        'real-worker-stages.jsonl', 'real-worker-test.log', 'tool-spans/result.json',
        'tool-spans/tests.log', 'tool-spans/runtime-stages.jsonl', 'worker-telemetry-bundle/manifest.json')]
    provenance_paths += [ROOT / 'deploy/lab/worker_telemetry.py', ROOT / 'tests/test_worker_telemetry_deployment.py',
        ROOT / 'integration/reliability_tool_timing.py', ROOT / 'integration/test_worker.py']
    provenance_paths += [EVIDENCE / CURRENT_VALIDATION / 'p06-requirement-audit.json',
        EVIDENCE / CURRENT_VALIDATION / 'final-audit-focused.log']
    provenance_paths += [EVIDENCE / FINAL_VALIDATION / name for name in (
        'entry-provenance.json','source-manifest.json','source-final-manifest.json','outage-investigation.json',
        'owner-recovery.json','owner-api-restart-validation.json','original-four-hour-validation.json',
        'two-hour-revalidation.json','lab-acceptance-validation.json','endurance-cohorts.json',
        'python-final.log','shutdown-before.log','shutdown-after.log','lifecycle-focused.log',
        'lab-service-focused.log','simulation-clock-focused.log','evidence-final-focused.log',
        'rate-limit-validation.json','owner-terminal-ui.json')]
    provenance_paths += [EVIDENCE / FINAL_VALIDATION / name for name in read_json(
        EVIDENCE / FINAL_VALIDATION / 'owner-terminal-ui.json')['screenshots']]
    provenance_paths += [EVIDENCE / INTERRUPTED_ENDURANCE / name for name in ('result.json','source-manifest.json')]
    provenance_paths += [EVIDENCE / LAB_RUN / name for name in lab['screenshots']]
    provenance_paths += [ROOT/name for name in ('api/main.py','tests/test_shutdown_cleanup.py',
        'deploy/lab/wait_dependencies.py','deploy/lab/aria-lab-dependencies.service.in',
        'deploy/lab/aria-fedora.service.in','deploy/aria.service','tests/test_lab_startup.py',
        'tests/test_simulation_clock.py','tests/endurance_harness.py','integration/test_endurance_postgres.py',
        'integration/reliability_endurance.py','integration/reliability_endurance_evidence.py',
        'tests/test_endurance_evidence.py','docs/operational-reliability-outage.md')]
    provenance_paths += [EVIDENCE / AUDIT_VALIDATION / name for name in (
        'entry-provenance.json','audit-before.log','audit-focused.log','source-manifest.json')]
    provenance_paths += [EVIDENCE / CLOCK_VALIDATION / name for name in (
        'host-suspend-evidence.json','clock-audit-focused.log','clock-source-manifest.json','post-suspend-owner-state.json')]
    provenance_paths += [EVIDENCE / METADATA_VALIDATION / name for name in (
        'current-revision-observation.json','requirement-contracts-before.json',
        'requirement-contracts-after.json','metadata-contracts.log','source-manifest.json')]
    provenance_paths += [ROOT / name for name in ('docs/operational-reliability-owner-decision.json',
        'docs/operational-roadmap.md')]
    provenance_paths += [EVIDENCE / DEFERRAL_VALIDATION / name for name in (
        'owner-deferral-preflight.json','owner-current-readonly.json','original-requirement-contracts.json',
        'deferral-before.log','deferral-audit.log')]
    provenance_paths += [EVIDENCE / DEFERRAL_VALIDATION / name for name in (
        'python-full.log','python-full-fixture-failure.log','cache-before.log','cache-after.log',
        'infrastructure-focused-fixed.log','observer-focused.log','observer-installation.json',
        'infrastructure-tested-source-manifest.json','owner-infrastructure-deployment.json')]
    provenance_paths += [ROOT / name for name in ('memory/session_manager.py','memory/database_models.py',
        'deploy/lab/observe_infrastructure.py','tests/test_session_cache_recovery.py',
        'tests/test_infrastructure_observer.py','integration/infrastructure_recovery.py',
        'integration/test_infrastructure_recovery.py','docs/operational-infrastructure-reliability.md',
        'deploy/lab/aria-infrastructure-observer.service.in','deploy/lab/aria-infrastructure-observer.timer.in')]
    provenance_paths += [EVIDENCE / run / name for run in ('infrastructure-0a1c5898bdde','infrastructure-ebd7dfca1e7b')
                        for name in ('summary.json','tests.log')]
    provenance_paths += [EVIDENCE / selected['8h'] / name for name in (
        'result.json','checkpoint.json','source-manifest.json','process.json')]
    provenance_paths += [EVIDENCE / INTELLIGENCE_VALIDATION / name for name in (
        'protocol.json','senior-reviewer-packet.json','composite-run.json','engineering-assessment.json',
        'engineering-scores.json','source-tested-manifest.json','owner-output-deployment.json',
        'agent-contracts.log','agent-contracts-fixed.log','partial-rejection-before.log',
        'partial-rejection-after.log','python-full.log','supervised-gates.log')]
    provenance_paths += [EVIDENCE / INTELLIGENCE_VALIDATION / name / 'run.json' for name in cohort_names]
    provenance_paths += [EVIDENCE / DISCOVERY_VALIDATION / name for name in (
        'python-full.log','discovery-before.log','discovery-after.log','audit-focused.log','source-tested-manifest.json',
        'audit-final-focused.log','audit-final-source-manifest.json','owner-discovery-deployment.json',
        'host-suspend-observation.json','host-suspend-observation.log','deploy_discovery_corrections.py')]
    provenance_paths += [EVIDENCE / 'p13-supervised-head-v1' / name for name in (
        'preflight.json','pending-proposal.json','expiry-validation.json')]
    provenance_paths += [EVIDENCE / DEFERRAL_VALIDATION / 'owner-senior-comparison-blocker.json']
    provenance_paths += [ROOT / name for name in ('evaluation/agent_intelligence.py',
        'integration/agent_intelligence.py','integration/supervised_lab_validation.py',
        'tests/test_agent_intelligence.py','tests/test_agent_public_rejections.py','tests/test_supervised_lab_validation.py',
        'agents/base_agent.py','agents/recon_agent.py','agents/scan_agent.py','llm/planner_errors.py',
        'tests/test_discovery_prompt_boundaries.py','agents/web_intel_agent.py','docs/aria-agent-intelligence-evaluation.md',
        'docs/aria-supervised-lab-run-card.md','docs/aria-8-5-operational-validation-program.md')]
    for name, validation in validations.items():
        provenance_paths += [EVIDENCE/name/path for path in validation['sha256']]
    matrix = {'schema': 'aria.operational.acceptance.v1', 'generated_at': datetime.now(timezone.utc).isoformat(),
        'goal_complete': completion_claim(reqs,duration_status,live['status'],owner_decision),
        'engineering_audit': {'status': next(r['status'] for r in reqs if r['requirement_id']=='P09-01'),
            'disposition': 'CLOSED_WITH_OWNER_DEFERRAL' if next(r['status'] for r in reqs
                if r['requirement_id']=='P09-01')=='VERIFIED' else 'IN_PROGRESS',
            'scope':'Original Phase00–09 engineering audit;one explicit eight-hour scheduling exception',
            'owner_deferral':owner_decision,'full_mission_complete':False},
        'tested_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        'tested_tree': 'Current full820 offline includes discovery instruction/fallback guards and supervised-gate2;historical full814,infrastructure798,actual PostgreSQL/Redis recovery2 and observer6tests remain separate. Actual-model quality uses retained earlier source lineages and real accounting;no post-correction model-quality,human reference or8/5 proof. Cycle14SQL59 and visible lab blocker-stop remain historical cohorts. No Kali deployment.',
        'regressions': regressions,
        'owner_running_build': current_owner,
        'last_verified_owner_build': current_owner,
        'controller_deployment': deployment,
        'infrastructure_recovery':read_json(EVIDENCE / 'infrastructure-ebd7dfca1e7b/summary.json'),
        'current_runtime_source_manifest':str((EVIDENCE / DISCOVERY_VALIDATION /
            'source-tested-manifest.json').relative_to(ROOT)),
        'historical_infrastructure_source_manifest':str((EVIDENCE / DEFERRAL_VALIDATION /
            'infrastructure-tested-source-manifest.json').relative_to(ROOT)),
        'agent_quality_evaluation':intelligence,
        'current_output_correction_source_manifest':str((EVIDENCE / DISCOVERY_VALIDATION /
            'source-tested-manifest.json').relative_to(ROOT)),
        'historical_original_build': read_json(EVIDENCE / 'live-build-observation.json'),
        'current_revision_observation': read_json(EVIDENCE / METADATA_VALIDATION / 'current-revision-observation.json'),
        'evidence_sha256': {str(p.relative_to(ROOT)): sha(p) for p in provenance_paths},
        'requirements': reqs, 'endurance': endurance,
        'endurance_clock_observations': {item['run']:endurance_clock_context(item['result'])
            for item in endurance+[{'run':active_name,'result':active_endurance}]},
        'active_endurance': {'run': active_name, 'checkpoint': active_endurance,
            'is_active': active_endurance['status']=='IN_PROGRESS',
            'disposition':'DEFERRED_BY_OWNER',
            'database_context': read_json(EVIDENCE / WORKER_VALIDATION / 'four-hour-database.json')},
        'interrupted_endurance': {'run':INTERRUPTED_ENDURANCE,'result':interrupted_endurance,
            'accepted_as_four_hours':False},
        'endurance_validations': validations,
        'live_bounded_acceptance': live,
        'visible_stream_acceptance': {key: stream[key] for key in ('status', 'checks', 'headless',
            'chromium_sandbox', 'source_unchanged_during_acceptance', 'server_sends', 'browser_events', 'limitations')},
        'local_worker_diagnostics': {'deployed': False, 'fixture': read_json(EVIDENCE / WORKER_VALIDATION / 'worker-runtime-fixtures.json'),
            'approval_review': str(EVIDENCE.relative_to(ROOT) / WORKER_VALIDATION / 'worker-telemetry-review.json')},
        'real_worker_baselines': {'unmodified_fixture': real_worker, 'tool_observer_fixture': tool_spans,
            'scope': 'New internal-only disposable targets; no owner database, Kali, live engagement or model'},
        'engineering_measurement_audit': baseline_audit,
        'unverified_requirements': [r['requirement_id'] for r in reqs if r['status'] != 'VERIFIED'],
        'longer_durations': duration_status,
        'operational_goal': {'hours_per_day':8,'days_per_week':5,'demonstrated':False,
            'reason':'Synthetic endurance and blocker-stop acceptance do not demonstrate repeated live operational capability.'}}
    (output / 'aria-acceptance-matrix.json').write_text(json.dumps(matrix, indent=2) + '\n')
    rows = metric_rows(benchmark, endurance, visible, stream,
        {'run':active_name,'result':active_endurance}
        if active_name not in [item['run'] for item in endurance] else None,intelligence)
    with (output / 'aria-performance-metrics.csv').open('w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    sections = []
    def section(title, body):
        sections.append('<section><h2>' + escape(title) + '</h2>' + body + '</section>')
    assessment = ('ENGINEERING AUDIT CLOSED WITH OWNER DEFERRAL · Eight-hour test DEFERRED_BY_OWNER. '
        'Roadmap incomplete;operational capability remains unproven.'
        if matrix['engineering_audit']['status']=='VERIFIED'
        else 'MISSION INCOMPLETE · Engineering audit checkpoint with explicit eight-hour owner deferral. Operational capability remains unproven.')
    outstanding = ', '.join(matrix['unverified_requirements']) or 'None under the recorded bounded acceptance criteria'
    section('Executive assessment', '<p class="alert">'+escape(assessment)+'</p><p>Observable mission state, strict model contracts, authorization, coordination, persistence recovery and dashboard behavior have retained evidence. Outstanding or deferred roadmap requirements: '+escape(outstanding)+'.</p><p>The owner accepts verified4h synthetic active-time endurance and explicitly defers8h to final operational validation(P14-02). The historical partial8h attempt remains CANCELLED;no deferred result is passed. The Phase09 engineering audit may close with this disclosed exception while the full roadmap remains incomplete.</p><p>Owner controller <code>'+escape(current_owner['build'])+'</code> is observed after the current host boot with existing Fedora PostgreSQL/Redis configuration. Historical API-only restart evidence preserved dependency PIDs/start times and80worker jobs/95model attempts. Current output-correction deployment preserved80jobs/103attempts,all terminal;the additional8attempts are the separately accounted local-model trials,not replay. The prior214-restart observation is explained by clean host shutdown,missing boot dependency startup and an ineffective rate-limit window; required cleanup failure was reproduced and corrected. Local Kali telemetry remains undeployed.</p><p>Visible laboratory acceptance is '+escape(live['status'])+' for the unchanged objective/limit/blocker-stop criterion. The actual owner workflow stopped on model_budget_denied with zero new model attempts,jobs or approvals. The discovery objective remains unsatisfied. Synthetic endurance never establishes successful live discovery or the8hours/day,5days/week operational goal.</p>')
    regression_text = (f"{regressions['offline']['tests']} Python tests /{regressions['offline']['unittest_seconds']:.3f}s; "
        f"retained SQL{regressions['sql']['tests']} /{regressions['sql']['unittest_seconds']:.3f}s; "
        f"historical worker SQL{regressions['worker_sql']['tests']} /{regressions['worker_sql']['unittest_seconds']:.3f}s")
    section('Revision and evidence', '<p>Git HEAD: <code>'+matrix['tested_head']+'</code>; branch autonoms_pentesters; uncommitted changes preserved. Current code has cycle26 full820 source provenance including discovery instruction/fallback guards and supervised-gate2. Historical intelligence-v2 full814,cycle21 infrastructure798/recovery2/observer6 and cycle14SQL59/graphical evidence remain separate cohorts. No model-quality improvement is measured after the discovery prompt correction. Earlier worker/container,synthetic graphical and stream cohorts retain their own source manifests and clocks. The current controller startup fingerprint excludes frontend/worker assets and is unsigned; it is not a signed loaded-source attestation. Initial owner patches,failed experiments and exact logs remain retained.</p><p>Regression: <strong>'+escape(regression_text)+'</strong>. Original SQL59 run failed4checks plus1error because a fixed simulated Monday had passed the wall clock; a fixture-only clock correction passed the same59assertions in a new database. Historical cycle13 offline757 and actual-container cases remain separate. Graphical blocker-stop uses the real owner deployment; earlier8-check synthetic UI and5-check passive stream evidence remain separate.</p>')
    revision = matrix['current_revision_observation']
    revision_relation = ('Remote observation unavailable.' if revision['remote_head'] is None else 'Local and remote revisions matched at this observation.' if revision['remote_matches_local_head'] else 'Local and remote revisions differ at this observation.')
    sections[-1] = sections[-1].replace('</section>', '<p>Read-only revision observation at '+escape(revision['observed_at'])+': local HEAD <code>'+escape(revision['head'])+'</code>; origin branch HEAD <code>'+escape(revision.get('remote_head') or 'Unavailable')+'</code>. Local ahead commits: '+escape(str(revision.get('local_ahead_commits','Unavailable')))+'; remote ahead commits: '+escape(str(revision.get('remote_ahead_commits','Unavailable')))+'. '+escape(revision_relation)+' The observed owner build matched the unsigned source fingerprint; no remote publish occurred.</p></section>')
    section('Actual architecture', '<div class="flow"><b>Browser objective / controls</b> → <b>Owned FastAPI routes</b> → <b>AutonomousEngine / campaign supervisor</b><br>↘ strict planner / review ↔ model pool → conservative attempt ledger<br>↘ TeamCoordinator → existing six specialists → attributed AgentResult → owner review<br>↘ exact command authorization → durable WorkerJobs → independent isolated worker policy<br>↘ PostgreSQL checkpoints / task events / research / encrypted review journal → read-only mission projection → REST / sequenced WebSocket → browser</div><p>These are source call paths, with component evidence boundaries documented in <a href="../docs/operational-reliability-baseline.md">architecture inventory</a> and <a href="../docs/operational-reliability-coordination.md">coordination inventory</a>. Specialist analysis proposes; it does not grant execution or verification.</p>')
    section('Workflow states', '<div class="flow">planning → waiting for exact approval → executing → durable observation → strict review → bounded completion<br>↘ blocked / budget exhausted / paused / cancellation pending / cancelled / failed (exact reasons)<br>bounded completion + unfinished durable tasks → work pending; missing completion evidence or ledger → blocked<br>unknown prior outcome → reconcile; no automatic sensitive replay</div><p>Phase position does not prove phase completion. Discovery can legitimately stop after the two required observations; optional follow-up hypotheses do not require more operations. Cancelled and failed work remain visible.</p>')
    defects = [
      ('Clean host shutdown followed by repeated API startup with stopped PostgreSQL/Redis', 'Separate ordered dependency unit,read-only readiness and5attempts/300s; actual API restart preserves container helpers', 'deploy/lab templates; wait_dependencies.py; outage/recovery/restart evidence'),
      ('Database reconciliation failure skipped pending worker cleanup and connection closure', 'Attempt every cleanup stage,preserve cancellation,and fail explicitly on required failures', 'api/main.py; test_shutdown_cleanup.py; retained failing lifespan reproduction'),
      ('Fixed synthetic Monday expired while SQL creation used wall clock', 'One scoped fixture clock for campaign creation/lease checks; production scheduling unchanged', 'tests/endurance_harness.py; test_simulation_clock.py; failed59 and passing59 SQL cohorts'),
      ('Optional Redis failure escaped after a successful SQL commit; stale SQL pool failed after PostgreSQL restart', 'Bounded optional cache operations with generation invalidation; database pre-ping without replaying uncertain statements', 'session_manager.py; database_models.py; isolated infrastructure failure/recovery2tests'),
      ('Partially rejected model plan retained execute-all instructions', 'Explain only validated proposals and disclose rejected suggestions before approval', 'base_agent.py; test_agent_public_rejections.py; retained before/after evidence'),
      ('Discovery role/skill prompts contradicted narrow objectives and worker capabilities; incomplete JSON created fallback plans', 'Preserve server objective/profile limits and block incomplete plans without fallback actions;model improvement still unmeasured', 'recon_agent.py; scan_agent.py; test_discovery_prompt_boundaries.py;cycle26 before/after/full820'),
      ('Completed observations skipped review on restart / last-step limit', 'Shared _finalize_observations before dispatch budget; exact reviewed receipts', 'agents/autonomous_engine.py; mission_continuity/checkpoint tests'),
      ('Accepted review projected twice after crash; changed model response conflicted', 'Encrypted exact-response journal; unknown outcomes block without another query', 'memory/investigation_reviews.py; real child-process SQL recovery'),
      ('Concurrent snapshots regressed terminal/accounting state or rebound a run', 'Row locks, monotonic revision/generation, identity and terminal fences', 'memory/autonomous_runs.py; three original SQL failures retained'),
      ('Full event queue lost terminal transition; stale browser run changed current status', 'Latest event plus gap flag; run/session/sequence filtering and read-only reconciliation', 'agents/autonomous_engine.py; app.js; event/Node regressions'),
      ('Missing native counts invented zero/partial usage; timeout/denial reasons hidden', 'Strict token components, unavailable measurements, closed safe failure codes', 'llm/local_client.py; planner_errors.py; blockers.py; failure matrices'),
      ('Cleanup persistence failure leaked engagement accounting context', 'Unconditional context reset even after persistence failure', 'agents/autonomous_engine.py; continuity fault injection'),
      ('Specialists received stale research despite planner freshness checks', 'Shared scope/model/evidence provenance filter; omitted-stale counts', 'memory/research.py; team_coordinator.py; old-HEAD reproduction'),
      ('Unknown readiness displayed0%; phase index implied completion', 'Unavailable readiness with no numeric ARIA value; no inferred prior completion', 'dashboard.js; Node and visible acceptance'),
      ('Stop during approval recorded human rejection while cancellation I/O remained pending', 'Stop/pause takes priority before human-rejection processing; completed evidence retained', 'agents/autonomous_engine.py; deterministic concurrent mission_continuity regression'),
      ('Expired proposal left the run indefinitely awaiting an impossible approval', 'Wait/projection use original durable deadline; exact blocker with no decision, dispatch or replan', 'agents/autonomous_engine.py; test_approval_expiry.py; real SQL late-approval denial'),
      ('Planner proposed TCP ports outside the worker ceiling', 'Strict metadata compatibility checked before proposal and centrally before submit; final authorization retained', 'worker/app.py; orchestrator/worker_preflight.py; test_worker_preflight.py'),
      ('Failed refresh retained stale successful state; duplicate deliveries inflated timeline', 'Unavailable state replaces failed read; stable event identities deduplicate sources', 'dashboard.js; dashboard_refresh.cjs'),
      ('Small charges rounded away; raw hypothesis labels implied verified evidence', 'Precise micro-USD/provider receipt display; fresh independent verification required', 'dashboard.js; Node/visible research checks'),
    ]
    section('Original defects, causes and corrections', table(['Before / reproduced cause', 'After', 'Implementation / test reference'], [[escape(v) for v in r] for r in defects]) + '<p>Historical tariff/approval, incompatible-port cancellation, invalid alternative_explanforations review, two-command completion, three hypotheses and timing observations are reconciled separately in the baseline document. They are not reused as fresh acceptance evidence.</p>')
    component_rows = [
      ('Mission / checkpoint / events', 'Implemented and verified synthetic contracts', regression_text + '; visible objective/blocker/reload; approval/cancel/expiry', 'Per-operation / batch fixture baselines; API/projection durations', 'One Uvicorn process; current unsigned controller build is recorded in owner_running_build', 'High for defined contracts'),
      ('LLM / routing / budgets', 'Strict contracts and containment verified', 'Four-provider fault matrix, unknown usage, encrypted journal and hard crash', 'Four client boundaries, queue/context, strict review and conservative attempt ledger', 'No model reasoning-quality claim; physical HTTP is distinct from provider-confirmed inference', 'High containment; provider performance evidence limited'),
      ('Team / research / persistence', 'Existing roles exercised; provenance/currentness enforced', 'Actual six-role entry points, dependency/duplicate/cancel tests', 'Messages/bytes/SQL/context counters', 'Common fixture response does not prove independent expertise; large ledgers unprofiled', 'High for scoped fixture contracts'),
      ('Execution / isolated worker', 'Existing authorization boundaries retained; compatibility preflight added', 'Scope, one-use approval, expiry, cancellation, admission and two real local container fixture cases', 'Local CLI/container phase and in-container subprocess wall/child CPU; owner/Kali timing unavailable', 'Kali telemetry deployment question pending; local rollback mechanics tested with synthetic callbacks', 'High for scoped contracts; live discovery completion remains unverified'),
      ('Frontend / graphical operation', 'Operational dashboard contracts verified', 'Visible sandboxed Chromium, real login/start/reload/dashboard/catalog; stale refresh and duplicate events', 'Correlated HTTP headers, DOM update, frame opportunity and navigation', 'Synthetic acceptance and actual owner blocker-stop separate; frame opportunity is not actual pixel presentation', 'High for listed controls'),
    ]
    section('Component assessment', table(['Component', 'Implementation maturity', 'Correctness evidence', 'Performance evidence', 'Operational limitations', 'Confidence'], [[escape(v) for v in r] for r in component_rows]))
    quality_rows=[]
    for dimension,summary in scores['dimensions'].items():
        measured=(str(summary['passed'])+'/'+str(summary['assessed'])) if summary['assessed'] else 'Unavailable:0assessed'
        quality_rows.append([escape(dimension),measured,str(summary['unassessed']),
            'Engineering-agent rubric;not an independent human assessment'])
    case_rows=[]
    for case in composite['cases']:
        errors=[r.get('error') for r in case.get('provider_records',[]) if r.get('error')]
        state=('RESPONSE COLLECTED' if case['actual_model_success'] else
               'NOT_TESTED_BUDGET' if 'model_budget_exhausted' in errors else 'TIMEOUT / QUALITY UNAVAILABLE')
        case_rows.append([escape(case['case_id']),escape(case.get('actual_agent_name',case['role'])),
            escape(state),f"{case['wall_seconds']:.3f}",
            escape(case.get('public_result',{}).get('agent_result',{}).get('status','Unavailable'))])
    section('Agent intelligence and operational validation roadmap',
        '<p>Frozen8-role controlled inputs use actual admitted local-model calls and unchanged owner accounting. '
        'Configured qwen3:4b-instruct timed out on its first request;no quality score. Separate qwen3.5:0.8b '
        'cohorts yielded6usable answers,a planner timeout,and a collaboration review denied before inference. '
        'Poor raw decisions and successful policy containment are different observations. No model-quality improvement '
        'is inferred from later software corrections to misleading partial-rejection summaries or discovery prompts/fallbacks.</p>'
        +table(['Dimension','Passed / assessed checks','Unassessed checks','Evidence scope'],quality_rows)
        +table(['Case','Actual existing agent','Model observation','Case wall seconds','Contained public status'],case_rows)
        +'<p>Latency includes context,ownership,accounting and provider work;heterogeneous single-case role timings '
        'do not establish isolated inference time or a performance comparison. Native usage for two timeouts remains '
        'unavailable and conservatively charged. At the evaluation checkpoint,the existing ledger is15calls/'
        '196074reserved tokens;3926remaining is below the minimum8192reservation. Original20/200000/$1 '
        'limits and old reservations are unchanged;no new paid-provider call or target dispatch occurred.</p>'
        '<p>Independent senior comparison is BLOCKED by explicit owner instruction;the reviewer packets are retained '
        'and AI grading is not substituted for human references. The one-action supervised HEAD proposal expired '
        'without owner approval,native expiry denial403 was verified,and zero target jobs were submitted. '
        'The final8/5 program is prepared for owner review;the8h test remains DEFERRED_BY_OWNER. '
        'Actual model quality,independent assessment and operational execution remain limited or blocked;'
        'full8/5 capability is unproven.</p>')
    section('Twelve-operation engineering benchmark', '<p>Real PostgreSQL and authorization/decision paths; deterministic model/owner and worker runtime fixtures. All twelve expected lifecycle records accounted for. <strong>No lost, duplicate or unauthorized dispatch</strong>; twelve preapproval denials, one duplicate authorization denial, one dependency denial and two foreign-owner denials. Nine tasks completed, two cancelled and one blocked as injected. The workload remains blocked; benchmark pass does not relabel it mission-completed.</p>' + table(['Operation', 'Responsible role', 'Expected / recorded state', 'Lifecycle ms'], [[str(o['number']), escape(o['role']), escape(o['expected_state'] + ' / ' + o['state']), f"{o['lifecycle_wall_ms']:.2f}"] for o in benchmark['operations']]))
    e_rows = []
    seconds = lambda value: 'Unavailable' if value is None else f'{value:.3f}s'
    for item in endurance:
        r, s = item['result'], item['statistics']['batch_wall_seconds']
        clock = endurance_clock_context(r)
        e_rows.append([str(r['requested_seconds']) + 's', '<span class="status-value">'+escape(r['status'])+'</span>', f"{r['elapsed_seconds']:.3f}s", seconds(clock['utc_timestamp_span_seconds']), seconds(clock['suspended_seconds']), str(r['recorded_operations']), str(r['availability_failures']), str(r.get('rss_growth_kb')), f"n={s['n']}; mean={s['mean']:.3f}; median={s['median']:.3f}; max={s['maximum']:.3f}; p95={s['p95']:.3f}" if s['p95'] is not None else 'Insufficient samples for p95'])
    if active_name not in [item['run'] for item in endurance]:
        partial_clock = endurance_clock_context(active_endurance)
        e_rows.append([str(active_endurance['requested_seconds'])+'s','<span class="status-value">'+escape(active_endurance['status'])+'</span>',
            f"{active_endurance['elapsed_seconds']:.3f}s",seconds(partial_clock['utc_timestamp_span_seconds'])
                if active_endurance.get('finished_at') else 'Not finished',
            seconds(active_endurance.get('suspended_seconds')),str(active_endurance['recorded_operations']),
            str(active_endurance['availability_failures']),str(active_endurance.get('rss_growth_kb')),
            'Historical partial attempt;8h DEFERRED_BY_OWNER' if active_endurance['status']=='CANCELLED'
                else 'Active checkpoint; duration not verified'])
    old_clock = endurance_clock_context(interrupted_endurance)
    e_rows.append(['14400s original attempt','<span class="status-value">CANCELLED</span>',f"{interrupted_endurance['elapsed_seconds']:.3f}s",
        seconds(old_clock['utc_timestamp_span_seconds']),seconds(old_clock['suspended_seconds']),
        str(interrupted_endurance['recorded_operations']),str(interrupted_endurance['availability_failures']),
        str(interrupted_endurance.get('rss_growth_kb')),'Host shutdown; not accepted as4h'])
    duration_text = '; '.join(key+': '+value for key,value in duration_status.items())
    section('Progressive endurance and performance', table(['Requested','Actual status','Active monotonic time','UTC timestamp span','Measured suspended time','Operations','Readiness failures','RSS growth KiB','Batch seconds (nearest-rank p95)'],e_rows)
        + '<p>Completed duration states: '+escape(duration_text)+'. These are synthetic active-time cohorts. ASGI readiness and disposable SQL only; no actual model inference or security tool/container. Each run keeps its source manifest; later edits do not change its provenance. Original4h cancellation during host shutdown remains retained. The historical1h cohort has one unavailable database diagnostic despite successful readiness. The historical15m peak_rss field is OS ru_maxrss, not a sampled RSS maximum.</p><p>CLOCK_MONOTONIC excludes host sleep. One recorded host-suspend interval during the replacement4h cohort was11912.154seconds; such intervals are excluded, not accepted as endurance or availability. The completed2h cohort spans10920.524UTC seconds versus7200.001active seconds; its3720.523second difference is unattributed because boottime diagnostics were not recorded. Do not infer sleep from an old UTC/monotonic difference, or continuous service availability from active-time samples. These results do not demonstrate uninterrupted8h operation or8hours/day5days/week capability.</p><p>Mean,median,maximum and p95(only n≥20,nearest rank) stay separate by cohort in JSON/CSV. Resource use,failure/retry and conservative token/cost accounting are separate. Existing10s readiness/512MiB headroom thresholds and acceptance criteria are unchanged. Proposed future alerts remain proposals.</p>')
    layers = [
      ('1. API handling', 'Server monotonic handler_ms; X-Request-ID; browser header interval', 'Response headers boundary excludes body/network/rendering; different routes not causal comparators'),
      ('2. Mission-state processing', 'Separate run load, owned task-ledger load and mission projection', 'Admin-denied ledger load is unavailable, never zero'),
      ('3. LLM request', 'Four clients: construction, HTTP attempt, parsing and total; strict-review validation separate', 'HTTP elapsed is not isolated inference time; cleanup measured separately'),
      ('4. Authorization', 'Per-operation proposal and decision wall-duration fixtures; 12 preapproval denials', 'Boundaries include SQL; not isolated cryptographic/policy CPU'),
      ('5. Human approval', 'Monotonic pending gate, accepted decision, polling and release fields; original durable deadline', 'Expired live action has no accepted-decision duration; not pure human deliberation'),
      ('6. Worker communication', 'Local HTTP/body/response-close, JSON decode and total client; request/job/session IDs', 'Offline transport fixtures; exchange includes worker work. Isolated wire latency and deployed baseline unavailable'),
      ('7. Queue waiting', 'Pool queue/context separate; real local worker mutex waiting/held observations', 'No comparable contention p95; current owner admission latency unavailable'),
      ('8. Container lifecycle', 'Real rootless Podman/private-target create/start/inspect/output/stop durations; per-stage summaries', 'CLI/backend overhead included; hardware/topology differs from Kali. Small samples, p95 unavailable'),
      ('9. Tool execution', 'Inside unprivileged fixture: validated curl/Nmap wall span and OS waited-child user/system CPU', 'One sample per tool; wall includes subprocess creation/output collection. No actual Kali/provider timing claim'),
      ('10. Result processing', 'Generic parser and strict review validation/preparation/projection measured separately', 'Offline parsing cohorts do not establish paid-provider latency'),
      ('11. Database persistence', 'SQL statement count/bytes/wall timing; review projection persistence', 'Statement durations and encompassing requests overlap; do not add them'),
      ('12. WebSocket delivery', 'Real isolated Uvicorn and graphical Chromium:4 correlated ordered events, per-stream ASGI send and browser-local microtask/frame intervals', 'Historical isolated stream cohort; no fresh owner WebSocket end-to-end latency. Observer microtask does not prove application handler completion'),
      ('13. Browser rendering', 'Real DOM update and two-frame opportunity; bounded correlated headers', 'Frame opportunity is not proof of presentation to the physical display'),
    ]
    runtime_rows = [[escape(stage), str(s['n']), f"{s['mean']:.3f}", f"{s['median']:.3f}",
        f"{s['maximum']:.3f}", 'Unavailable'] for stage,s in baseline_audit['runtime_stage_statistics'].items()]
    tool_rows = [[escape(s['tool']), f"{s['tool_wall_ms']:.6f}", f"{s['child_user_cpu_ms']:.3f}",
        f"{s['child_system_cpu_ms']:.3f}", '1 / unavailable'] for s in tool_spans['samples']]
    section('Measurement boundaries across thirteen layers', table(['Layer', 'Measured contract / correlation', 'Limit'], [[escape(v) for v in row] for row in layers])
        + '<p>No missing measurement is serialized as zero. Correlation uses session/run/action/job, logical-model-request/attempt and server request IDs according to ownership; browser and machine clocks keep their own domains.</p>'
        + '<h3>Real local container fixture baseline (ms)</h3>'
        + table(['Runtime call','n','Mean','Median','Maximum','p95'], runtime_rows)
        + '<h3>Separate unprivileged in-container tool observer (ms)</h3>'
        + table(['Tool','Wall span','Child user CPU','Child system CPU','n / p95'], tool_rows)
        + '<p>New internal HTTP fixtures, rootless Podman and an immutable cached image; no owner DB, Kali, live target or provider. Runtime calls include CLI/backend work. Tool wall spans include subprocess creation/output collection; CPU is OS-reported waited-child usage. These are separate cohorts; no cross-clock subtraction, causal speedup, actual Kali calibration or aggregate latency claim. Source snapshots were observed after testing and are unsigned.</p>')
    screenshots = ''
    for name in visible['screenshots']:
        p = EVIDENCE / VISIBLE_RUN / name
        screenshots += '<details><summary>' + escape(name) + '</summary><img loading="lazy" alt="Sanitized visible Chromium synthetic acceptance: ' + escape(name) + '" src="data:image/png;base64,' + base64.b64encode(p.read_bytes()).decode() + '"></details>'
    stream_picture = base64.b64encode((EVIDENCE / STREAM_RUN / 'stream-workspace.png').read_bytes()).decode()
    screenshots += '<details><summary>Passive synthetic stream</summary><img alt="Four passive fixture events; discovery not executed" src="data:image/png;base64,'+stream_picture+'"></details>'
    section('Visible Chromium evidence', '<p>Fedora graphical Chromium156.0.8078.4, headless=False, chromium_sandbox=True. Real login, session selection, start, reload and dashboard navigation; no request-API substitution or route mock. No credential-bearing trace or storage-state capture. Source unchanged during acceptance. Records are synthetic; worker deliberately unavailable. Separate real Uvicorn/browser stream fixture delivered4 ordered labelled passive events through the ordinary authenticated route; no engine loop, authorization proposal or worker/model operation. Server ASGI and browser microtask/frame timings keep separate clocks, n=4 and no p95. This synthetic cohort is separate from the actual owner blocker-stop acceptance below.</p>' + screenshots)
    owner_panels = ''
    for name in ('owner-terminal-objective.png','owner-terminal-blocker.png','owner-terminal-budget.png'):
        picture = base64.b64encode((EVIDENCE/FINAL_VALIDATION/name).read_bytes()).decode()
        owner_panels += '<details><summary>'+escape(name)+'</summary><img alt="Actual owner terminal panel; discovery blocked, no new model/tool call" src="data:image/png;base64,'+picture+'"></details>'
    section('Separate visible laboratory acceptance', '<p>Actual owner deployment,headless=False and chromium_sandbox=True. Normal graphical login,session selection,start,reload,dashboard and evidence navigation; no request-API substitution. An immediate graphical start response returned a new blocked run,then the normal UI loaded its exact objective and model_budget_denied terminal. Later read-only durable evidence matches the same identity,reason and objective. No WebSocket terminal was emitted because admission stopped before the loop; no event is invented. Budget before/after remains7calls/99972reservedtokens;zero new provider attempts,jobs,authorizations or decisions.</p><p>This satisfies only the unchanged objective/limit/blocker-stop criterion. Completion=false;port-discovery and HTTP-response observations remain missing. Original expired proposal remains untouched;no pricing reapproval or automatic retry. The pre-settling immediate workspace screenshot is not current-reason proof;the settled dashboard and bound durable status are used. Current graphical captures are retained privately;the images above belong to synthetic cohorts.</p><pre>'+escape(json.dumps(live,indent=2))+'</pre>'+owner_panels)
    req_rows = []
    for r in reqs:
        links = ' '.join('<a href="../' + escape(p) + '">' + escape(p) + '</a>' for p in r['implementation_reference'] + r['test_reference'])
        req_rows.append([escape(r['requirement_id']), '<span class="' + ('pass' if r['status'] == 'VERIFIED' else 'open') + '">' + escape(r['status']) + '</span>', links, escape(r['actual_evidence']), escape(r['remaining_limitations']), '<strong>'+escape(r['confidence'])+'</strong><p>'+escape(r['confidence_basis'])+'</p>'])
    section('Requirement-by-requirement audit', '<p>Confidence is a qualitative review of the stated evidence scope, not an operational readiness score or independent attestation.</p>'+table(['ID', 'Status', 'Implementation / tests', 'Actual evidence', 'Remaining limitations', 'Confidence and evidence scope'], req_rows))
    section('Remaining blockers and recommendations', '<p>Operational8hours/day,5days/week capability remains unproven. No paid-provider reliability,successful current live discovery or five-day schedule has been demonstrated by synthetic duration tests.</p><ol>' + ''.join('<li><strong>' + escape(rid) + '</strong>: ' + escape(OPEN_LIMITATIONS[rid]) + '</li>' for rid in matrix['unverified_requirements']) + '</ol><p>Full mission acceptance requires every recorded mandatory requirement VERIFIED. The explicit owner decision permits only the Phase09 engineering audit to close with its disclosed8h deferral. Deferred,blocked and untested durations never pass;new phases10–14 remain visible. Broader operational capability requires separate authorized live evidence.</p>')
    css = 'body{overflow-wrap:anywhere;margin:0;background:#0b1220;color:#e4ebf5;font:16px/1.6 system-ui,sans-serif}header,main{max-width:1450px;margin:auto;padding:28px}header{border-bottom:1px solid #34445d}h1{font-size:42px;line-height:1.2}h2{color:#80dfdf}section{margin:28px 0;padding:24px;background:#121e30;border:1px solid #32435c;border-radius:12px}a{color:#b4c8ff;overflow-wrap:anywhere}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:14px}td,th{padding:12px;text-align:left;vertical-align:top;border-bottom:1px solid #354660}th{color:#82e2df;overflow-wrap:normal}.status-value,.pass,.open{white-space:nowrap}.alert,.open{color:#ffc69c}.pass{color:#89e1b3}.flow{overflow-wrap:anywhere;padding:22px;border-left:4px solid #80dfdf;background:#0c1728;line-height:2}pre{white-space:pre-wrap;overflow-wrap:anywhere}img{max-width:100%;height:auto}details{padding:14px;border:1px solid #34445d;margin:12px 0}summary{cursor:pointer}code{overflow-wrap:anywhere}li{margin:12px 0}@media(max-width:700px){header,main{padding:12px}section{padding:14px}h1{font-size:30px}}'
    html = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ARIA operational reliability audit</title><style>' + css + '</style><header><p>ARIA · Engineering reliability / evidence checkpoint</p><h1>Operational reliability audit</h1><p>' + matrix['generated_at'] + ' · '+escape(assessment)+' · No global readiness percentage</p></header><main>' + ''.join(sections) + '</main></html>'
    (output / 'aria-operational-reliability-audit.html').write_text(html)
    print(json.dumps({'requirements': len(reqs), 'unverified': matrix['unverified_requirements'], 'goal_complete': matrix['goal_complete'], 'metric_rows': len(rows), 'html_bytes': len(html.encode())}))


if __name__ == '__main__':
    main()
