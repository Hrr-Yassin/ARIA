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
SQL_RUN = 'sql-27879ded114a'
VISIBLE_RUN = 'visible-80581393fe82'
ENDURANCE_RUNS = ['endurance-3d8e73d8ef16', 'endurance-d31a0e3f21b1', 'endurance-d1aef3ed96de']
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
 'P05-01': ('memory/execution_authorization.py orchestrator/blockers.py agents/autonomous_engine.py', 'tests/test_execution.py tests/test_authorization_store.py tests/test_model_response_failures.py'),
 'P06-01': ('llm/request_metrics.py integration/reliability_workload.py integration/reliability_endurance.py', 'tests/test_request_metrics.py integration/test_reliability_workload_postgres.py'),
 'P07-01': ('web/static/scripts/app.js web/static/scripts/dashboard.js', 'tests/frontend_contracts.cjs tests/dashboard_contracts.cjs integration/reliability_visible.py'),
 'P07-02': ('integration/reliability_visible.py', 'integration/reliability_visible.py'),
 'P08-01': ('tests integration', 'tests/frontend_contracts.cjs tests/dashboard_contracts.cjs tests/team_budget_button.cjs'),
 'P08-02': ('integration/reliability_workload.py', 'integration/test_reliability_workload_postgres.py'),
 'P08-03': ('integration/aria_auto_replan_chromium.py', ''),
 'P08-04': ('integration/reliability_endurance.py', 'integration/reliability_endurance.py'),
 'P09-01': ('integration/reliability_audit.py', 'GOALS.md PLANS.md PROGRESS.md'),
}
OPEN_LIMITATIONS = {
 'P02-03': 'Accounting/timing contracts verified with offline transport fixtures. No paid-provider latency/availability claim; actual charges remain unavailable unless returned by the provider. Full API/queue/WS/browser integration remains P06.',
 'P05-01': 'Deployed worker capabilities do not advertise independent port ceiling; pre-admission command compatibility remains unverified. Existing authorization/isolation/expiry/budget gates remain intact.',
 'P06-01': 'Queue, container, real tool, WebSocket delivery and complete browser data-render timing are unavailable; thirteen-layer correlation is incomplete. Proposed thresholds are not acceptance claims.',
 'P07-01': 'Graphical core controls verified on fixtures; complete operational/performance panel coverage and live-deployment verification remain open.',
 'P08-01': 'Python713 and current scoped SQL10 plus dedicated accounting benchmark pass; prior combined SQL42 and frontend checks also pass. Final regression must follow remaining changes with exact source provenance.',
 'P08-03': 'Fresh visible laboratory workflow has not been performed. Original backend is still the initial owner build; current provider approval/budget must be verified and required human decisions preserved.',
 'P08-04': '15m and30m verified in ASGI/disposable SQL fixture cohorts. One-hour run pending; 2h/4h/8h NOT_TESTED. No deployed-network/container/browser endurance claim.',
 'P09-01': 'This is a checkpoint audit. Mandatory engineering requirements remain unmet; final completion audit cannot pass yet.',
}


def read_json(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stats(values):
    values = sorted(v for v in values if isinstance(v, (int, float)) and math.isfinite(v))
    return ({'n': len(values), 'mean': statistics.mean(values), 'median': statistics.median(values),
             'maximum': max(values), 'p95': values[math.ceil(.95 * len(values)) - 1] if len(values) >= 20 else None}
            if values else {'n': 0, 'mean': None, 'median': None, 'maximum': None, 'p95': None})


def requirements():
    result = []
    for block in re.split(r'(?=^### P)', (ROOT / 'PLANS.md').read_text(), flags=re.M)[1:]:
        rid, title = re.match(r'### (P\d+-\d+): (.*)', block).groups()
        def field(name):
            match = re.search(r'^- ' + re.escape(name) + r': (.*)', block, re.M)
            return match.group(1) if match else ''
        implementation, tests = REFERENCES[rid]
        refs = implementation.split() + tests.split()
        for ref in refs:
            if not (ROOT / ref).exists():
                raise ValueError('Missing audit reference: ' + ref)
        result.append({'requirement_id': rid, 'title': title, 'status': field('Status'),
            'acceptance_criteria': field('Acceptance criteria'),
            'implementation_reference': implementation.split(), 'test_reference': tests.split(),
            'actual_evidence': field('Evidence / limitations'),
            'remaining_limitations': OPEN_LIMITATIONS.get(rid,
                'Verified for the defined synthetic/source contract. Production-scale and fresh live acceptance are separate requirements.')})
    return result


def metric_rows(benchmark, endurance, visible):
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
                    'seconds' if metric.startswith('batch') else 'ms', f"n={summary['n']}; p95 nearest rank only for n>=20")
    for key, value in (visible.get('navigation_timings_ms') or {}).items():
        row(VISIBLE_RUN, 'visible_chromium_navigation', key, value, 'ms', 'Single browser-clock navigation sample, not complete asynchronous data rendering')
    for layer in ('api_request_handling_full', 'autonomous_mission_state_processing', 'llm_provider_attempt_real',
                  'human_approval_wait_new', 'queue_wait', 'container_lifecycle', 'real_tool_execution',
                  'live_review_validation_not_run', 'websocket_delivery', 'browser_async_data_render'):
        row('current_audit', 'missing_layer', layer, None, 'ms', 'Not measured; no zero or cross-machine clock subtraction inferred')
    return rows


def table(headers, rows):
    return '<div class="scroll"><table><thead><tr>' + ''.join('<th>' + escape(h) + '</th>' for h in headers) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td>' + str(v) + '</td>' for v in r) + '</tr>' for r in rows) + '</tbody></table></div>'


def main():
    output = ROOT / 'reports'
    output.mkdir(exist_ok=True)
    benchmark = read_json(EVIDENCE / SQL_RUN / 'twelve-operation-benchmark.json')
    visible = read_json(EVIDENCE / VISIBLE_RUN / 'result.json')
    endurance = []
    for name in ENDURANCE_RUNS:
        path = EVIDENCE / name
        result = read_json(path / ('result.json' if (path / 'result.json').exists() else 'checkpoint.json'))
        batches = [json.loads(line)['wall_seconds'] for line in (path / 'batches.jsonl').read_text().splitlines()]
        samples = [json.loads(line) for line in (path / 'samples.jsonl').read_text().splitlines()]
        endurance.append({'run': name, 'result': result, 'statistics': {
            'batch_wall_seconds': stats(batches), 'readiness_wall_ms': stats([s.get('api_readiness_wall_ms') for s in samples])}})
    reqs = requirements()
    provenance_paths = [EVIDENCE / 'cycle8-source-manifest.json', EVIDENCE / SQL_RUN / 'tests.log',
        EVIDENCE / 'sql-99a74b4f9983/tests.log', EVIDENCE / 'sql-17b978e92971/tests.log',
        EVIDENCE / 'python-cycle8.log', EVIDENCE / VISIBLE_RUN / 'result.json', ROOT / 'GOALS.md', ROOT / 'PLANS.md']
    matrix = {'schema': 'aria.operational.acceptance.v1', 'generated_at': datetime.now(timezone.utc).isoformat(),
        'goal_complete': all(r['status'] == 'VERIFIED' for r in reqs),
        'tested_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        'tested_tree': 'HEAD plus preserved owner and reliability changes; per-run manifests are authoritative',
        'owner_running_build': read_json(EVIDENCE / 'live-build-observation.json'),
        'evidence_sha256': {str(p.relative_to(ROOT)): sha(p) for p in provenance_paths},
        'requirements': reqs, 'endurance': endurance,
        'unverified_requirements': [r['requirement_id'] for r in reqs if r['status'] != 'VERIFIED'],
        'longer_durations': {'2h': 'NOT_TESTED', '4h': 'NOT_TESTED', '8h': 'NOT_TESTED'}}
    (output / 'aria-acceptance-matrix.json').write_text(json.dumps(matrix, indent=2) + '\n')
    rows = metric_rows(benchmark, endurance, visible)
    with (output / 'aria-performance-metrics.csv').open('w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    sections = []
    def section(title, body):
        sections.append('<section><h2>' + escape(title) + '</h2>' + body + '</section>')
    section('Executive assessment', '<p class="alert">MISSION INCOMPLETE · Checkpoint audit. Verified contracts and fixture results do not establish global operational readiness.</p><p>Mission objectives, truthful bounded completion, strict review containment, checkpoint/event fencing, coordination and persistence recovery have reproducible evidence. Outstanding requirements: ' + escape(', '.join(matrix['unverified_requirements'])) + '.</p><p>Original owner backend build <code>e5da773393398091</code> matches HEAD plus the preserved initial corrections. New code has been tested on disposable deployments; the owner service was not restarted. No paid model call, live target operation, Kali/VM/network or privilege change occurred in this reliability program.</p>')
    section('Revision and evidence', '<p>Git HEAD: <code>' + matrix['tested_head'] + '</code>; branch autonoms_pentesters. Dirty-tree provenance is essential: HEAD alone does not identify tested bytes. Initial owner patch/hashes, source manifests and failed/passing logs are retained privately. The startup fingerprint excludes frontend/worker assets and is unsigned.</p><p>Regression: <strong>713 Python tests /35.399s; scoped SQL10 /19.924s plus dedicated accounting benchmark</strong>. Prior combined SQL42 /38.727s precedes final logical-request grouping. Frontend/dashboard/budget contracts, JavaScript syntax and whitespace checks pass. Counts are separate cohorts, not an operational readiness score.</p>')
    section('Actual architecture', '<div class="flow"><b>Browser objective / controls</b> → <b>Owned FastAPI routes</b> → <b>AutonomousEngine / campaign supervisor</b><br>↘ strict planner / review ↔ model pool → conservative attempt ledger<br>↘ TeamCoordinator → existing six specialists → attributed AgentResult → owner review<br>↘ exact command authorization → durable WorkerJobs → independent isolated worker policy<br>↘ PostgreSQL checkpoints / task events / research / encrypted review journal → read-only mission projection → REST / sequenced WebSocket → browser</div><p>These are source call paths, with component evidence boundaries documented in <a href="../docs/operational-reliability-baseline.md">architecture inventory</a> and <a href="../docs/operational-reliability-coordination.md">coordination inventory</a>. Specialist analysis proposes; it does not grant execution or verification.</p>')
    section('Workflow states', '<div class="flow">planning → waiting for exact approval → executing → durable observation → strict review → bounded completion<br>↘ blocked / budget exhausted / paused / cancellation pending / cancelled / failed (exact reasons)<br>bounded completion + unfinished durable tasks → work pending; missing completion evidence or ledger → blocked<br>unknown prior outcome → reconcile; no automatic sensitive replay</div><p>Phase position does not prove phase completion. Discovery can legitimately stop after the two required observations; optional follow-up hypotheses do not require more operations. Cancelled and failed work remain visible.</p>')
    defects = [
      ('Completed observations skipped review on restart / last-step limit', 'Shared _finalize_observations before dispatch budget; exact reviewed receipts', 'agents/autonomous_engine.py; mission_continuity/checkpoint tests'),
      ('Accepted review projected twice after crash; changed model response conflicted', 'Encrypted exact-response journal; unknown outcomes block without another query', 'memory/investigation_reviews.py; real child-process SQL recovery'),
      ('Concurrent snapshots regressed terminal/accounting state or rebound a run', 'Row locks, monotonic revision/generation, identity and terminal fences', 'memory/autonomous_runs.py; three original SQL failures retained'),
      ('Full event queue lost terminal transition; stale browser run changed current status', 'Latest event plus gap flag; run/session/sequence filtering and read-only reconciliation', 'agents/autonomous_engine.py; app.js; event/Node regressions'),
      ('Missing native counts invented zero/partial usage; timeout/denial reasons hidden', 'Strict token components, unavailable measurements, closed safe failure codes', 'llm/local_client.py; planner_errors.py; blockers.py; failure matrices'),
      ('Cleanup persistence failure leaked engagement accounting context', 'Unconditional context reset even after persistence failure', 'agents/autonomous_engine.py; continuity fault injection'),
      ('Specialists received stale research despite planner freshness checks', 'Shared scope/model/evidence provenance filter; omitted-stale counts', 'memory/research.py; team_coordinator.py; old-HEAD reproduction'),
      ('Unknown readiness displayed0%; phase index implied completion', 'Unavailable readiness with no numeric ARIA value; no inferred prior completion', 'dashboard.js; Node and visible acceptance'),
    ]
    section('Original defects, causes and corrections', table(['Before / reproduced cause', 'After', 'Implementation / test reference'], [[escape(v) for v in r] for r in defects]) + '<p>Historical tariff/approval, incompatible-port cancellation, invalid alternative_explanforations review, two-command completion, three hypotheses and timing observations are reconciled separately in the baseline document. They are not reused as fresh acceptance evidence.</p>')
    component_rows = [
      ('Mission / checkpoint / events', 'Implemented and verified synthetic contracts', 'Offline708; SQL42; visible objective/blocker/reload', 'Per-operation / batch fixture baselines', 'One Uvicorn process; no new owner deployment', 'High for defined contracts'),
      ('LLM / routing / budgets', 'Strict contracts and containment verified; timing partial', 'Fault matrix, unknown usage, encrypted journal and hard crash', 'Local/OpenRouter instrumentation; paid duration unavailable', 'No paid-provider availability/reasoning claim; caller timing incomplete', 'High containment; incomplete performance'),
      ('Team / research / persistence', 'Existing roles exercised; provenance/currentness enforced', 'Actual six-role entry points, dependency/duplicate/cancel tests', 'Messages/bytes/SQL/context counters', 'Common fixture response does not prove independent expertise; large ledgers unprofiled', 'High for scoped fixture contracts'),
      ('Execution / isolated worker', 'Existing authorization boundaries retained', 'Scope, one-use approval, cancellation and admission fixtures', 'ASGI mock worker; no container/tool timing', 'Deployed port ceiling not advertised; fresh live acceptance missing', 'High gate tests; limited live confidence'),
      ('Frontend / graphical operation', 'Core UI verified on real source-attested app', 'Visible sandboxed Chromium, real login/start/reload/dashboard', 'One navigation sample; no full data-render timing', 'Synthetic records; complete panel/live verification pending', 'High for listed controls'),
    ]
    section('Component assessment', table(['Component', 'Implementation maturity', 'Correctness evidence', 'Performance evidence', 'Operational limitations', 'Confidence'], [[escape(v) for v in r] for r in component_rows]))
    section('Twelve-operation engineering benchmark', '<p>Real PostgreSQL and authorization/decision paths; deterministic model/owner and worker runtime fixtures. All twelve expected lifecycle records accounted for. <strong>No lost, duplicate or unauthorized dispatch</strong>; twelve preapproval denials, one duplicate authorization denial, one dependency denial and two foreign-owner denials. Nine tasks completed, two cancelled and one blocked as injected. The workload remains blocked; benchmark pass does not relabel it mission-completed.</p>' + table(['Operation', 'Responsible role', 'Expected / recorded state', 'Lifecycle ms'], [[str(o['number']), escape(o['role']), escape(o['expected_state'] + ' / ' + o['state']), f"{o['lifecycle_wall_ms']:.2f}"] for o in benchmark['operations']]))
    e_rows = []
    for item in endurance:
        r, s = item['result'], item['statistics']['batch_wall_seconds']
        e_rows.append([str(r['requested_seconds']) + 's', escape(r['status']), f"{r['elapsed_seconds']:.3f}s", str(r['recorded_operations']), str(r['availability_failures']), str(r.get('rss_growth_kb')), f"n={s['n']}; mean={s['mean']:.3f}; median={s['median']:.3f}; max={s['maximum']:.3f}; p95={s['p95']:.3f}" if s['p95'] is not None else 'Insufficient samples for p95'])
    section('Progressive endurance and performance', table(['Requested', 'Actual status', 'Elapsed', 'Operations', 'Readiness failures', 'RSS growth KiB', 'Batch seconds (nearest-rank p95)'], e_rows) + '<p>ASGI readiness and disposable SQL only. Fixtures execute no actual model inference, tool or container. Unknown timings remain unavailable. Each run has its own loaded-source manifest; later edits were not loaded into an already-running process. 2h,4h,8h are NOT_TESTED. No extrapolation or causal improvement claim.</p><p>Thirteen-layer measurement inventory: API readiness, coordination, authorization/proposal, fixture worker path, parsing, SQL and navigation have scoped measurements. Real provider, human waiting, queue/container/tool, strict-review validation, WebSocket delivery and asynchronous browser data rendering still have missing layers. Cross-machine timestamps are not subtracted. Proposed future alerts: batch p95 above twice the30m baseline for the same workload, or readiness above its existing10s timeout; these are proposals, not retroactive acceptance thresholds.</p>')
    screenshots = ''
    for name in visible['screenshots']:
        p = EVIDENCE / VISIBLE_RUN / name
        screenshots += '<details><summary>' + escape(name) + '</summary><img loading="lazy" alt="Sanitized visible Chromium synthetic acceptance: ' + escape(name) + '" src="data:image/png;base64,' + base64.b64encode(p.read_bytes()).decode() + '"></details>'
    section('Visible Chromium evidence', '<p>Fedora graphical Chromium156.0.8078.4, headless=False, chromium_sandbox=True. Real login, session selection, start, reload and dashboard navigation; no request-API substitution or route mock. No credential-bearing trace or storage-state capture. Source unchanged during acceptance. Records are synthetic; worker deliberately unavailable. This does not satisfy fresh live laboratory acceptance.</p>' + screenshots)
    req_rows = []
    for r in reqs:
        links = ' '.join('<a href="../' + escape(p) + '">' + escape(p) + '</a>' for p in r['implementation_reference'] + r['test_reference'])
        req_rows.append([escape(r['requirement_id']), '<span class="' + ('pass' if r['status'] == 'VERIFIED' else 'open') + '">' + escape(r['status']) + '</span>', links, escape(r['actual_evidence']), escape(r['remaining_limitations'])])
    section('Requirement-by-requirement audit', table(['ID', 'Status', 'Implementation / tests', 'Actual evidence', 'Remaining limitations'], req_rows))
    section('Remaining blockers and recommendations', '<ol>' + ''.join('<li><strong>' + escape(rid) + '</strong>: ' + escape(OPEN_LIMITATIONS[rid]) + '</li>' for rid in matrix['unverified_requirements']) + '</ol><p>Keep the primary goal active. Finish independent authorized engineering work and audit every mandatory requirement before declaring completion. A blocked or untested requirement is not a passed requirement.</p>')
    css = 'body{margin:0;background:#0b1220;color:#e4ebf5;font:16px/1.6 system-ui,sans-serif}header,main{max-width:1450px;margin:auto;padding:28px}header{border-bottom:1px solid #34445d}h1{font-size:42px;line-height:1.2}h2{color:#80dfdf}section{margin:28px 0;padding:24px;background:#121e30;border:1px solid #32435c;border-radius:12px}a{color:#b4c8ff;overflow-wrap:anywhere}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:14px}td,th{padding:12px;text-align:left;vertical-align:top;border-bottom:1px solid #354660}th{color:#82e2df}.alert,.open{color:#ffc69c}.pass{color:#89e1b3}.flow{padding:22px;border-left:4px solid #80dfdf;background:#0c1728;line-height:2}img{max-width:100%;height:auto}details{padding:14px;border:1px solid #34445d;margin:12px 0}summary{cursor:pointer}code{overflow-wrap:anywhere}li{margin:12px 0}@media(max-width:700px){header,main{padding:12px}section{padding:14px}h1{font-size:30px}}'
    html = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ARIA operational reliability audit</title><style>' + css + '</style><header><p>ARIA · Engineering reliability / evidence checkpoint</p><h1>Operational reliability audit</h1><p>' + matrix['generated_at'] + ' · Mission incomplete · No global readiness percentage</p></header><main>' + ''.join(sections) + '</main></html>'
    (output / 'aria-operational-reliability-audit.html').write_text(html)
    print(json.dumps({'requirements': len(reqs), 'unverified': matrix['unverified_requirements'], 'goal_complete': matrix['goal_complete'], 'metric_rows': len(rows), 'html_bytes': len(html.encode())}))


if __name__ == '__main__':
    main()
