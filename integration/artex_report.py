"""Generate the ARTEX mission evaluation from retained validation results."""
from __future__ import annotations

import base64
import csv
import hashlib
import html
import json
from pathlib import Path
from statistics import median

EVIDENCE = Path('.local-lab/artex')
REPORTS = Path('reports')
METRICS = {
    'readyMs': 'ms', 'firstContentfulPaintMs': 'ms', 'domContentLoadedMs': 'ms',
    'apiRequests': 'requests', 'localTransferBytes': 'bytes', 'jsHeapBytes': 'bytes',
}


def read(path: Path) -> dict:
    if not path.is_file():
        return {}
    return json.loads(path.read_text())


def regression_summary(path: Path) -> str:
    if not path.is_file():
        return 'No regression result retained.'
    lines = path.read_text().splitlines()
    count = next((line for line in reversed(lines) if line.startswith('Ran ')), 'Test count unavailable')
    return count + ('. Result passed.' if lines and lines[-1] == 'OK' else '. Result unverified.')


def browser_summary(result: dict, compatibility: dict) -> dict:
    existing = compatibility.get('checks', [])
    return {'version': result.get('browser'), 'headless': result.get('headless'), 'checks': result.get('checks', {}),
            'uncaught_page_errors': result.get('pageErrors'), 'compatibility_total': len(existing),
            'compatibility_passed': sum(check.get('status') == 'passed' for check in existing),
            'compatibility_uncaught_errors': compatibility.get('pageErrors'),
            'index_sha256': result.get('assets', {}).get('index.html')}


def cohort_validation(stage: str, browser: dict, database: dict) -> dict:
    checks = database.get('checks', {})
    visible = checks.get('visible_database_browser', {})
    return {
        'offline_python': regression_summary(EVIDENCE / f'{stage}-regressions.log'),
        'offline_scope': 'Offline regressions excluding the four in-process vulnerability reproduction tests in tests.test_research_lab.',
        'browser': browser,
        'disposable_postgres': {'migration': database.get('migration'), 'checks': sorted(checks),
                                **{key: checks[key] for key in ('durable_har_inspection', 'durable_finding_history',
                                   'fresh_process_readback', 'durable_exploration_checkpoint', 'retained_read_timings')
                                   if key in checks},
                                'visible_browser_checks': visible.get('checks'),
                                'retained_asset_ready_ms': visible.get('retainedAssetReadyMs')},
    }


def generate() -> None:
    matrix_path = REPORTS / 'artex-integration-matrix.json'
    matrix = read(matrix_path)
    baseline = read(EVIDENCE / 'baseline/result.json')
    candidate = read(EVIDENCE / 'acceptance-browser/result.json')
    postgres = read(EVIDENCE / 'acceptance-postgres-final/postgres.json')
    compatibility = read(EVIDENCE / 'acceptance-compatibility/result.json')
    followup = read(EVIDENCE / 'inspection-browser/result.json')
    followup_compatibility = read(EVIDENCE / 'inspection-compatibility/result.json')
    followup_postgres = read(EVIDENCE / 'inspection-postgres/postgres.json')
    followup_db = followup_postgres.get('checks', {})
    har = followup_db.get('durable_har_inspection', {})
    checkpoint = read(EVIDENCE / 'checkpoint-browser/result.json')
    checkpoint_compatibility = read(EVIDENCE / 'checkpoint-compatibility/result.json')
    checkpoint_postgres = read(EVIDENCE / 'checkpoint-postgres-final/postgres.json')
    asset = read(EVIDENCE / 'assets-browser/result.json')
    asset_compatibility = read(EVIDENCE / 'assets-compatibility/result.json')
    asset_postgres = read(EVIDENCE / 'assets-postgres/postgres.json')
    load = read(EVIDENCE / 'large/result.json').get('checks', {}).get('large_graph', {})
    worker = read(EVIDENCE / 'worker-capability-recheck.json') or read(EVIDENCE / 'worker-capability-read.json')
    rows = []
    comparison = {}
    cohorts = [('baseline', baseline), ('candidate', candidate), ('retained inspection', followup),
               ('saved checkpoints', checkpoint), ('linked assets', asset)]
    if len({result.get('browser') for _, result in cohorts if result}) > 1:
        raise ValueError('Browser cohorts must use the same Chromium version')
    for stage, result in cohorts:
        for metric, unit in METRICS.items():
            values = [item[metric] for item in result.get('samples', []) if item.get(metric) is not None]
            for sample, value in enumerate(values, 1):
                rows.append(('overview', stage, sample, metric, round(value, 3), unit))
            if values:
                comparison.setdefault(metric, {})[stage] = round(median(values), 3)
        graph = result.get('checks', {}).get('graphs', {})
        for metric, unit in [('explorationReadyMs', 'ms'), ('graphFrameMedianMs', 'ms'), ('graphFrameSamples', 'frames')]:
            value = graph.get(metric)
            if value is not None:
                rows.append(('exploration', stage, 1, metric, round(value, 3), unit))
    asset_ms = asset_postgres.get('checks', {}).get('visible_database_browser', {}).get('retainedAssetReadyMs')
    if asset_ms is not None:
        rows.append(('asset graph', 'linked assets, postgres fixture', 1, 'navigation_to_saved_capture_ms', asset_ms, 'ms'))
    for metric, unit in [('retainedNodes', 'nodes'), ('mountedNodes', 'nodes'), ('frameMedianMs', 'ms'),
                         ('frameSamples', 'frames'), ('browserCpuPercent', 'percent'), ('browserSummedRssBytes', 'bytes')]:
        value = load.get(metric)
        if value is not None:
            rows.append(('asset graph, 1201 synthetic evidence nodes', 'candidate', 1, metric, round(value, 3), unit))
    timing = postgres.get('checks', {}).get('durable_traffic_metadata', {}).get('request_ms', [])
    for index, value in enumerate(timing, 1):
        rows.append(('traffic API including authentication', 'postgres fixture', index, 'api_request', value, 'ms'))
    for metric in ('two_concurrent_imports_ms', 'capture_detail_ms'):
        if metric in har:
            rows.append(('retained HAR API including authentication', 'postgres fixture', 1, metric, har[metric], 'ms'))
    with (REPORTS / 'artex-performance-metrics.csv').open('w', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['workflow', 'cohort', 'sample', 'metric', 'value', 'unit'])
        writer.writerows(rows)

    def cell(value: object) -> str:
        return '<td>' + html.escape(str(value)) + '</td>'

    requirement_table = ''.join('<tr>' + ''.join(cell(entry[key]) for key in ('id', 'status', 'acceptance')) + '</tr>'
                                for entry in matrix['requirements'] if entry['id'].startswith('P'))
    measured = ''.join('<tr>' + cell(metric + ' (' + METRICS[metric] + ')') +
        ''.join(cell(stages.get(stage, 'Unavailable')) for stage, _ in cohorts) + '</tr>'
        for metric, stages in comparison.items())
    cohort_headers = ''.join(f'<th scope="col">{html.escape(stage.capitalize())}</th>' for stage, _ in cohorts)
    screenshots = []
    for stage, name, caption in [
        ('acceptance-browser', 'exploration.png', 'Visible Chromium exploration graph, synthetic data'),
        ('acceptance-browser', 'asset.png', 'Visible Chromium asset graph, synthetic data'),
        ('acceptance-browser', 'communication.png', 'Recorded dependency roles, synthetic data'),
        ('acceptance-browser', 'traffic-mobile.png', 'Mobile traffic list after switching synthetic engagements'),
        ('acceptance-postgres-final', 'postgres-traffic.png', 'Durable capture inspector, disposable PostgreSQL synthetic data'),
        ('acceptance-postgres-final', 'postgres-evidence-review.png', 'Saved inconclusive disposition, disposable PostgreSQL synthetic data'),
        ('inspection-postgres', 'postgres-har-inspection.png', 'Reviewed HAR request and response, disposable PostgreSQL synthetic data'),
        ('inspection-postgres', 'postgres-evidence-review.png', 'Finding revision history, disposable PostgreSQL synthetic data'),
        ('checkpoint-postgres-final', 'postgres-checkpoint.png', 'Exploration at saved team sequence 11, disposable PostgreSQL synthetic data'),
        ('assets-postgres', 'postgres-retained-assets.png', 'Asset Graph saved traffic record, disposable PostgreSQL synthetic data'),
    ]:
        path = EVIDENCE / stage / name
        if path.is_file():
            content = path.read_bytes()
            encoded = base64.b64encode(content).decode()
            screenshots.append(f'<figure><img alt="{caption}" src="data:image/png;base64,{encoded}">'
                               f'<figcaption>{caption}<br><code>SHA-256 {hashlib.sha256(content).hexdigest()}</code></figcaption></figure>')
    checks = candidate.get('checks', {})
    passed = sum(check.get('status') == 'passed' for check in checks.values())
    first_regression = regression_summary(EVIDENCE / 'verified-regression.log')
    first_browser = browser_summary(candidate, compatibility)
    followup_run = cohort_validation('inspection', browser_summary(followup, followup_compatibility), followup_postgres)
    followup_run['offline_python'] = regression_summary(EVIDENCE / 'inspection-regressions-final.log')
    checkpoint_run = cohort_validation('checkpoint', browser_summary(checkpoint, checkpoint_compatibility), checkpoint_postgres)
    asset_run = cohort_validation('assets', browser_summary(asset, asset_compatibility), asset_postgres)
    matrix['validation_runs'] = {
        'offline_python': first_regression,
        'browser': first_browser,
        'disposable_postgres': {'migration': postgres.get('migration'), 'checks': sorted(postgres.get('checks', {})),
                                'restart': postgres.get('checks', {}).get('fresh_process_readback')},
        'asset_graph_load': load,
        'worker_capability_probe': worker,
        'retained_inspection': followup_run,
        'exploration_checkpoint': checkpoint_run,
        'retained_asset_correlation': asset_run,
    }
    matrix_path.write_text(json.dumps(matrix, indent=2) + '\n')
    browser_message = f'Visible Chromium {candidate.get("browser", "unavailable")} passed {passed} of {len(checks)} focused workflow groups.'
    def workflow_summary(run: dict) -> str:
        browser = run['browser']
        groups = browser['checks']
        passed_groups = sum(item.get('status') == 'passed' for item in groups.values())
        database_checks = run['disposable_postgres']['visible_browser_checks'] or []
        return (f"Visible Chromium passed {passed_groups} of {len(groups)} focused groups and "
                f"{browser['compatibility_passed']} of {browser['compatibility_total']} compatibility scenarios. "
                f"Disposable PostgreSQL supported {len(database_checks)} visible workflows. {run['offline_python']}")
    checked = ', '.join(postgres.get('checks', {})) or 'No PostgreSQL result loaded'
    worker_status = worker.get('status', 'unavailable')
    sizes = comparison.get('readyMs', {})
    bars = ''
    if len(sizes) >= 2:
        ceiling = max(sizes.values()) * 1.15
        bars = '<figure aria-label="Median Overview readiness">' + ''.join(
            f'<div class="measure"><span>{stage.title()} {value:.1f} ms</span>'
            f'<meter min="0" max="{ceiling:.1f}" value="{value:.1f}">{value:.1f} ms</meter></div>'
            for stage, value in sizes.items()) + '</figure>'
    load_message = ''
    if load.get('status') == 'passed':
        load_message = f"Asset pagination mounted {load['mountedNodes']} of {load['retainedNodes']} synthetic evidence nodes. " \
            f"The SVG transform sequence recorded a {load['frameMedianMs']:.1f} ms median interval. " \
            "The CSV includes summed Chromium process CPU and RSS. Summed RSS can count shared memory more than once."
    report = f'''<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARIA ARTEX integration evaluation</title>
<style>
:root {{ color-scheme: light dark; font: 16px/1.55 system-ui, sans-serif; }}
body {{ max-width: 68rem; margin: auto; padding: clamp(1rem,4vw,3rem); }}
p,li {{ max-width: 83ch; }} h1 {{ max-width: 26ch; line-height: 1.1; }} table {{ width: 100%; border-collapse: collapse; }}
th,td {{ text-align:left; padding:.55rem; border-bottom:1px solid GrayText; vertical-align:top; overflow-wrap:anywhere; }}
figure {{ margin:1.5rem 0; }} img {{ display:block; width:100%; border:1px solid GrayText; border-radius:.5rem; }}
pre, code {{ overflow-wrap:anywhere; white-space:pre-wrap; }} .scroll {{ overflow-x:auto; }}
.measure {{ display:grid; grid-template-columns:minmax(8rem,1fr) 3fr; align-items:center; gap:1rem; }}
.measure meter {{ width:100%; height:1.6rem; }}
</style><main>
<h1>ARIA ARTEX integration evaluation</h1>
<p>Mission Control now presents linked asset and investigation records, task supervision, retained coordination, historical review decisions, and scoped HTTP inspection. The existing FastAPI and PostgreSQL stores supply the records. This evaluation covers software behavior and controlled fixtures.</p>
<h2>Reference and architecture</h2>
<p>ARTEX documents typed asset and exploration graphs, evidence links, traffic records and usage supervision. ARIA represents those concepts as read-oriented views with shared record IDs, relationship reasons and visible missing references. FastAPI added a versioned owner-only traffic read endpoint. Existing database tables, report authority and accounting services supply the data. The frontend uses the native Mission Control shell and existing SVG renderer.</p>
<ul><li><a href="https://github.com/BaaRai/ARTEX#how-it-works">ARTEX documentation</a></li>
<li><a href="../docs/artex-aria-comparison.md">Initial feature comparison</a></li>
<li><a href="../docs/artex-inspired-architecture.md">ARIA architecture and acceptance contracts</a></li></ul>
<h2>Requirement evidence</h2>
<div class="scroll"><table><thead><tr><th scope="col">ID</th><th scope="col">Status</th><th scope="col">Evidence and open work</th></tr></thead>
<tbody>{requirement_table}</tbody></table></div>
<h2>Validation</h2>
<p>{html.escape(first_regression)} {html.escape(browser_message)} Compatibility scenarios passed {first_browser['compatibility_passed']} of {first_browser['compatibility_total']}.
Disposable PostgreSQL checks covered {html.escape(checked.replace('_', ' '))}.</p>
<p>The retained inspection cohort covered immutable finding history, encrypted HAR detail, concurrent import deduplication, and isolation. {html.escape(workflow_summary(followup_run))}</p>
<p>The saved checkpoint cohort restored an earlier finding state, navigated a retained dependency, disclosed missing sequences and unreadable records, and cleared history on engagement switch. Two fresh API processes produced the same saved checkpoint. {html.escape(workflow_summary(checkpoint_run))} These follow-up offline cohorts exclude four in-process vulnerability reproduction tests.</p>
<p>The linked-assets cohort traversed a mapped capture and its backing Traffic and catalog records, grouped an explicit default-port alias, and verified that switching engagements cleared the saved inspection. {html.escape(workflow_summary(asset_run))}</p>
<p>The configured worker capability probe returned {html.escape(worker_status)}. The probe describes advertisement and connectivity. Runtime execution, live model evaluation and independent human quality remain separate acceptance gates.</p>
<p>Focused Python tests cover malformed retained capture data, redaction, invalid pagination, unauthenticated access and foreign-owner denial. Browser checks use synthetic data and labelled evidence. Model quality, independent human review and live worker outcomes have no new evaluation evidence.</p>
<h2>Performance</h2>
<p>Five navigations per cohort used the same visible Chromium and loopback fixture. Figures are medians. Each readiness sample ends when the selected session and stored admission blocker are visible. These samples quantify local UI costs with synthetic fixture reads. Host scheduling and browser cache state may affect timing.</p>
<div class="scroll"><table><thead><tr><th scope="col">Metric</th>{cohort_headers}</tr></thead>
<tbody>{measured}</tbody></table></div>
{bars}
<p>{html.escape(load_message)}</p>
<p>Graph frame intervals come from a synthetic transform sequence. They describe the measured browser workload only. Capture API timing includes authorization and SQL reads. The CSV retains individual navigation samples, graph timing and database-backed request timings.</p>
<p><a href="artex-performance-metrics.csv">Performance samples</a> · <a href="artex-integration-matrix.json">Machine-readable matrix</a></p>
<h2>Visible Chromium captures</h2>
{''.join(screenshots)}
<h2>Reproduce</h2>
<pre>mkdir -p .local-lab/artex
npm --prefix web/mission-control run build -- --outDir /tmp/aria-artex-retained-assets
.venv/bin/python -B -m integration.artex_regressions &gt; .local-lab/artex/assets-regressions.log 2&gt;&amp;1
.venv/bin/python -B -m integration.artex_browser --assets /tmp/aria-artex-retained-assets --output .local-lab/artex/assets-browser
.venv/bin/python -B -m integration.artex_browser --assets /tmp/aria-artex-retained-assets --output .local-lab/artex/assets-compatibility --existing-suite
.venv/bin/python -B -m integration.mission_disposable --headed --assets /tmp/aria-artex-retained-assets --output .local-lab/artex/assets-postgres/postgres.json
.venv/bin/python -B -m integration.artex_report</pre>
<p>The entry bundle is archived locally under <code>.local-lab/artex/baseline-assets</code>. Its nine files match the baseline run's SHA-256 manifest. Use that directory with the same browser harness and <code>--baseline --output .local-lab/artex/baseline</code> to rerun the baseline.</p>
</main></html>'''
    (REPORTS / 'artex-integration-report.html').write_text(report + '\n')


if __name__ == '__main__':
    generate()
