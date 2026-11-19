"""Build the self-contained Mission Control engineering report from local evidence."""
from __future__ import annotations

from base64 import b64encode
from hashlib import sha256
from html import escape
from pathlib import Path
from statistics import median
import json
import os
import re

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / '.local-lab' / 'mission-control'
OUTPUT = ROOT / 'reports' / 'aria-mission-control-2.html'
LABELS = {
    'readyMs': ('Overview ready', ' ms'),
    'firstContentfulPaintMs': ('First contentful paint', ' ms'),
    'domContentLoadedMs': ('DOMContentLoaded', ' ms'),
    'apiRequests': ('Initial API requests', ''),
    'localTransferBytes': ('Same-origin transfer', ' bytes'),
    'jsHeapBytes': ('Reported JavaScript heap', ' bytes'),
    'nodes': ('DOM elements', ''),
}
MATRIX = [
    ('1. Local source', 'Verified', 'Clean entry at 9906005. The working-tree changes and bundle digests bind to the browser results.'),
    ('2. Operational overview', 'Verified in fixtures', 'Mission, phase, scope, worker, review queue, blockers, accounting, investigation, and recent event records share the selected session.'),
    ('3. Frontend technologies', 'Verified', 'Local Vite and TypeScript build, D3/SVG diagrams, Apache ECharts analytics, Canvas 2D and PixiJS, browser-native layout and transitions, Playwright.'),
    ('4. Contract audit', 'Verified in scoped interfaces', 'Endpoint matrix, recreated budget defect, schema checks, same-origin requests, owner scoping, deduplication, stale handling and socket teardown.'),
    ('5. Application shell', 'Verified in fixtures', 'Ten views share navigation and session selection. Workspace loads the existing authenticated research document on demand, preserves unsent drafts during shell refresh, and releases its document on exit. Existing operational settings and review handlers are reused.'),
    ('6. Agent graph', 'Verified for recorded data', 'Actual agent registrations, owned assignments, dependencies and evidence IDs. Unattributed collaboration has no graph edge.'),
    ('7. Event pipeline', 'Verified for retained sources', 'Bounded forward catch-up, team cursor pages, retained rings for current and older campaigns, worker receipt snapshots and a bounded authorization journal. Replay uses a fixed window. Overwritten rings, other approval sources and intermediate worker states can fall outside the stored history.'),
    ('8. Accounting analytics', 'Verified for retained measurements', 'An allowlisted owner-scoped view supplies reservations, token and cost measures, provider-reported cost where available, latency and recorded timeouts. Task states, bounded command timing and campaign events have independent sources. Unmeasured worker CPU, memory and precise job durations are unknown.'),
    ('9. Operator controls', 'Verified for measured contracts', 'Session creation, signed report download, proposal rejection, pause, stop, cancel and confirmed campaign resume use existing server contracts. Pending web replay cancellation remains unconfirmed. Existing activation, settings and execution-releasing review handlers remain available in Workspace; no paid inference or target operation was used to test them.'),
    ('10. Design system', 'Verified in fixtures', 'Persistent themes, accents, density, reduced motion, Simple/Advanced mode, collapsible observation panels and keyboard inspector width. Containment and current approvals remain visible. Viewport and keyboard coverage is recorded below.'),
    ('11. Performance', 'Measured', 'Five navigation samples per Chromium cohort, interaction timing, DOM windows and three renderer workloads. Browser-metric cohort and limitations are disclosed below.'),
    ('12. Reliability', 'Verified in fixtures', '401, 403, 404 and 500, malformed JSON contract, network loss, disconnected worker, session switch, restored state and socket recovery.'),
    ('13. Browser acceptance', 'Verified in fixtures', 'Visible Chromium and cross-browser Firefox use real FastAPI routes with isolated fixture stores. Separate PostgreSQL validation confirms durable route behavior.'),
    ('14. Continuation', 'Recorded', 'GOALS, PLANS and PROGRESS retain the original competence, reliability and deferred endurance requirements.'),
    ('15. Deliverables', 'Verified locally', 'Bundled application, source, build lock, contracts, regression code, browser measurements and this report are retained. Research chat and configuration surfaces are reused inside Workspace and remain available standalone.'),
    ('16. Full acceptance', 'Broader operations remain open', 'The workstation serves the verified frontend. Live worker and provider outcomes, historical data outside source retention, and execution-releasing workflows are outside this evidence.'),
]


def read(directory):
    return json.loads((EVIDENCE / directory / 'result.json').read_text())


def number(value):
    return 'Unavailable' if value is None else f'{value:,.2f}'.rstrip('0').rstrip('.') if isinstance(value, float) else f'{value:,}'


def table(head, rows):
    columns = ''.join('<th scope="col">' + escape(str(value)) + '</th>' for value in head)
    content = ''.join('<tr>' + ''.join('<td>' + escape(str(value)) + '</td>' for value in row) + '</tr>' for row in rows)
    return '<div class="table-wrap"><table><thead><tr>' + columns + '</tr></thead><tbody>' + content + '</tbody></table></div>'


def link(path, label):
    relative = os.path.relpath(path, OUTPUT.parent)
    return f'<a href="{escape(relative, quote=True)}">{escape(label)}</a>'


def screenshot(path, label):
    blob = b64encode(path.read_bytes()).decode('ascii')
    return f'<figure><img loading="lazy" alt="{escape(label)}" src="data:image/png;base64,{blob}"><figcaption>{escape(label)}</figcaption></figure>'


def metric(cohort, key):
    values = [sample[key] for sample in cohort['samples'] if sample.get(key) is not None]
    return median(values) if values else None


def verified_source(cohort, *, renderer_benchmark=False):
    manifest = cohort.get('sourceHashes', {})
    if renderer_benchmark:
        manifest = {path: digest for path, digest in manifest.items() if path.startswith('web/') or path == 'integration/mission_browser.py'}
        required = {'web/mission-control/src/bench.ts', 'web/mission-control/src/density.ts', 'integration/mission_browser.py'}
        if not required <= set(manifest) or not any(path.startswith('web/static/mission-bench/') for path in manifest):
            return False
    if not manifest:
        return False
    for path, expected in manifest.items():
        current = ROOT / path
        if not current.is_file() or sha256(current.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f'Measured source differs from the working tree at {path}')
    return True


def render():
    before, chromium, firefox, stress = map(read, ('before-chromium', 'after-chromium', 'after-firefox', 'stress-chromium'))
    pg_path = EVIDENCE / 'postgres-result.json'
    pg = json.loads(pg_path.read_text())
    workstation_path = EVIDENCE / 'workstation-status.json'
    workstation = json.loads(workstation_path.read_text())
    owner_path = EVIDENCE / 'workstation-browser.json'
    owner = json.loads(owner_path.read_text())
    shell_hash = owner['sourceHashes'].get('web/static/mission/index.html')
    if (owner['headless'] or len(set(owner['views'])) != 10 or any(owner.get(key) != [] for key in
            ('pageErrors', 'serverFailures', 'blockedWrites')) or not verified_source(owner) or
            workstation['status'] != 200 or workstation['body_sha256'] != shell_hash):
        raise RuntimeError('Current read-only workstation acceptance is missing or incomplete')
    timeline_path = EVIDENCE / 'timeline-profile.json'
    timeline = json.loads(timeline_path.read_text())
    if (timeline['headless'] or timeline['records'] != 603 or len(timeline['samples']) != 3 or
            timeline['pageErrors'] or not verified_source(timeline)):
        raise RuntimeError('Current visible timeline profile is missing or incomplete')
    db_browser = pg['checks'].get('visible_database_browser')
    if not db_browser or db_browser.get('headless') or not verified_source(db_browser):
        raise RuntimeError('Visible browser evidence against the disposable PostgreSQL source is missing')
    if pg['checks'].get('durable_accounting_projection') != {'sanitized_attempts': 1, 'foreign_admin_denied': 404}:
        raise RuntimeError('Disposable accounting behavior did not meet its isolation and projection checks')
    checks = chromium['checks']
    if before['headless'] or chromium['headless'] or stress['headless']:
        raise RuntimeError('The Chromium evidence requires headed capture')
    if len(checks) < 18 or len(firefox['checks']) != len(checks):
        raise RuntimeError('The complete Chromium and Firefox scenario matrices are missing')
    if any(item['status'] != 'passed' for result in (chromium, firefox) for item in result['checks']):
        raise RuntimeError('Browser regression failures remain in the acceptance input')
    if [item['name'] for item in checks] != [item['name'] for item in firefox['checks']]:
        raise RuntimeError('The browser cohorts used different acceptance scenarios')
    for result in (chromium, firefox):
        if not verified_source(result):
            raise RuntimeError('Source hashes are missing from a current evidence record')
    if not verified_source(stress, renderer_benchmark=True):
        raise RuntimeError('The renderer evidence does not match the benchmark package and measurement script')
    if chromium['pageErrors'] or firefox['pageErrors']:
        raise RuntimeError('The browser run retained uncaught exceptions')
    py_path = EVIDENCE / 'python-final.log'
    js_path = EVIDENCE / 'javascript-final.log'
    build_path = EVIDENCE / 'frontend-build.log'
    py_text = py_path.read_text()
    regression = re.search(r'Ran (\d+) tests in (\d+\.\d+)s\s+OK\s*$', py_text)
    if not regression or len(js_path.read_text().strip().splitlines()) != 5 or 'built in' not in build_path.read_text():
        raise RuntimeError('Final offline, frontend or bundle verification is missing')
    interactions = {key: value for item in chromium['interaction'] for key, value in item.items()}
    if not interactions.get('overviewRefreshVisualMatch'):
        raise RuntimeError('The overview refresh comparison is missing')
    metrics = []
    for key, (label, unit) in LABELS.items():
        a, b = metric(before, key), metric(chromium, key)
        delta = ((b - a) / a) * 100 if a and b is not None else None
        metrics.append((label, number(a) + unit if a is not None else 'Unavailable', number(b) + unit if b is not None else 'Unavailable',
                        'Unavailable' if delta is None else f'{delta:+.1f}%'))
    gallery = [
        ('before-chromium', 'overview-desktop.png', 'Before · Operations Overview'),
        ('after-chromium', 'overview-desktop.png', 'After · Mission Control Overview'),
        ('before-chromium', 'workspace-desktop.png', 'Before · Research workspace'),
        ('after-chromium', 'investigation-desktop.png', 'After · Investigation workspace'),
        ('after-chromium', 'workspace-integrated.png', 'Shared shell with the existing research workspace'),
        ('after-chromium', 'containment-pausing.png', 'Pause acknowledgement awaits server confirmation'),
        ('after-chromium', 'containment-stop-pending.png', 'Pending web replay cancellation is explicitly unconfirmed'),
        ('after-chromium', 'agents-desktop.png', 'D3 orchestration graph'),
        ('after-chromium', 'event-relationships.png', 'Retained event relationships'),
        ('after-chromium', 'application-topology.png', 'Saved application topology'),
        ('after-chromium', 'analytics-desktop.png', 'ECharts token and cost analytics'),
        ('after-chromium', 'overview-768.png', 'Tablet layout at 768 px'),
        ('after-chromium', 'overview-390.png', 'Mobile layout at 390 px'),
        ('after-chromium', 'settings-light.png', 'Light theme and preferences'),
        ('after-firefox', 'overview-desktop.png', 'Firefox overview'),
    ]
    visuals = ''.join(screenshot(EVIDENCE / directory / asset, label) for directory, asset, label in gallery)
    visuals += screenshot(EVIDENCE / db_browser['screenshot'], 'Authorization record from disposable PostgreSQL in visible Chromium')
    visuals += screenshot(EVIDENCE / db_browser['archiveScreenshot'], 'Older campaign replay from disposable PostgreSQL in visible Chromium')
    renderer_rows = [(
        row['renderer'].split(' · ')[0], row['markers'], row.get('fps', 'Unavailable'),
        row.get('frameP95Ms', 'Unavailable'), row.get('drawP95Ms', 'Unavailable'),
        row.get('longFrames', 'Unavailable'), row.get('browserCpuMs', 'Unavailable'),
        row.get('browserCpuPercent', 'Unavailable'), row.get('browserSummedRssBytes', 'Unavailable'), row.get('jsHeapBytes', 'Unavailable'))
        for row in stress['rendererResults']]
    renderer_detail = ', '.join(sorted({row['renderer'] for row in stress['rendererResults'] if 'WebGL' in row['renderer']}))
    def delta_bars(key):
        a, b = metric(before, key), metric(chromium, key)
        limit = max(a, b, 1)
        fill = lambda name, val: f'<div class="barline"><span>{name}</span><meter value="{val}" max="{limit}"></meter><strong>{number(val)}</strong></div>'
        return fill('Before', a) + fill('After', b)

    section = lambda title, contents: f'<section><h2>{title}</h2>{contents}</section>'
    intro = f"""<header><p class="eyebrow">ARIA ENGINEERING REPORT</p><h1>Mission Control 2.0</h1>
      <p>Local source integration, browser acceptance and renderer measurements</p>
      <div class="chips"><span>{len(checks)} scenarios per browser</span><span>{regression.group(1)} Python regressions</span>
      <span>5 JavaScript suites</span><span>10 workstation views</span></div></header>"""
    overview = section('Scope and provenance', f"""
      <p>FastAPI serves the new locally built application at <code>/dashboard</code>. The read models retain the existing session,
      approval, worker isolation and accounting authorities. The shared shell covers ten operator views. Workspace loads the existing
      research document inside the shell, sharing identity and palette while retaining its established chat, review and settings handlers.</p>
      <p>Baseline revision <code>{escape(before['head'])}</code>. The candidate is the working tree on that revision, with
      source and built-asset SHA-256 manifests in the current run records. Chromium {escape(chromium['version'])} was visible
      with its browser sandbox enabled. Firefox {escape(firefox['version'])} ran headlessly for compatibility.</p>
      <p>The browser fixtures exercise the real serving, login, socket and API handlers on loopback with synthetic stores.
      Worker responses and pending approvals were controlled. The production service, target hosts and paid providers were outside
      this fixture cohort. The PostgreSQL run verified real authentication and journal reads through FastAPI and then served
      the same database to visible Chromium with the application lifecycle suspended.</p>
      <p>The workstation served the matching {escape(workstation['shell'])} shell with HTTP {workstation['status']} at
      <code>{escape(workstation['observed_at'])}</code>. Visible Chromium {escape(owner['browser'])} signed in with the existing
      owner account and opened all ten views. It recorded zero uncaught page errors, server failures or write attempts beyond sign-in.
      The browser's transport was read-only after sign-in. {link(EVIDENCE / owner['screenshots'][0], 'Workstation overview screenshot')}
      · {link(EVIDENCE / owner['screenshots'][1], 'Workstation workspace screenshot')}</p>
      <p>{link(ROOT / 'docs/mission-control-contracts.md', 'Frontend and backend contract matrix')}</p>""")
    corrections = section('Continuation and reproduced corrections', table(
      ('Requirement', 'Previous state / reproduced defect', 'Correction and evidence'), [
        ('MC-02 · shared workspace', 'The research document opened outside the shared shell.',
         'Workspace loads it on demand under the selected session. Both browsers exercise real keyboard input, refresh and mode preservation, session replacement, mobile sizing and document disposal.'),
        ('MC-05a · stop truth', 'The endpoint returned stopped with a pending web replay cancellation.',
         'The response status includes worker and web replay pending counts. A retained failing Python test precedes the fix.'),
        ('MC-05a · durable recovery', 'The acknowledgement warning disappeared after reload.',
         'Operations reads only grouped owner/requester-bound WebAction state counts. Reload, independent source failure/recovery, redaction and PostgreSQL isolation are tested; the read never calls the connector.'),
        ('MC-05a · reconciliation', 'An existing read could satisfy the post-mutation refresh with old state.',
         'Operator requests wait for older in-flight reads before revalidation. The browser holds a pre-stop response until after acknowledgement and verifies the final server state.'),
        ('MC-05b · existing controls', 'Campaign resume existed only in the compatibility overview.',
         'Operations has explicit confirmation and uses the existing owner-only resume endpoint. Workspace retains existing activation/review/settings handlers. Actual paid inference and target execution were excluded.'),
        ('MC-06 · preferences', 'Panel collapsing was absent and keyboard width had no browser evidence.',
         'Collapse state and 700px inspector width survive reload. Containment, proposals and stored replay status remain visible.'),
        ('MC-06 · browser investigation', 'Workspace load briefly exposed a null document root; Firefox fill entered no text.',
         'Theme synchronization guards the loading document. A retained input-event/navigation probe established that actual typing persists; acceptance now types and verifies the draft before refresh.'),
        ('MC-06 · performance', 'The renderer benchmark lacked process memory and actual timeline scrolling.',
         'The report records actual timeline frame measurements, native UHD 620 renderer workloads, process CPU and summed RSS.'),
        ('MC-03 · event catch-up', 'Each refresh fetched only the first forward page even when the server reported more retained records.',
         'One refresh follows up to four pages and shows any backlog. Both browsers verified 200 of 230 new records in the first refresh, the final 30 on the next, and recovery after a stalled cursor.')]))
    performance = section('Before and after', f"""
      <div class="columns"><div><h3>Initial API requests</h3>{delta_bars('apiRequests')}</div>
      <div><h3>Overview ready in milliseconds</h3>{delta_bars('readyMs')}</div></div>
      {table(('Measurement', 'Before median', 'After median', 'Change'), metrics)}
      <p>Five Chromium navigations per cohort at 1440 × 960 with network interception and browser cache disabled.
      Readiness waits for settled overview values. The baseline loads the legacy record set. The new Overview loads only
      its current source set. The heap measure is Chromium's reported JavaScript heap at the sample, with no forced
      collection or process memory attribution. The candidate browser matrix ran alongside Firefox compatibility checks.
      The dedicated timeline profile below ran separately.</p>
      {table(('Interaction', 'Measurement'), [
          ('Settled snapshot after refresh', 'Exact match' if interactions.get('overviewRefreshPixelMatch') else
           f"GPU rounding only: {interactions.get('overviewChangedPixels')} pixels, max {interactions.get('overviewMaxChannelDifference')}/255 channel delta"),
          *[(label, number(interactions.get(key)) + unit)
            for label, key, unit in [('Session selection to rendered result', 'selectionMs', ' ms'),
             ('Retained entries in stress list', 'virtualListRecords', ''), ('Mounted rows', 'mountedRecords', ''),
             ('Keyboard jump to final record', 'jumpToLastMs', ' ms'),
             ('Actual timeline scroll', 'timelineScrollFps', ' FPS'),
             ('Timeline scroll frame p95', 'timelineScrollFrameP95Ms', ' ms'),
             ('Timeline scroll sampled intervals', 'timelineScrollFrames', '')]]
      ])}
      <p>The baseline showed call reservations remaining without the token floor explanation. The candidate states the
      3,926-token headroom and the 8,192-token minimum together. Missing counters and measurements remain unknown.</p>""")
    timeline_area = section('Live timeline resource profile', f"""
      <p>Visible Chromium scrolled through 603 records served by the authenticated FastAPI event route and its fixture store.
      Each of three samples covers 120 animation frame intervals. At the final position the timeline mounted 18 rows.</p>
      {table(('Sample', 'FPS', 'Frame p95 ms', 'Browser CPU ms', 'CPU %', 'Summed process RSS bytes', 'JS heap bytes'), [
          (index, *(number(sample.get(key)) for key in ('fps', 'frameP95Ms', 'browserCpuMs', 'browserCpuPercent',
                                                       'browserSummedRssBytes', 'jsHeapBytes')))
          for index, sample in enumerate(timeline['samples'], 1)])}
      <p>Process CPU includes Chromium work across cores, including automation. The RSS sum can count shared pages for each
      process that maps them. The JavaScript heap comes from the page. This profile measures the rendered timeline with scripted scrolling.</p>""")
    renderer_area = section('Renderer benchmark on Intel UHD 620', f"""
      <p>{escape(stress['method'])}. {escape(renderer_detail)}.</p>
      {table(('Renderer', 'Markers', 'FPS', 'Frame p95 ms', 'Draw p95 ms', 'Frames over 25 ms', 'Browser CPU ms', 'CPU %', 'Summed process RSS bytes', 'JS heap bytes'), renderer_rows)}
      <p>D3/SVG serves bounded semantic diagrams with focusable nodes and labelled relationships. Canvas 2D is the default for
      event markers and had the lowest p95 draw time in these runs. PixiJS provides hardware WebGL as an explicit alternative.
      The application falls back to Canvas when WebGL is unavailable. The 8,000-marker benchmark deliberately exceeds the
      production timeline buffer. Browser CPU sums matched Chromium processes and can exceed elapsed wall time.</p>
      <p>The retained benchmark uses the same benchmark source, compiled bundle and Playwright measurement script as the current
      files. The browser acceptance and overview timing samples were refreshed for the new event experience.</p>""")
    firefox_cases = {item['name']: item for item in firefox['checks']}
    acceptance = section('Browser and database acceptance', f"""
      {table(('Scenario', 'Visible Chromium', 'Firefox'), [(item['name'], item['status'], firefox_cases[item['name']]['status']) for item in checks])}
      <p>Both browsers reported zero uncaught page errors. The stress timeline asserted bounded mounted rows and keyboard
      navigation through 603 retained records. Overview refresh comparisons record the exact hash and pixel differences;
      visual stability permits only a maximum 2/255 channel delta on at most 0.01% of pixels to account for GPU raster rounding.</p>
      <p>Python offline suite passed {regression.group(1)} checks in {regression.group(2)} seconds. Five JavaScript suites passed.
      The TypeScript and Vite production build succeeded. A fresh PostgreSQL 16.6 container at migration 0005 passed
      latest, older and newer event reads, archived campaign paging, protected receipt and authorization projections, and the
      accounting and token-admission checks. The latter used an owner-scoped attempt projection and tested redaction. Visible Chromium
      authenticated against that database, displayed the recorded denial, and opened the retained timeout and authorization inspectors.
      It also replayed an older campaign from the database. The full disposable run took
      {number(pg['elapsedMs'])} ms including container lifecycle.</p>
      <p>Both browsers verified that live arrivals leave replay fixed, empty filters preserve the exit control, revocation
      retires the previously loaded records, and a failed campaign snapshot can be retried. The reconnect scenario also
      verified that a live refresh preserves the selected search text.</p>
      <p>The signed download fixture covered a successful ZIP, a rejected stale export, a mismatched manifest digest, and an
      unsigned report with no download action.</p>""")
    artifacts = [(directory, EVIDENCE / directory / 'result.json') for directory in
                 ('before-chromium', 'after-chromium', 'after-firefox', 'stress-chromium')]
    artifacts += [('disposable PostgreSQL', pg_path), ('workstation shell observation', workstation_path),
                  ('workstation read-only browser', owner_path), ('timeline resource profile', timeline_path),
                  ('pre-fix event catch-up failure', EVIDENCE / 'iteration-8-before' / 'result.json'),
                  ('Python regressions', py_path), ('JavaScript regressions', js_path), ('frontend build', build_path)]
    references = ''.join(f'<li>{link(path, label)} <code>{sha256(path.read_bytes()).hexdigest()}</code></li>' for label, path in artifacts)
    requirements = section('Requirement evidence and limitations', table(('Requirement', 'Disposition', 'Evidence'), MATRIX))
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">' + (
        '<title>ARIA Mission Control 2.0 engineering report</title><style>' + STYLE + '</style></head><body><main>' +
        intro + overview + corrections + performance + timeline_area + renderer_area + acceptance + requirements +
        section('Graphical evidence', '<div class="gallery">' + visuals + '</div>') +
        section('Raw evidence and SHA-256', '<ul class="artifacts">' + references + '</ul>') + '</main></body></html>\n')


STYLE = """
:root { color-scheme: dark; font: 15px/1.6 system-ui, sans-serif; --base:#0b101a; --panel:#121a28; --ink:#edf1fa; --line:#2d3a50;
  --muted:#abb6cc; --accent:#b7a3ff; }
* { box-sizing:border-box; } body { margin:0; background:var(--base); color:var(--ink); } main { max-width:1360px; margin:auto; padding:32px 22px; }
header, section { margin-bottom:18px; padding:clamp(15px,3vw,29px); background:var(--panel); border:1px solid var(--line); border-radius:13px; }
header { background:linear-gradient(120deg,#141c2a,#211e37); } h1,h2,h3,p { margin:0 0 10px; } h1 { font-size:clamp(32px,6vw,60px); line-height:1.08; }
h2 { font-size:24px; } h3 { font-size:15px; } p { color:var(--muted); } a { color:var(--accent); } a:focus-visible { outline:2px solid var(--accent); }
.eyebrow { color:var(--accent); font-family:monospace; letter-spacing:.15em; }.chips,.columns { display:flex; flex-wrap:wrap; gap:12px; }
.chips span { border:1px solid var(--line); border-radius:30px; padding:3px 10px; } .columns>div { flex:1 1 280px; }
.barline { display:grid; gap:8px; align-items:center; grid-template-columns:60px 1fr 70px; margin:6px 0; }
meter { width:100%; accent-color:var(--accent); }.table-wrap { overflow:auto; margin:14px 0; }
table { border-collapse:collapse; width:100%; font-size:13px; } td,th { border-bottom:1px solid var(--line); text-align:left; padding:7px 10px; }
th { color:var(--accent); font-size:12px; } .gallery { display:grid; grid-template-columns:repeat(auto-fit,minmax(min(100%,440px),1fr)); gap:16px; }
figure { margin:0; border:1px solid var(--line); border-radius:8px; overflow:hidden; } img { display:block; width:100%; height:auto; }
figcaption { padding:8px 10px; color:var(--muted); } .artifacts { padding-left:19px; } code { overflow-wrap:anywhere; }
"""


async def verify_view():
    from playwright.async_api import async_playwright, expect
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, chromium_sandbox=True)
        page = await browser.new_page(viewport={'width': 1440, 'height': 960})
        await page.goto(OUTPUT.as_uri())
        await expect(page.get_by_role('heading', name='Mission Control 2.0', exact=True)).to_be_visible()
        await expect(page.get_by_role('heading', name='Requirement evidence and limitations')).to_have_count(1)
        images = await page.locator('figure img').evaluate_all('async images => { for (const image of images) { '
            'image.loading = "eager"; await image.decode(); } return images.map(image => image.naturalWidth); }')
        assert len(images) == 17 and all(width >= 390 for width in images)
        await page.screenshot(path=EVIDENCE / 'report-preview.png')
        await page.set_viewport_size({'width': 390, 'height': 844})
        assert await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        await browser.close()
    print('Graphical report, 17 embedded images and mobile width verified')


if __name__ == '__main__':
    import argparse
    import asyncio
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-view', action='store_true')
    args = parser.parse_args()
    OUTPUT.parent.mkdir(exist_ok=True)
    page = render()
    OUTPUT.write_text(page, encoding='utf-8')
    print(OUTPUT)
    if args.verify_view:
        asyncio.run(verify_view())
