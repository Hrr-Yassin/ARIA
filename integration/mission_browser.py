"""Measure ARIA in a real browser against the loopback FastAPI fixture.

Run with `.venv/bin/python -m integration.mission_browser --stage before --headed`.
Screenshots and raw metrics use the ignored .local-lab directory.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import socket
import subprocess
from contextlib import ExitStack, asynccontextmanager
from hashlib import sha256
from pathlib import Path
from time import perf_counter

import uvicorn
import psutil
from playwright.async_api import async_playwright, expect

from integration.mission_fixture import ALPHA, OWNER, Fixture, settings

ROOT = Path(__file__).resolve().parents[1]
METRICS = """() => {
    const navigation = performance.getEntriesByType('navigation')[0];
    const resources = performance.getEntriesByType('resource');
    const fcp = performance.getEntriesByName('first-contentful-paint')[0];
    return {
      domContentLoadedMs: navigation?.domContentLoadedEventEnd ?? null,
      firstContentfulPaintMs: fcp?.startTime ?? null,
      apiRequests: resources.filter(e => new URL(e.name).pathname.startsWith('/api/')).length,
      localTransferBytes: resources.filter(e => new URL(e.name).origin === location.origin)
        .reduce((total, e) => total + e.transferSize, 0),
      jsHeapBytes: performance.memory?.usedJSHeapSize ?? null,
      nodes: document.getElementsByTagName('*').length,
      width: document.documentElement.scrollWidth,
    };
}"""


def sources(stage):
    """Bind the measured browser build to its local fixtures and assets."""
    if stage == 'stress':
        paths = [ROOT / 'web/mission-control/src' / item for item in ('bench.ts', 'density.ts')]
        paths.extend((ROOT / 'web/static/mission-bench').rglob('*'))
    elif stage == 'after':
        paths = [*list((ROOT / 'web/mission-control/src').glob('*')),
                 *list((ROOT / 'web/static/mission').rglob('*')),
                 *[ROOT / 'web/mission-control' / item for item in ('package.json', 'package-lock.json', 'tsconfig.json', 'vite.config.ts')],
                 *[ROOT / item for item in ('api/main.py', 'api/routers/mission.py', 'api/routers/pentest.py',
                     'llm/engagement_budget.py', 'llm/request_metrics.py', 'memory/team_tasks.py', 'orchestrator/mission_status.py',
                     'web/login.html', 'web/static/scripts/login.js')]]
        paths.extend([ROOT / 'web/index.html', *list((ROOT / 'web/static/scripts').glob('*.js')),
                      *list((ROOT / 'web/static/styles').glob('*.css'))])
    else:
        paths = [ROOT / 'web/dashboard.html', ROOT / 'web/static/scripts/dashboard.js']
    paths.extend((ROOT / 'integration').glob('mission_*.py'))
    return {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest() for path in sorted(paths)
            if path.is_file() and path.name != 'mission_report.py'}


async def sign_in(page, base, mission=False):
    await page.goto(base + ("/login?next=mission" if mission else "/login"))
    await page.get_by_label("Username").fill(OWNER)
    await page.get_by_label("Password").fill("fixture-only-password")
    await page.get_by_role("button", name="Sign In").click()
    if mission:
        await page.wait_for_url("**/dashboard*")
    else:
        await page.wait_for_url(base + "/")
    await page.evaluate("sid => localStorage.setItem('current_session', sid)", ALPHA)


async def baseline(browser, base, out):
    context = await browser.new_context(viewport={"width": 1440, "height": 960}, reduced_motion="reduce")
    await context.route("**/*", lambda route: route.continue_() if route.request.url.startswith(base + "/") else route.abort())
    page = await context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    await sign_in(page, base)
    await expect(page.locator("#workspace-main")).to_be_visible()
    await page.screenshot(path=out / "workspace-desktop.png")
    ready = []
    for index in range(5):
        start = perf_counter()
        await page.goto(base + "/dashboard/legacy")
        await expect(page.locator('[data-dashboard-ready="true"]')).to_have_count(1)
        await expect(page.locator("#metric-calls")).to_contain_text("15")
        ready.append({"readyMs": round((perf_counter() - start) * 1000, 2), **await page.evaluate(METRICS)})
        if index == 0:
            await page.screenshot(path=out / "overview-desktop.png")
    # The stored budget has 3926 tokens left and a minimum reservation of 8192.
    budget_card = await page.locator("#budget-body").inner_text() if await page.locator("#budget-body").count() else ""
    captures = {"modelCallsTile": await page.locator("#metric-calls").inner_text(),
                "explainsReservationFloor": "8,192" in budget_card or "8192" in budget_card,
                "budgetPanel": budget_card[:1500]}
    await page.set_viewport_size({"width": 390, "height": 844})
    await page.screenshot(path=out / "overview-mobile.png")
    result = {"samples": ready, "defect": captures, "mobile": await page.evaluate(METRICS), "pageErrors": errors}
    await context.close()
    return result


async def current(browser, base, out, fixture):
    from integration.mission_scenarios import scenarios

    context = await browser.new_context(viewport={"width": 1440, "height": 960}, reduced_motion="reduce")
    await context.route("**/*", lambda route: route.continue_() if route.request.url.startswith(base + "/") else route.abort())
    page = await context.new_page()
    page.set_default_timeout(7000)
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    result = await scenarios(page, base, out, fixture, errors)
    await context.close()
    return result


async def stress(browser, base, out):
    context = await browser.new_context(viewport={"width": 1440, "height": 960}, device_scale_factor=1)
    page = await context.new_page()
    await page.goto(base + '/static/mission-bench/bench.html')
    await expect(page.locator('#benchmark-state')).to_have_text('Ready')
    await page.bring_to_front()
    cdp = await browser.new_browser_cdp_session()
    detail = await cdp.send('SystemInfo.getInfo')
    devices = [{key: item[key] for key in ('vendorId', 'deviceId', 'vendorString', 'deviceString') if key in item}
               for item in detail['gpu']['devices']]
    rows = []
    for markers in (128, 1000, 8000):
        for engine in ('svg', 'canvas', 'pixi'):
            start = {p['id']: p['cpuTime'] for p in (await cdp.send('SystemInfo.getProcessInfo'))['processInfo']}
            began = perf_counter()
            try:
                row = await page.evaluate('([engine, count]) => window.ariaRendererBenchmark(engine, count)', [engine, markers])
                end = (await cdp.send('SystemInfo.getProcessInfo'))['processInfo']
                row['wallMs'] = round(1000 * (perf_counter() - began), 2)
                row['browserCpuMs'] = round(1000 * sum(max(0, p['cpuTime'] - start[p['id']]) for p in end if p['id'] in start), 1)
                row['browserCpuPercent'] = round(100 * row['browserCpuMs'] / row['wallMs'], 1)
                try:
                    row['browserSummedRssBytes'] = sum(psutil.Process(p['id']).memory_info().rss for p in end)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    row['browserSummedRssBytes'] = None
                row['jsHeapBytes'] = (await page.evaluate(METRICS))['jsHeapBytes']
                row['status'] = 'measured'
            except Exception as error:
                row = {'renderer': engine, 'markers': markers, 'status': 'unavailable',
                       'reason': f'{type(error).__name__}: {error}'[:250]}
            rows.append(row)
            print(row, flush=True)
    await context.close()
    return {'rendererResults': rows, 'gpuDevices': devices,
            'method': '60 sampled frames after 13 warm-up frames, 1050×320 surface, full bounded-marker redraw per animation frame. '
                      'CPU sums matched process CPU time; percentage may exceed 100% across cores. '
                      'Summed process RSS includes shared pages in each process; it is not unique browser memory.'}


@asynccontextmanager
async def loopback_server(application):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        base = f"http://127.0.0.1:{listener.getsockname()[1]}"
        server = uvicorn.Server(uvicorn.Config(application, log_level="warning", access_log=False, lifespan="off",
                                               timeout_graceful_shutdown=2))
        server_task = asyncio.create_task(server.serve(sockets=[listener]))
        try:
            async with asyncio.timeout(5):
                while not server.started:
                    await asyncio.sleep(0.02)
            yield base
        finally:
            server.should_exit = True
            await server_task


async def main(args):
    out = ROOT / ".local-lab" / "mission-control" / f"{args.stage}-{args.browser}"
    out.mkdir(parents=True, exist_ok=True)
    fixture = Fixture(current=args.stage == "after")
    with ExitStack() as patches:
        for patch in fixture.patches():
            patches.enter_context(patch)
        async with loopback_server(fixture) as base, async_playwright() as playwright:
            settings.ALLOWED_ORIGINS.append(base)
            runtime = getattr(playwright, args.browser)
            config = {"chromium_sandbox": True, "args": ["--disable-background-networking"]} if args.browser == "chromium" else {}
            browser = await runtime.launch(headless=not args.headed, **config)
            try:
                if args.stage == 'stress':
                    result = await stress(browser, base, out)
                elif args.stage == 'after':
                    result = await current(browser, base, out, fixture)
                else:
                    result = await baseline(browser, base, out)
                result.update({"browser": args.browser, "version": browser.version, "headless": not args.headed,
                    "cohort": "FastAPI with isolated fixture stores", "head": subprocess.check_output(
                        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), "sourceHashes": sources(args.stage)})
                (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
                print(out / "result.json")
                if any(check['status'] != 'passed' for check in result.get('checks', [])):
                    raise SystemExit(1)
            finally:
                await browser.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=("before", "after", "stress"), default="before")
    parser.add_argument("--browser", choices=("chromium", "firefox"), default="chromium")
    parser.add_argument("--headed", action="store_true")
    arguments = parser.parse_args()
    if arguments.stage == 'stress' and arguments.browser != 'chromium':
        parser.error('The renderer benchmark uses Chromium process metrics.')
    asyncio.run(main(arguments))
