"""Measure the real Mission Control event timeline in visible Chromium."""
from __future__ import annotations

import asyncio
import json
from contextlib import ExitStack
from time import perf_counter

import psutil
from playwright.async_api import async_playwright, expect

from integration.mission_browser import METRICS, ROOT, loopback_server, sign_in, sources
from integration.mission_fixture import ALPHA, Fixture, settings


SCROLL = """async root => {
    const intervals = [];
    let previous;
    for (let index = 0; index < 121; index++) {
        const now = await new Promise(requestAnimationFrame);
        if (previous !== undefined) intervals.push(now - previous);
        previous = now;
        root.scrollTop = index * (root.scrollHeight - root.clientHeight) / 120;
    }
    intervals.sort((a, b) => a - b);
    return {frames: intervals.length, fps: 1000 * intervals.length / intervals.reduce((a, b) => a + b, 0),
        frameP95Ms: intervals[Math.ceil(intervals.length * .95) - 1],
        mountedRows: root.querySelectorAll('.record').length};
}"""


async def profile() -> None:
    fixture = Fixture(current=False)
    fixture.extra_team = 600
    with ExitStack() as patches:
        for patch in fixture.patches():
            patches.enter_context(patch)
        async with loopback_server(fixture) as base, async_playwright() as pw:
            settings.ALLOWED_ORIGINS.append(base)
            browser = await pw.chromium.launch(headless=False, chromium_sandbox=True,
                                               args=['--disable-background-networking'])
            try:
                page = await browser.new_page(viewport={'width': 1440, 'height': 960}, reduced_motion='reduce')
                await page.context.route('**/*', lambda route: route.continue_()
                                         if route.request.url.startswith(base + '/') else route.abort())
                page_errors = []
                page.on('pageerror', lambda error: page_errors.append(str(error)))
                await sign_in(page, base, mission=True)
                await page.goto(base + '/dashboard?view=events&sid=' + ALPHA)
                await page.bring_to_front()
                await page.get_by_label('Event source').select_option('team')
                await expect(page.get_by_text('50 retained records.', exact=False)).to_be_visible()
                for count in (150, 250, 350, 450, 550, 603):
                    await page.get_by_role('button', name='Load older team events').click()
                    await expect(page.get_by_text(f'{count} retained records.', exact=False)).to_be_visible()
                timeline = page.get_by_role('region', name='Event timeline')
                cdp = await browser.new_browser_cdp_session()
                samples = []
                for _ in range(3):
                    await timeline.evaluate('node => { node.scrollTop = 0 }')
                    start = {process['id']: process['cpuTime'] for process in
                             (await cdp.send('SystemInfo.getProcessInfo'))['processInfo']}
                    began = perf_counter()
                    sample = await timeline.evaluate(SCROLL)
                    end = (await cdp.send('SystemInfo.getProcessInfo'))['processInfo']
                    sample['wallMs'] = round(1000 * (perf_counter() - began), 2)
                    sample['browserCpuMs'] = round(1000 * sum(max(0, process['cpuTime'] - start[process['id']])
                                                              for process in end if process['id'] in start), 1)
                    sample['browserCpuPercent'] = 100 * sample['browserCpuMs'] / sample['wallMs']
                    try:
                        sample['browserSummedRssBytes'] = sum(psutil.Process(process['id']).memory_info().rss
                                                               for process in end)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        sample['browserSummedRssBytes'] = None
                    sample['jsHeapBytes'] = (await page.evaluate(METRICS))['jsHeapBytes']
                    samples.append(sample)
                assert not page_errors, page_errors
                assert all(sample['mountedRows'] < 25 for sample in samples), samples
                result = {'browser': browser.version, 'headless': False, 'records': 603, 'samples': samples,
                          'pageErrors': page_errors, 'sourceHashes': sources('after')}
            finally:
                await browser.close()
    output = ROOT / '.local-lab/mission-control/timeline-profile.json'
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(output)


if __name__ == '__main__':
    asyncio.run(profile())
