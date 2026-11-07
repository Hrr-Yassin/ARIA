"""Visible UI regression check for restored terminal autonomous status."""
import asyncio
import json
from pathlib import Path
from playwright.async_api import async_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
BASE = 'http://localhost:7000'
SESSION_NAME = 'Session 11/7/2026, 5:43:36 AM'
OUT = ROOT / '.local-lab/aria-http-autonomy-benchmark'


async def main():
    creds = dict(line.split(': ', 1) for line in (ROOT / '.local-lab/login.txt').read_text().splitlines())
    result = {'headless': False, 'session_name': SESSION_NAME, 'checks': []}
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=False, slow_mo=100)
        page = await browser.new_page(viewport={'width': 1440, 'height': 1000})
        await page.goto(BASE + '/login')
        await page.get_by_label('Username').fill(creds['Username'])
        await page.get_by_label('Password').fill(creds['Password'])
        async with page.expect_response(lambda r: r.url.endswith('/api/login')) as login:
            await page.locator('#login-btn').click()
        result['login_status'] = (await login.value).status
        await page.wait_for_url(BASE + '/')
        await expect(page.locator('.session-item').filter(has_text=SESSION_NAME)).to_be_visible()
        await page.locator('.session-item').filter(has_text=SESSION_NAME).click()
        await expect(page.locator('#auto-label')).to_have_text('AUTONOMOUS — BLOCKED')
        await expect(page.locator('#auto-log')).to_contain_text('malformed output')
        result['checks'] = ['saved blocked state is labeled in the toolbar', 'planner failure remains visible in activity log']
        await page.screenshot(path=str(OUT / '06-terminal-status-retest.png'), full_page=True)
        result['screenshot'] = '.local-lab/aria-http-autonomy-benchmark/06-terminal-status-retest.png'
        result['toolbar_status'] = await page.locator('#auto-label').inner_text()
        result['activity'] = (await page.locator('#auto-log').inner_text())[:1200]
        await browser.close()
    (OUT / 'ui-retest.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    asyncio.run(main())
