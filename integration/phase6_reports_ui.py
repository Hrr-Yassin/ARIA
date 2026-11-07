"""Local Firefox report UI acceptance with synthetic API responses; no target I/O.

ARIA_PHASE6_UI=1 .local-lab/browser-venv/bin/python -m integration.phase6_reports_ui
"""
import os
import asyncio
import json
from pathlib import Path
from playwright.async_api import async_playwright

async def main():
    loop = asyncio.get_running_loop()
    def wake():
        loop.call_later(0.05, wake)
    loop.call_later(0.05, wake)
    root = Path(__file__).resolve().parents[1]
    html = (root / 'web/index.html').read_text()
    start = html.index('    <section class="settings-section" id="reports-panel">')
    end = html.index('    <section class="settings-section" id="program-policy-panel">', start)
    css = (root / 'web/static/styles/index.css').read_text()
    script = (root / 'web/static/scripts/reports.js').read_text()
    out = root / '.local-lab/phase6'
    out.mkdir(parents=True, exist_ok=True)
    print('Starting local browser driver', flush=True)
    async with async_playwright() as p:
        print('Launching Firefox', flush=True)
        browser = await p.firefox.launch(headless=True)
        try:
            print('Rendering synthetic report UI', flush=True)
            page = await browser.new_page(viewport={'width': 440, 'height': 1000})
            await page.route('**/*', lambda route: route.abort())
            await page.set_content('<html><head><style>' + css + '\nbody{height:auto;overflow:auto}.settings-body{max-width:400px;margin:auto}input,select,textarea{max-width:100%;box-sizing:border-box}</style></head><body><div class="settings-body">' + html[start:end] + '</div></body></html>')
            await page.add_script_tag(content=script)
            await page.evaluate('''() => {
                const report = {id:'synthetic-report', revision:1, package_sha256:'f'.repeat(64),scope_digest:'a'.repeat(64),
                    template:'bug_bounty',document:{findings:[{id:'f1',title:'Private JSON disclosure on https://lab.test/item'}]}};
                Object.defineProperty(crypto, 'randomUUID', {value: () => 'synthetic-request-id', configurable:true});
                let signed=false;
                const api=async(path,opts={})=> {
                    if(path.endsWith('/findings'))return {findings:[{id:'f1', title:'Private object disclosure',state:'reportable',ready_for_external_submission:true}]};
                    if(path.endsWith('/preview'))return {report,signed,files:{'report.md':'# Private JSON disclosure on https://lab.test/item\\n\\nAsset: https://lab.test/item\\n\\n## Independent reproduction\\n\\n1. Reset synthetic fixture.\\n2. Read owner object as the controlled outsider.\\n3. Compare the selected private JSON marker with the owner and negative-control observations.\\n\\nDemonstrated impact: access to the selected controlled private value only.\\nPotential escalation is unverified.','manifest.json':'{"schema":"aria-report-v1","redaction":"credentials removed","evidence":"complete bounded observations"}','evidence/000-response.http':'HTTP/1.1 200 OK\\nContent-Type: application/json\\n\\n{"secret":"[REDACTED]"}'}};
                    if(path.endsWith('/signoff')){signed=true;return {data:{}};}
                    return {report_drafts:[report],report_signoffs:signed?[{report_id:report.id}]:[],report_outcomes:[]};
                };
                window.AriaReports.init({api,getContext:()=>({sessionId:'synthetic',epoch:1})});
            }''')
            await page.click('#reports-refresh')
            await page.get_by_role('button', name='Open preview').click()
            await page.wait_for_selector('#reports-actions:not(.hidden)')
            assert await page.locator('#reports-preview pre').first.text_content()
            await page.screenshot(path=str(out/'report-preview-mobile.png'), full_page=True)
            for key in ('reports-reviewed', 'reports-reproduced', 'reports-redacted'):
                await page.check('#' + key)
            await page.fill('#reports-reason', 'Synthetic review of complete draft and attachments')
            await page.click('#reports-signoff')
            print(await page.locator('#reports-status').inner_text(), flush=True)
            await page.wait_for_selector('#reports-signed-actions:not(.hidden)', timeout=5000)
            await page.screenshot(path=str(out/'report-signed-mobile.png'), full_page=True)
            assert await page.locator('#reports-signoff').is_disabled()
            assert await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
            result={'status':'passed','browser':'Firefox','api':'synthetic in-page doubles','target_requests':0,
                    'checks':['preview renders','human checkbox signoff','signed export controls','no horizontal overflow at 440px'],
                    'screenshots':['report-preview-mobile.png','report-signed-mobile.png']}
            (out/'browser.json').write_text(json.dumps(result,indent=2))
            print(json.dumps(result))
        finally:
            await browser.close()

if __name__ == '__main__':
    if os.environ.get('ARIA_PHASE6_UI') != '1':
        raise SystemExit('Set ARIA_PHASE6_UI=1 to run local Firefox UI acceptance')
    asyncio.run(main())
