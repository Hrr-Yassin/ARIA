"""Inspect only the static competence report in visible sandboxed Chromium."""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from playwright.async_api import async_playwright


async def inspect(report: Path, output: Path) -> dict:
    report=report.resolve();output.mkdir(parents=True,exist_ok=True)
    before=hashlib.sha256(report.read_bytes()).hexdigest()
    data=json.loads(report.with_name('aria-cybersecurity-competence-results.json').read_text())
    errors=[]
    async with async_playwright() as pw:
        browser=await pw.chromium.launch(headless=False,chromium_sandbox=True)
        try:
            page=await browser.new_page(viewport={'width':1600,'height':1100})
            page.on('pageerror',lambda exc:errors.append(type(exc).__name__))
            await page.route('http://**/*',lambda route:route.abort())
            await page.route('https://**/*',lambda route:route.abort())
            await page.goto(report.as_uri())
            await page.wait_for_load_state('load')
            assert await page.title()=='ARIA · Cybersecurity competence audit'
            assert await page.locator('section').count()==13
            body=await page.locator('body').inner_text()
            assert 'Fresh model quality: BLOCKED' in body
            assert 'Independent senior assessment: BLOCKED' in body
            assert '8/5 readiness: UNPROVEN' in body
            assert '3 / 12' in body and '5 / 10' in body
            assert await page.locator('#evidence tbody tr').count()==len(data['metrics'])
            await page.screenshot(path=output/'desktop.png',animations='disabled')
            for identity in ('baseline','components','burp','limitations'):
                section=page.locator('#'+identity)
                await section.scroll_into_view_if_needed()
                await section.screenshot(path=output/(identity+'.png'),animations='disabled')
            search=page.locator('#case-filter')
            await search.fill('auth-opaque-bearer')
            filtered=await page.locator('#evidence tbody tr:visible').count()
            assert 0<filtered<len(data['metrics'])
            await search.fill('')
            assert await page.locator('#evidence tbody tr:visible').count()==len(data['metrics'])
            await page.set_viewport_size({'width':390,'height':844})
            await page.evaluate('window.scrollTo(0,0)')
            mobile=await page.evaluate('({viewport:innerWidth,width:document.documentElement.scrollWidth})')
            assert mobile['width']<=mobile['viewport'],mobile
            await page.screenshot(path=output/'mobile.png',animations='disabled')
            assert not errors,errors
            assert hashlib.sha256(report.read_bytes()).hexdigest()==before
            result={'status':'passed','observed_at':datetime.now(timezone.utc).isoformat(),
                    'scope':'Static report only; no application/provider/target action',
                    'headless':False,'chromium_sandbox':True,'browser_version':browser.version,
                    'sections':13,'metric_rows':len(data['metrics']),'filter_matched_rows':filtered,
                    'mobile_width':390,'mobile_horizontal_overflow':False,'page_errors':errors,
                    'html_sha256':before,'independent_human_assessment':False}
            (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
            print(json.dumps(result))
            return result
        finally:
            await browser.close()


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report',type=Path,default=Path('reports/aria-cybersecurity-competence-audit.html'))
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();asyncio.run(inspect(args.report,args.output))


if __name__=='__main__':
    main()
