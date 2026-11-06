"""Real Firefox context isolation with synthetic fulfilled receipts; zero target I/O.
Run with .local-lab/browser-venv/bin/python -m integration.phase3_browser.
"""
import asyncio
import json
from pathlib import Path
from playwright.async_api import async_playwright
from worker.browser_contexts import IsolatedBrowserPool


async def main():
    allowed = {('owner', 'a', 'one'): 'revision-1', ('owner', 'a', 'two'): 'revision-2',
               ('owner', 'b', 'one'): 'revision-3'}
    calls = []
    async def authorize(owner, engagement, identity):
        return allowed[(owner, engagement, identity)]
    async def fetch(owner, engagement, identity, method, url):
        if url != 'http://app.example.test/':
            raise ValueError('No approved receipt for this request')
        calls.append((engagement, identity, url))
        return {'status': 200, 'headers': {'content-type': 'text/html'},
                'body': ('<html><body>Owned ' + identity + '</body></html>').encode()}
    async def cancel(*key):
        pass
    async with async_playwright() as playwright:
        pool = IsolatedBrowserPool(playwright, authorize, fetch, cancel)
        try:
            contexts = [await pool.context(*key) for key in allowed]
            pages = [await context.new_page() for context in contexts]
            for index, page in enumerate(pages):
                await page.goto('http://app.example.test/')
                assert await page.evaluate('document.cookie') == ''
                assert await page.evaluate('localStorage.length') == 0
                await page.evaluate('(value) => {document.cookie="account="+value; localStorage.setItem("account",value)}', str(index))
            for index, page in enumerate(pages):
                assert await page.evaluate('document.cookie') == 'account=' + str(index)
                assert await page.evaluate('localStorage.getItem("account")') == str(index)
            assert await pool.context('owner','a','one') is contexts[0]
            for url in ['http://excluded.example.test/', 'http://app.example.test/unapproved']:
                try:
                    await pages[0].goto(url)
                except Exception:
                    pass
                else:
                    raise AssertionError('Unapproved navigation was not blocked')
            await pool.close_identity('owner','a','one')
            fresh = await pool.context('owner','a','one')
            page = await fresh.new_page(); await page.goto('http://app.example.test/')
            assert await page.evaluate('document.cookie') == ''
            assert await page.evaluate('localStorage.length') == 0
            del allowed[('owner','a','two')]
            try:
                await pages[1].goto('http://app.example.test/')
            except Exception:
                pass
            else:
                raise AssertionError('Revoked identity navigated')
            result = {'status':'passed','browser':'Firefox','isolated_identity_engagement_contexts':3,
                      'cookies_and_local_storage_isolated':True,'closed_context_storage_discarded':True,
                      'unapproved_requests_blocked':True,'revocation_blocks_navigation':True,
                      'synthetic_worker_receipts':len(calls),'target_requests':0,
                      'limitation':'Transport receipts mocked; authenticated worker tested separately.'}
            output=Path('.local-lab/phase3');output.mkdir(parents=True,exist_ok=True)
            (output/'browser.json').write_text(json.dumps(result,indent=2))
            print(json.dumps(result))
        finally:
            await pool.close()


if __name__ == '__main__':
    asyncio.run(main())
