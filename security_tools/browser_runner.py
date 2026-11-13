"""Chromium observes one approved response; every browser network request is blocked."""
import asyncio
import json
import sys
from security_tools.snapshot import fetch


async def observe(playwright, url: str, status: int, headers: list, body: bytes) -> dict:
    # Chromium's sandbox is mandatory; never use --no-sandbox or a shared context.
    browser = await playwright.chromium.launch(headless=True, chromium_sandbox=True)
    context = None
    try:
        context = await browser.new_context(service_workers='block', accept_downloads=False,
            permissions=[], java_script_enabled=False)
        fulfilled = False
        async def route(request_route):
            nonlocal fulfilled
            req = request_route.request
            if not fulfilled and req.url == url and req.method == 'GET' and req.is_navigation_request():
                fulfilled = True
                # Drop cookies, redirects and transport headers from the snapshot.
                content_type = next((v for k, v in headers if k.lower() == 'content-type'), 'text/html')
                await request_route.fulfill(status=status, headers={'content-type': content_type}, body=body)
            else:
                await request_route.abort('blockedbyclient')
        async def websocket(route):
            await route.close()
        await context.route('**/*', route)
        await context.route_web_socket('**/*', websocket)
        page = await context.new_page()
        page.set_default_timeout(5000)
        await page.goto(url, wait_until='domcontentloaded', timeout=5000)
        if not fulfilled:
            raise ValueError('Navigation was not fulfilled by the approved response')
        return {'url': url, 'status': status, 'title': (await page.title())[:256]}
    finally:
        try:
            if context is not None:
                await context.close()
        finally:
            await browser.close()


async def main(url: str) -> None:
    from playwright.async_api import async_playwright
    status, headers, body = fetch(url)
    async with async_playwright() as playwright:
        async with asyncio.timeout(10):
            result = await observe(playwright, url, status, headers, body)
    print(json.dumps(result))


if __name__ == '__main__':
    asyncio.run(main(sys.argv[1]))
