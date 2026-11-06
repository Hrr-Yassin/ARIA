"""Ephemeral Firefox contexts; all HTTP is fulfilled by reviewed worker receipts.

No browser request uses route.continue_(). A fresh context has no imported storage,
service workers, downloads, permissions or WebSocket transport. The fetch callback
must consume an approved identity-bound worker action; it cannot grant permission.
Playwright is an optional lab/browser-runtime dependency, not imported by the API.
"""
import asyncio
from dataclasses import dataclass, field


@dataclass
class Slot:
    context: object
    binding: str
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    closed: bool = False


class IsolatedBrowserPool:
    def __init__(self, playwright, authorize, fetch, cancel, max_contexts=8):
        self.playwright = playwright
        self.authorize, self.fetch, self.cancel = authorize, fetch, cancel
        self.max_contexts = min(max_contexts, 8)
        self.browser = None
        self.slots = {}
        self.lock = asyncio.Lock()

    async def context(self, owner: str, engagement: str, identity: str):
        key = (owner, engagement, identity)
        binding = await self.authorize(*key)
        async with self.lock:
            old = self.slots.get(key)
            if old and old.binding == binding and not old.closed:
                return old.context
            if old:
                old.closed = True
                await old.context.close()
                del self.slots[key]
            if len(self.slots) >= self.max_contexts:
                raise ValueError('Browser identity context limit reached')
            if self.browser is None:
                self.browser = await self.playwright.firefox.launch(headless=True, firefox_user_prefs={
                    'media.peerconnection.enabled': False,
                    'network.dns.disablePrefetch': True,
                    'network.prefetch-next': False,
                    'network.http.speculative-parallel-limit': 0,
                })
            context = await self.browser.new_context(service_workers='block', accept_downloads=False,
                                                     permissions=[], java_script_enabled=True)
            slot = Slot(context, binding)
            try:
                async def websocket(route):
                    await route.close()
                await context.route_web_socket('**/*', websocket)
                async def route(request_route):
                    async with slot.lock:
                        try:
                            if slot.closed or await self.authorize(*key) != slot.binding:
                                raise ValueError('Browser identity expired or changed')
                            request = request_route.request
                            if request.method not in {'GET', 'HEAD'} or request.post_data:
                                raise ValueError('Browser request needs a supported reviewed HTTP action')
                            result = await self.fetch(*key, request.method, request.url)
                            if slot.closed or await self.authorize(*key) != slot.binding:
                                raise ValueError('Browser identity changed during receipt collection')
                            if len(result['body']) > 32768:
                                raise ValueError('Browser response exceeds worker evidence limit')
                            await request_route.fulfill(status=result['status'], headers=result['headers'], body=result['body'])
                        except Exception:
                            await request_route.abort('blockedbyclient')
                await context.route('**/*', route)
                self.slots[key] = slot
                return context
            except BaseException:
                await context.close()
                raise

    async def close_identity(self, owner: str, engagement: str, identity: str):
        key = (owner, engagement, identity)
        async with self.lock:
            slot = self.slots.pop(key, None)
            if slot:
                slot.closed = True
                await slot.context.close()
        await self.cancel(*key)

    async def close(self):
        await asyncio.gather(*(self.close_identity(*key) for key in list(self.slots)), return_exceptions=True)
        if self.browser:
            await self.browser.close()
            self.browser = None
