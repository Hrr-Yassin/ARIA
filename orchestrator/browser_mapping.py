"""Browser rendering is fed only by explicitly approved identity-bound jobs."""
import asyncio
import base64
import hashlib
import json
from email.parser import BytesParser

from fastapi import HTTPException
from config.settings import settings
from memory.application_map import application_map
from memory.execution_authorization import execution_authorization
from memory.worker_jobs import worker_jobs
from worker.browser_contexts import IsolatedBrowserPool
from worker.http_profile import parse, cipher


class BrowserMapping:
    def __init__(self):
        self.approvals = {}
        self.pool = None
        self.playwright = None
        self.lock = asyncio.Lock()
        self.navigation = {}

    async def authorize(self, owner, sid, identity_id):
        # View checks current ownership and applies expiry. Credentials stay in SQL.
        view = await application_map.view(sid, owner)
        identity = view['identities'].get(identity_id)
        if not identity or not identity['active']:
            raise HTTPException(409, 'Browser identity expired or revoked')
        return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()

    async def fetch(self, owner, sid, identity_id, method, url):
        key = (owner, sid, identity_id, method, url)
        action = self.approvals.pop(key, None)
        if action is None:
            raise HTTPException(403, 'No explicit approval for browser request')
        # The shared gate consumes the approval once and rechecks live identity.
        result = await execution_authorization.execute(owner, sid, action.command,
            tool='aria-http', action_id=action.id, timeout=10)
        job = await worker_jobs.store.get(result['job_id'])
        if (job['state'] != 'succeeded' or job['user_id'] != owner or job['session_id'] != sid
                or job.get('http_identity') != identity_id):
            raise HTTPException(409, 'Browser worker request did not complete')
        await application_map.catalog_replay(sid, owner, result['job_id'])
        protected = json.loads(cipher(settings.HTTP_REPLAY_KEY).decrypt(job['protected_response'].encode()))
        raw = base64.b64decode(protected['response_b64'])
        head, _, body = raw.partition(b'\r\n\r\n')
        status, _, headers = head.partition(b'\r\n')
        fields = BytesParser().parsebytes(headers + b'\r\n\r\n')
        # Framing belongs to Playwright; no proxy credentials or hop-by-hop headers.
        excluded = {'content-length', 'transfer-encoding', 'connection', 'proxy-authenticate', 'proxy-authorization'}
        return {'status': int(status.split(b' ')[1]), 'body': body,
                'headers': {key: value for key, value in fields.items() if key.lower() not in excluded}}

    async def cancel(self, owner, sid, identity_id):
        self.approvals = {key: value for key, value in self.approvals.items() if key[:3] != (owner, sid, identity_id)}
        await worker_jobs.cancel_session(owner, sid)

    async def start(self):
        if not settings.BROWSER_MAPPING_ENABLED:
            raise HTTPException(503, 'Browser mapping runtime is disabled')
        async with self.lock:
            if self.pool is None:
                try:
                    from playwright.async_api import async_playwright
                    self.playwright = await async_playwright().start()
                    self.pool = IsolatedBrowserPool(self.playwright, self.authorize, self.fetch, self.cancel)
                except ImportError:
                    raise HTTPException(503, 'Install the optional reviewed browser runtime') from None

    async def preview(self, owner, sid, identity_id, action_id):
        action, _ = await execution_authorization._load(action_id, owner, sid, requester=True)
        if action.tool != 'aria-http':
            raise HTTPException(403, 'An identity-bound HTTP approval is required')
        args = parse(action.command)
        if action.status != 'approved' or args[1] != identity_id:
            raise HTTPException(403, 'Explicit approval for this browser identity is required')
        await self.start()
        key = (owner, sid, identity_id)
        async with self.navigation.setdefault(key, asyncio.Lock()):
            try:
                context = await self.pool.context(*key)
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(503, 'Browser engine unavailable or context capacity reached') from None
            request_key = (*key, args[4], args[5])
            # Navigation uses GET; HEAD remains a replay-only operation.
            if args[4] != 'GET':
                raise HTTPException(409, 'Browser navigation requires an approved GET')
            self.approvals[request_key] = action
            page = await context.new_page()
            try:
                await page.goto(args[5], wait_until='domcontentloaded', timeout=15000)
                screenshot = await page.screenshot(type='png', timeout=5000)
                if len(screenshot) > 3 * 1024 * 1024:
                    raise HTTPException(409, 'Browser preview exceeds limit')
                return screenshot
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(409, 'Browser preview blocked, cancelled or timed out; inspect worker status') from None
            finally:
                self.approvals.pop(request_key, None)
                await page.close()

    async def revoke(self, owner, sid, identity_id):
        if self.pool:
            await self.pool.close_identity(owner, sid, identity_id)

    async def close(self):
        if self.pool:
            try:
                await self.pool.close()
            finally:
                self.pool = None
                self.navigation.clear()
                self.approvals.clear()
        if self.playwright:
            await self.playwright.stop()
            self.playwright = None


browser_mapping = BrowserMapping()
