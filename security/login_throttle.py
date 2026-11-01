"""Bounded login admission. Redis provides a shared/restart-safe rate window."""
import asyncio
import hashlib
import time
from collections import OrderedDict
from fastapi import HTTPException

SCRIPT = '''
local account = tonumber(redis.call('GET', KEYS[1]) or '0')
local peer = tonumber(redis.call('GET', KEYS[2]) or '0')
if account >= tonumber(ARGV[1]) or peer >= tonumber(ARGV[2]) then return 0 end
for i=1,2 do
  local n = redis.call('INCR', KEYS[i])
  if n == 1 then redis.call('EXPIRE', KEYS[i], ARGV[3]) end
end
return 1
'''


class LoginThrottle:
    def __init__(self, account_limit=5, peer_limit=20, window=300):
        self.account_limit, self.peer_limit, self.window = account_limit, peer_limit, window
        self._buckets = OrderedDict()
        self._lock = asyncio.Lock()

    async def reserve(self, username, peer, redis=None):
        account = 'aria:login:account:' + hashlib.sha256(username.casefold().encode()).hexdigest()
        address = 'aria:login:peer:' + hashlib.sha256(peer.encode()).hexdigest()
        if redis is not None:
            try:
                allowed = await redis.eval(SCRIPT, 2, account, address, self.account_limit, self.peer_limit, self.window)
            except Exception:
                raise HTTPException(503, 'Login admission storage unavailable') from None
            if allowed != 1:
                raise HTTPException(429, 'Login rate limit reached', headers={'Retry-After': str(self.window)})
            return
        # Documented single-process fallback when Redis is not configured.
        async with self._lock:
            now = time.monotonic()
            for key in list(self._buckets):
                if self._buckets[key][1] <= now:
                    del self._buckets[key]
            values = [(key, self._buckets.get(key, (0, now + self.window))) for key in (account, address)]
            if values[0][1][0] >= self.account_limit or values[1][1][0] >= self.peer_limit:
                raise HTTPException(429, 'Login rate limit reached', headers={'Retry-After': str(self.window)})
            if len(self._buckets) + sum(k not in self._buckets for k,_ in values) > 4096:
                raise HTTPException(503, 'Login admission capacity reached')
            for key, (count, deadline) in values:
                self._buckets[key] = (count + 1, deadline)


login_throttle = LoginThrottle()
