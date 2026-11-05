"""Run service tests using only aria_test and Redis 15; never the owner DB.
Uses deployment connection settings without printing credentials.
"""
import os
import subprocess
import sys
from sqlalchemy.engine import make_url
from config.settings import settings

if __name__ == '__main__':
    if os.environ.get('ARIA_DISPOSABLE_SERVICES') != '1':
        raise SystemExit('Set ARIA_DISPOSABLE_SERVICES=1 to reset aria_test and Redis 15')
    url = make_url(settings.DATABASE_URL).set(database='aria_test')
    redis = make_url(settings.REDIS_URL).set(database='15')
    env = {**os.environ, 'DATABASE_URL':url.render_as_string(hide_password=False),
        'REDIS_URL':redis.render_as_string(hide_password=False), 'ARIA_INTEGRATION':'1'}
    raise SystemExit(subprocess.run([sys.executable, '-B', '-m', 'unittest', 'integration.test_services', '-v'], env=env).returncode)
