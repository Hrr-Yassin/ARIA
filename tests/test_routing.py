from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tests.support import OfflineCase


class RoutingTests(OfflineCase):
    async def test_encoded_traversal_never_serves_source(self):
        for path in ('/%2e%2e/config/settings.py', '/%2e%2e/.env', '/web/%2e%2e/%2e%2e/config/settings.py'):
            with self.subTest(path=path):
                response = await self.client.get(path)
                self.assertEqual(response.status_code, 404)

    async def test_unknown_api_is_json_404(self):
        response = await self.client.get('/api/not-a-real-route')
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers['content-type'], 'application/json')

    async def test_only_explicit_ui_pages_are_served(self):
        for path in ('/', '/login', '/login.html', '/admin', '/admin.html', '/chat/session'):
            with self.subTest(path=path):
                self.assertEqual((await self.client.get(path)).status_code, 200)
        self.assertEqual((await self.client.get('/static/scripts/app.js')).status_code, 200)
        self.assertEqual((await self.client.get('/arbitrary-file.py')).status_code, 404)

    async def test_unknown_path_cannot_follow_web_symlink(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'index.html').write_text('UI')
            (root / 'leak').symlink_to(Path('config/settings.py').resolve())
            with patch('api.main.WEB_DIR', root):
                self.assertEqual((await self.client.get('/leak')).status_code, 404)
