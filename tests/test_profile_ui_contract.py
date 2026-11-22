"""Mission Control profile panel versus the backend it must reflect (P4)."""
from types import SimpleNamespace

from tests.support import OfflineCase
from tests.test_engagement_profiles import lab, scope_for


class UiBackendContract(OfflineCase):
    """Mission Control's profile panel must only use what the backend serves and enforces."""

    def source(self):
        from pathlib import Path
        return Path('web/mission-control/src/profiles.ts').read_text()

    async def test_panel_endpoints_exist_with_the_methods_it_uses(self):
        import re
        from api.main import app
        routes = {(getattr(route, 'path', ''), method) for route in app.routes for method in getattr(route, 'methods', set())}
        self.assertIn(('/api/engagements/{session_id}/profile', 'GET'), routes)
        self.assertIn(('/api/engagements/{session_id}/profile', 'POST'), routes)
        self.assertIn(('/api/engagements/profile-kinds', 'GET'), routes)
        used = set(re.findall(r"/api/engagements/[^`'\s]*", self.source()))
        self.assertEqual(used, {'/api/engagements/${encodeURIComponent(sid)}/profile', '/api/engagements/profile-kinds'})

    async def test_panel_kinds_and_fields_match_backend(self):
        import re
        from api.auth import get_current_user
        from api.main import app
        from memory.engagement_profiles import ProfileKind, describe
        source = self.source()
        ui_kinds = re.findall(r"\['(private_lab|ctf|authorized_pentest|bug_bounty)', '", source)
        self.assertEqual(ui_kinds, list(ProfileKind.__args__))  # type: ignore[attr-defined]
        app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(user_id='owner', role='admin')
        try:
            kinds = (await self.client.get('/api/engagements/profile-kinds')).json()['kinds']
        finally:
            app.dependency_overrides.pop(get_current_user, None)
        self.assertEqual(sorted(kinds), sorted(ui_kinds))
        self.assertTrue(all('required' in spec for spec in kinds.values()))
        configured = describe(scope_for(lab())['engagement_profile'])
        self.assertIn('restrictions.enforced', source)
        self.assertIn('restrictions.warning', source)
        self.assertIn('permitted_capabilities', configured['enforced'])
        self.assertIn('warning', describe(None))
        for field in ('denied_operations', 'history', 'restrictions', 'profile'):
            self.assertIn(f'view.{field}', source)
        self.assertNotIn('setInterval', source)       # no client-side policy state independent of the backend
