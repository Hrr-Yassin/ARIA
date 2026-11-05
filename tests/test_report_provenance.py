from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch
from agents.report_agent import ReportAgent
from tests.support import OfflineCase
from tests.test_access import OWNER, SESSION


class ReportProvenanceTests(OfflineCase):
    async def test_capture_manifest_in_all_text_report_formats(self):
        reference='71ebbbd0-5351-4dda-96ea-7adc918d6cff'
        logs=[{'id':reference,'type':'burp_evidence','data':{'protected_original':'never-export-ciphertext',
            'summary':{'method':'GET','url':'http://192.0.2.1/'}}}]
        with TemporaryDirectory() as directory, patch('config.settings.settings.REPORT_OUTPUT_DIR',directory), patch('api.auth.current_identity',AsyncMock(return_value=OWNER)), patch('api.session_access.get_accessible_session',AsyncMock(return_value=SESSION)), patch('memory.session_manager.session_manager.get_findings_summary',AsyncMock(return_value={'findings':[],'counts':{},'total':0})), patch('memory.session_manager.session_manager.get_chat_logs',AsyncMock(return_value=logs)), patch('agents.report_agent.register_report',AsyncMock()):
            for fmt in ['html','markdown','latex']:
                with self.subTest(format=fmt):
                    result=await ReportAgent().generate_report('engagement','owner',fmt)
                    content=Path(result['filepath']).read_text()
                    self.assertIn(reference,content)
                    self.assertNotIn('never-export-ciphertext',content)
                    self.assertEqual(result['findings_count'],0)
