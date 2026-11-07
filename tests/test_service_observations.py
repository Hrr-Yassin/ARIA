"""Port/version discovery cannot establish a vulnerability's severity."""
from agents.orchestrator_agent import orchestrator_agent
from tests.support import OfflineCase


class ServiceObservationTests(OfflineCase):
    async def test_common_ports_and_suspect_versions_remain_unverified(self):
        output = '\n'.join([
            '21/tcp open ftp vsftpd 2.3.4',
            '23/tcp open telnet Linux telnetd',
            '80/tcp open http Apache httpd 2.2.8',
            '443/tcp open https Apache httpd',
            '4444/tcp open irc UnrealIRCd',
        ])
        result = orchestrator_agent._parse_output_basic(
            'nmap', 'nmap -sT -p 21,23,80,443,4444 192.0.2.1', output, '192.0.2.1')
        self.assertEqual(result['verbose']['open_ports_count'], 5)
        self.assertEqual(len(result['findings']), 5)
        self.assertEqual(result['risk_level'], 'INFO')
        self.assertIn('no vulnerability has been verified', result['chat_message'])
        for finding in result['findings']:
            self.assertEqual(finding['severity'], 'info')
            self.assertEqual(finding['vulnerability_type'], 'service_observation')
            self.assertIn('vulnerability status is unverified', finding['description'])
            self.assertEqual(finding['cve_ids'], [])
            self.assertIn(finding['evidence'], output)
