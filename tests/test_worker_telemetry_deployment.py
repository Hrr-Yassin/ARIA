"""Offline maintenance transactions never contact a guest or execute a tool."""
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from deploy.lab import worker_telemetry as telemetry


class WorkerTelemetryDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.directory = self.enterContext(TemporaryDirectory())
        self.root = Path(self.directory)
        self.source = self.root/'source'
        (self.source/'worker').mkdir(parents=True)
        self.worker = self.root/'installed'
        self.worker.mkdir()
        self.old = b'VERSION = "old"\n'
        self.payload = {'observability.py': b'ENABLED = True\n',
                        'service.py': b'import worker.observability\n'}
        self.enterContext(patch.object(telemetry, 'BASE_SERVICE_SHA', telemetry.digest(self.old)))
        self.enterContext(patch.object(telemetry, 'REVIEWED_SHA',
            {name: telemetry.digest(data) for name, data in self.payload.items()}))
        (self.worker/'service.py').write_bytes(self.old)
        (self.worker/'service.py').chmod(0o640)
        for name, data in self.payload.items():
            (self.source/'worker'/name).write_bytes(data)
        self.bundle = self.root/'bundle'
        telemetry.prepare_bundle(self.source, self.bundle)
        self.quiescent, self.restart, self.verify = Mock(return_value=True), Mock(), Mock(return_value=True)

    def install(self, **kwargs):
        return telemetry.install_reviewed_files(self.worker, self.bundle,
            owner_authorized=kwargs.get('authorized', True), quiescent=self.quiescent,
            restart=self.restart, verify_running=self.verify)

    def assert_original(self):
        self.assertEqual((self.worker/'service.py').read_bytes(), self.old)
        self.assertEqual(stat.S_IMODE((self.worker/'service.py').stat().st_mode), 0o640)
        self.assertFalse((self.worker/'observability.py').exists())

    def test_success_replaces_exact_files_preserving_identity_and_modes(self):
        previous = (self.worker/'service.py').stat()
        result = self.install()
        self.assertEqual(result.status, 'APPLIED')
        for name, data in self.payload.items():
            path = self.worker/name
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual((path.stat().st_uid, path.stat().st_gid), (previous.st_uid, previous.st_gid))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
        self.assertEqual((Path(result.backup)/'service.py').read_bytes(), self.old)
        self.assertEqual(self.quiescent.call_count, 2)
        self.restart.assert_called_once()
        self.verify.assert_called_once()

    def test_no_approval_causes_no_check_restart_or_write(self):
        with self.assertRaises(PermissionError):
            self.install(authorized=False)
        self.assert_original()
        self.quiescent.assert_not_called()
        self.restart.assert_not_called()
        self.assertEqual(list(self.worker.iterdir()), [self.worker/'service.py'])

    def test_initial_quiescence_unknown_causes_no_source_change(self):
        self.quiescent.return_value = None
        with self.assertRaises(RuntimeError):
            self.install()
        self.assert_original()
        self.restart.assert_not_called()

    def test_changed_baseline_and_tampered_bundle_are_refused(self):
        path = self.worker/'service.py'
        path.write_bytes(b'owner edit')
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(path.read_bytes(), b'owner edit')
        path.write_bytes(self.old)
        (self.bundle/'service.py').write_bytes(b'tampered')
        with self.assertRaises(ValueError):
            self.install()
        self.assert_original()
        self.restart.assert_not_called()

    def test_existing_observer_and_symlink_are_not_overwritten(self):
        observer = self.worker/'observability.py'
        observer.write_bytes(b'owner module')
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(observer.read_bytes(), b'owner module')
        observer.unlink()
        observer.symlink_to(self.bundle/'observability.py')
        with self.assertRaises(ValueError):
            self.install()
        self.assertTrue(observer.is_symlink())
        self.restart.assert_not_called()

    def test_partial_replace_failure_restores_files_without_restart(self):
        replace = os.replace
        def fail_service(source, destination):
            if Path(destination).name == 'service.py':
                raise OSError('injected stage failure')
            return replace(source, destination)
        with patch('deploy.lab.worker_telemetry.os.replace', side_effect=fail_service):
            result = self.install()
        self.assertEqual(result.status, 'FAILED')
        self.assertTrue(result.files_restored)
        self.assert_original()
        self.restart.assert_not_called()
        self.assertFalse(list(self.worker.glob('.telemetry-stage-*')))

    def test_post_start_failure_restores_original_then_verifies_restart(self):
        self.verify.side_effect = [False, True]
        result = self.install()
        self.assertEqual(result.status, 'FAILED')
        self.assertTrue(result.files_restored)
        self.assertTrue(result.service_restored)
        self.assert_original()
        self.assertEqual(self.restart.call_count, 2)

    def test_failed_new_restart_restores_old_service(self):
        self.restart.side_effect = [RuntimeError('injected startup failure'), None]
        result = self.install()
        self.assertEqual(result.status, 'FAILED')
        self.assertTrue(result.files_restored and result.service_restored)
        self.assert_original()

    def test_failed_old_restart_does_not_claim_service_restored(self):
        self.restart.side_effect = [RuntimeError('new failed'), RuntimeError('old failed')]
        result = self.install()
        self.assertTrue(result.files_restored)
        self.assertFalse(result.service_restored)
        self.assert_original()

    def test_lost_quiescence_rolls_back_before_starting_any_service(self):
        self.quiescent.side_effect = [True, False]
        result = self.install()
        self.assertEqual(result.status, 'FAILED')
        self.assertTrue(result.files_restored)
        self.assert_original()
        self.restart.assert_not_called()

    def test_external_edit_during_failed_start_requires_manual_reconciliation(self):
        def changed():
            (self.worker/'service.py').write_bytes(b'operator edit during maintenance')
            return False
        self.verify.side_effect = changed
        result = self.install()
        self.assertEqual(result.status, 'FAILED')
        self.assertFalse(result.files_restored or result.service_restored)
        self.assertEqual((self.worker/'service.py').read_bytes(), b'operator edit during maintenance')
        self.restart.assert_called_once()

    def test_bundle_generation_refuses_reuse_and_unreviewed_source(self):
        with self.assertRaises(FileExistsError):
            telemetry.prepare_bundle(self.source, self.bundle)
        (self.source/'worker'/'service.py').write_bytes(b'changed source')
        with self.assertRaises(ValueError):
            telemetry.prepare_bundle(self.source, self.root/'other-bundle')
        self.assertFalse((self.root/'other-bundle').exists())
