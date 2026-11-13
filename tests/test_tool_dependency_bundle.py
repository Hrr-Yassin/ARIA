"""Offline dependency inventory controls; no package installation or build."""
from pathlib import Path
import tempfile
import unittest
from worker.adapters.verify_bundle import inventory


class DependencyBundleTests(unittest.TestCase):
    def test_inventory_binds_bytes_permissions_and_relative_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            binary=root/'binary';binary.write_bytes(b'fixture');binary.chmod(0o755)
            link=root/'link';link.symlink_to('binary')
            first=inventory(root)
            self.assertEqual(first['link'],{'symlink':'binary'})
            binary.chmod(0o644)
            self.assertNotEqual(first,inventory(root))
            binary.chmod(0o755);binary.write_bytes(b'changed')
            self.assertNotEqual(first,inventory(root))
            link.unlink();link.symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):inventory(root)
