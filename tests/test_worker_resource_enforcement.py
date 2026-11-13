import tempfile
import unittest
from pathlib import Path
from worker.container_entry import verify_limits


class WorkerResourceTests(unittest.TestCase):
    def test_kernel_limits_are_required_and_unbounded_values_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name,value in [('memory.max','268435456'),('pids.max','64'),('cpu.max','100000 100000')]:
                (root/name).write_text(value)
            verify_limits(root=root)
            for name,value in [('memory.max','max'),('pids.max','max'),('cpu.max','max 100000'),('cpu.max','200000 100000')]:
                original=(root/name).read_text();(root/name).write_text(value)
                with self.assertRaises(RuntimeError):verify_limits(root=root)
                (root/name).write_text(original)
            (root/'memory.max').write_text('1073741824');(root/'pids.max').write_text('128')
            verify_limits(large=True,root=root)
            with self.assertRaises(RuntimeError):verify_limits(root=root)
