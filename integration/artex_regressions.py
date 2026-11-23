"""Run ARIA offline regressions for the retained-record observability mission."""

from pathlib import Path
import unittest


if __name__ == '__main__':
    directory = Path(__file__).resolve().parents[1] / 'tests'
    modules = ['tests.' + path.stem for path in sorted(directory.glob('test_*.py'))
               if path.stem != 'test_research_lab']
    print('Offline cohort excludes the vulnerability reproduction tests in tests.test_research_lab.', flush=True)
    suite = unittest.defaultTestLoader.loadTestsFromNames(modules)
    raise SystemExit(not unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful())
