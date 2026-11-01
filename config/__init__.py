"""ARIA supports CPython 3.11; native dependency locks are validated for this series."""
import sys

if sys.version_info[:2] != (3, 11):
    raise RuntimeError("ARIA requires Python 3.11; create a Python 3.11 virtual environment")
