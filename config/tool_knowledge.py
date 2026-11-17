"""Bounded version-aware tool literacy. Knowledge never authorizes execution."""
from __future__ import annotations

import json
from pathlib import Path

CATALOG = Path(__file__).with_name('tool_knowledge.json')


def catalog() -> list[dict]:
    """Read reviewed descriptive data, without imports, installations or dispatch."""
    if CATALOG.stat().st_size > 100000:
        raise ValueError('Tool knowledge catalog exceeds its bound')
    rows = json.loads(CATALOG.read_text())['tools']
    if len({row['tool'] for row in rows}) != len(rows):
        raise ValueError('Duplicate tool knowledge entry')
    return rows


def for_tools(tools: set[str], capabilities: dict | None = None) -> list[dict]:
    """Only supply facts for already advertised tools; versions remain explicit.

    Declared dependency targets and historical probes are not current executable
    versions. The provider sees an unknown runtime version unless fresh worker
    metadata actually provides one. This catalog grants no capability or scope.
    """
    rows = {row['tool']: row for row in catalog()}
    result = []
    for tool in sorted(tools)[:12]:
        if tool not in rows:
            continue
        row = rows[tool]
        result.append({'tool': tool, 'official_documentation': row['official_documentation'],
                       'reference_version': row['reference_version'],
                       'runtime_version': None,
                       'version_status': 'unknown; reference version does not establish worker version',
                       'interpretation': row['interpretation'],
                       'profile_limits': row['profile_limits'],
                       'authority': 'descriptive knowledge only; server capability, scope and approval still required'})
    return result
