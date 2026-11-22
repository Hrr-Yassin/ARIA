"""Prompt context and structured-output schema compaction (P3).

Compaction removes bytes that carry no information for generation: generated
titles and defaults in JSON schemas (validation is performed by Pydantic, not by
the schema) and insignificant JSON whitespace. Every compaction is lossless for
the model-facing contract: required fields, enums, bounds and
``additionalProperties`` are preserved.
"""
from __future__ import annotations

import json
from typing import Any

_SCHEMA_NOISE = frozenset({'title', 'default', 'description', 'examples'})


def compact_schema(schema: Any) -> Any:
    """Drop schema annotations that do not constrain generated output."""
    if isinstance(schema, dict):
        result = {}
        for key, value in schema.items():
            # Keep property *names* such as a field literally called "title".
            if key in _SCHEMA_NOISE and not isinstance(value, dict):
                continue
            result[key] = (value if key in {'properties', '$defs'} and not isinstance(value, dict)
                           else compact_schema(value))
        if 'properties' in schema and isinstance(schema['properties'], dict):
            result['properties'] = {name: compact_schema(prop) for name, prop in schema['properties'].items()}
        return result
    if isinstance(schema, list):
        return [compact_schema(item) for item in schema]
    return schema


def compact_json(value: Any) -> str:
    """Minimal JSON encoding for prompt context."""
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False)


def estimate_tokens(text: str) -> int:
    """Conservative planning estimate (UTF-8 bytes / 4); billing uses provider receipts."""
    return (len(text.encode()) + 3) // 4
