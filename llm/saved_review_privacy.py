"""Wire contract for saved-evidence reviews.

The builder supplies bare JSON. The provider receives exactly one
untrusted-engagement envelope containing that JSON.
"""
from contextvars import ContextVar
from dataclasses import dataclass
import json
import re

from security.redaction import redact

OPEN_TAG = '<untrusted_engagement_data>'
CLOSE_TAG = '</untrusted_engagement_data>'
OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions'
REVIEW_QUESTIONS = (
    'Identify plausible defensive interpretations and missing evidence.',
    'Challenge the prior interpretations and identify contradictory or missing evidence.',
)
DISPOSITIONS = {'supported', 'rejected', 'inconclusive'}
SECRET_LITERAL = re.compile(r'\b(?:sk-(?:or-)?[A-Za-z0-9_-]{16,}|Bearer\s+[A-Za-z0-9_.-]{12,})\b|-----BEGIN [^-]*PRIVATE KEY-----', re.I)
saved_review: ContextVar[bool] = ContextVar('saved_review', default=False)


class ReviewPrivacyError(ValueError):
    """A saved-review request violates the outbound contract."""


def require(condition: bool) -> None:
    if not condition:
        raise ReviewPrivacyError('Saved review payload rejected')


def wrap_engagement_data(prompt: str) -> str:
    return f'{OPEN_TAG}\n{prompt}\n{CLOSE_TAG}'


def unique_fields(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def validate_review_json(prompt: str, *, wrapped: bool, secrets=()) -> dict:
    """Accept bare builder JSON or the exact wire envelope, as selected by the caller."""
    if wrapped:
        prefix, suffix = OPEN_TAG + '\n', '\n' + CLOSE_TAG
        require(prompt.startswith(prefix) and prompt.endswith(suffix))
        prompt = prompt[len(prefix):-len(suffix)]
    require(len(prompt) <= 64000)
    try:
        body = json.loads(prompt, object_pairs_hook=unique_fields)
    except (ValueError, RecursionError) as error:
        raise ReviewPrivacyError('Saved review JSON rejected') from error

    def text(value: object, limit: int) -> None:
        require(isinstance(value, str) and 0 < len(value) <= limit and bool(value.strip()))
        require(OPEN_TAG not in value.lower() and CLOSE_TAG not in value.lower())
        require(not SECRET_LITERAL.search(value) and redact(value, secrets) == value)
        require(not any(ord(char) < 32 and char not in '\n\r\t' for char in value))

    require(isinstance(body, dict) and set(body) == {
        'question', 'objective', 'saved_observations', 'unverified_prior_claims'})
    require(body['question'] in REVIEW_QUESTIONS)
    text(body['objective'], 4000)
    observations = body['saved_observations']
    require(isinstance(observations, list) and 0 < len(observations) <= 100)
    ids = set()
    for record in observations:
        keys = {'id', 'summary', 'command', 'provenance'}
        require(isinstance(record, dict) and keys <= record.keys() <= keys | {'truncated'})
        require(record['command'] == '' and type(record.get('truncated', False)) is bool)
        text(record['id'], 100)
        text(record['provenance'], 100)
        if record['summary'] != '':
            text(record['summary'], 6000)
        require(record['id'] not in ids)
        ids.add(record['id'])
    claims = body['unverified_prior_claims']
    require(isinstance(claims, list) and len(claims) <= 10)
    require(body['question'] == REVIEW_QUESTIONS[1] or not claims)
    for claim in claims:
        require(isinstance(claim, dict) and set(claim) == {
            'task_id', 'run_id', 'description', 'evidence_references', 'disposition'})
        for key in ('task_id', 'run_id', 'description'):
            text(claim[key], 500 if key == 'description' else 100)
        refs = claim['evidence_references']
        require(isinstance(refs, list) and 0 < len(refs) <= 100
                and all(isinstance(ref, str) and ref in ids for ref in refs))
        require(isinstance(claim['disposition'], str) and claim['disposition'] in DISPOSITIONS)
    return body


@dataclass(frozen=True)
class PreparedReview:
    prompt: str
    system: str

    def wire_body(self, payload: dict, *, url: str, model: str, tariff: dict | None) -> bytes:
        require(url == OPENROUTER_URL)
        raw = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode()
        wire = json.loads(raw)
        require(set(wire) == {'messages', 'model', 'temperature', 'max_tokens', 'provider'})
        require(wire['model'] == model and type(wire['max_tokens']) is int and wire['max_tokens'] > 0)
        require(type(wire['temperature']) in (float, int) and 0 <= wire['temperature'] <= 2)
        require(wire['messages'] == [{'role': 'system', 'content': self.system},
                                     {'role': 'user', 'content': self.prompt}])
        validate_review_json(wire['messages'][1]['content'], wrapped=True)
        require(bool(tariff) and wire['provider'] == {
            'allow_fallbacks': False, 'require_parameters': True, 'only': [tariff['endpoint']],
            'max_price': {'prompt': float(tariff['input_usd_per_million']),
                          'completion': float(tariff['output_usd_per_million'])}})
        return raw


prepared_review: ContextVar[PreparedReview | None] = ContextVar('prepared_review', default=None)
