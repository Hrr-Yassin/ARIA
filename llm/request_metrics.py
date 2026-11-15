"""Monotonic client timings with explicit boundaries and unavailable fields.

Provider HTTP duration is client-observed request/response time, including
network and server work. It is not model inference time or mission duration.
No prompt, response, credential, wall-clock subtraction or authority is stored.
"""
from contextlib import contextmanager
import math
import time

TIMING_FIELDS = ('request_construction_ms', 'provider_discovery_ms',
                 'provider_attempt_ms', 'response_processing_ms',
                 'structured_validation_ms', 'client_total_ms', 'pool_attempt_ms')


class RequestMetrics:
    def __init__(self):
        self.started = time.monotonic_ns()
        self.values = dict.fromkeys(TIMING_FIELDS)
        self.http_attempts = 0

    @contextmanager
    def phase(self, name):
        begin = time.monotonic_ns()
        try:
            yield
        finally:
            elapsed = (time.monotonic_ns() - begin) / 1e6
            self.values[name] = (self.values[name] or 0) + elapsed

    async def post(self, client, *args, **kwargs):
        self.http_attempts += 1
        with self.phase('provider_attempt_ms'):
            return await client.post(*args, **kwargs)

    def finish(self, result):
        self.values['client_total_ms'] = (time.monotonic_ns() - self.started) / 1e6
        return {**result, 'timings': {**self.values, 'http_attempts': self.http_attempts}}


def token_components(usage):
    usage = usage if isinstance(usage, dict) else {}
    def count(key):
        value = usage.get(key)
        return value if type(value) is int and value >= 0 else None
    return {'input_tokens': count('prompt_tokens'), 'output_tokens': count('completion_tokens')}


def safe_timings(value):
    """Only finite nonnegative closed fields enter the durable attempt ledger."""
    value = value if isinstance(value, dict) else {}
    result = {}
    for key in TIMING_FIELDS:
        number = value.get(key)
        result[key] = (number if type(number) in {int, float} and math.isfinite(number)
                       and 0 <= number <= 86400000 else None)
    attempts = value.get('http_attempts')
    result['http_attempts'] = attempts if type(attempts) is int and 0 <= attempts <= 100 else None
    return result
