"""Optional hard budget for live validation, shared across async child tasks.
Reserve an upper bound before every physical provider call, including failures.
"""
from contextvars import ContextVar
from dataclasses import dataclass

current_budget = ContextVar('aria_validation_budget', default=None)


@dataclass
class ValidationBudget:
    max_calls: int = 20
    max_tokens: int = 40000
    calls: int = 0
    reserved_tokens: int = 0
    actual_tokens: int = 0
    ledger_path: str | None = None

    def reserve(self, prompt, system, output_limit):
        # UTF-8 byte count is a conservative input-token ceiling, not a tokenizer estimate.
        ceiling = len((prompt + system).encode('utf-8')) + output_limit
        if self.calls >= self.max_calls or self.reserved_tokens + ceiling > self.max_tokens:
            return False
        self.calls += 1
        self.reserved_tokens += ceiling
        self.persist()
        return True

    def record(self, actual):
        if isinstance(actual, int) and actual > 0:
            self.actual_tokens += actual
            self.persist()

    def persist(self):
        if self.ledger_path is None: return
        import json,os
        from pathlib import Path
        target=Path(self.ledger_path)
        temporary=target.with_suffix('.tmp')
        temporary.write_text(json.dumps(self.snapshot()))
        temporary.chmod(0o600)
        os.replace(temporary,target)

    def snapshot(self):
        return {'calls':self.calls, 'reserved_token_ceiling':self.reserved_tokens,
            'reported_actual_tokens':self.actual_tokens, 'max_calls':self.max_calls, 'max_tokens':self.max_tokens}
