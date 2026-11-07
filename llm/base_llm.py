"""
PentestAI v8 — Base LLM Client
"""
import time
from abc import ABC, abstractmethod
from typing import Optional


class BaseLLMClient(ABC):
    """Abstract base for all LLM provider clients."""

    def __init__(self, api_key: str = "", model: str = "", temperature: float = 0.1):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.provider_name = "unknown"

    @abstractmethod
    async def query(self, prompt: str, system: str = "") -> dict:
        """
        Send prompt to LLM.
        Returns: {"success": bool, "content": str, "tokens_used": int, "latency_ms": int, "error": str}
        """
        pass

    def is_configured(self) -> bool:
        return bool(self.api_key)


def usage_metrics(usage: dict, token_field: str = 'total_tokens') -> dict:
    """Preserve unknown provider usage; optional cost is reported USD, not a tariff."""
    from decimal import Decimal, InvalidOperation, ROUND_CEILING
    tokens = usage.get(token_field)
    tokens = tokens if type(tokens) is int and tokens >= 0 else None
    cost = None
    try:
        raw = Decimal(str(usage['cost']))
        if raw.is_finite() and raw >= 0:
            cost = int((raw * 1000000).to_integral_value(rounding=ROUND_CEILING))
    except (KeyError, InvalidOperation, ValueError, TypeError):
        pass
    return {'tokens_used': tokens, 'cost_microusd': cost}
