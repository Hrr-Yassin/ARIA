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
