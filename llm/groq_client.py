"""
PentestAI v8 — Groq Client
"""
import time
import httpx
from llm.base_llm import BaseLLMClient


class GroqClient(BaseLLMClient):

    def __init__(self, api_key: str = "", model: str = "llama-3.3-70b-versatile", temperature: float = 0.1):
        super().__init__(api_key, model, temperature)
        self.provider_name = "Groq"
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"

    async def query(self, prompt: str, system: str = "") -> dict:
        if not self.api_key:
            return {"success": False, "content": "", "error": "no_key"}

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        start = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                r = await client.post(
                    self.base_url,
                    headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                    json={"model": self.model, "messages": messages, "temperature": self.temperature, "max_tokens": 4096},
                )
                latency = int((time.monotonic() - start) * 1000)

                if r.status_code == 429:
                    return {"success": False, "content": "", "error": "rate_limited", "latency_ms": latency}
                r.raise_for_status()

                data = r.json()
                content = data["choices"][0]["message"]["content"]
                tokens = data.get("usage", {}).get("total_tokens", 0)
                return {"success": True, "content": content, "tokens_used": tokens, "latency_ms": latency}
        except httpx.HTTPStatusError as e:
            return {"success": False, "content": "", "error": f"http_{e.response.status_code}", "latency_ms": int((time.monotonic()-start)*1000)}
        except Exception as e:
            return {"success": False, "content": "", "error": str(e), "latency_ms": int((time.monotonic()-start)*1000)}
