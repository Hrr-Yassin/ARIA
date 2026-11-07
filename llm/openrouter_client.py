"""
PentestAI v8 — OpenRouter Client
"""
import time
import httpx
from llm.base_llm import BaseLLMClient, usage_metrics


class OpenRouterClient(BaseLLMClient):

    def __init__(self, api_key: str = "", model: str = "anthropic/claude-sonnet-4-5", temperature: float = 0.1):
        super().__init__(api_key, model, temperature)
        self.provider_name = "OpenRouter"
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"

    async def query(self, prompt: str, system: str = "") -> dict:
        if not self.api_key:
            return {"success": False, "content": "", "error": "no_key"}

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        start = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=90.0) as client:
                r = await client.post(
                    self.base_url,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                        "HTTP-Referer": "https://pentestai.local",
                        "X-Title": "PentestAI v8",
                    },
                    json={"model": self.model, "messages": messages, "temperature": self.temperature, "max_tokens": 4096},
                )
                latency = int((time.monotonic() - start) * 1000)

                if r.status_code == 429:
                    return {"success": False, "content": "", "error": "rate_limited", "latency_ms": latency}
                r.raise_for_status()

                data = r.json()
                content = data["choices"][0]["message"]["content"]
                metrics = usage_metrics(data.get("usage") or {})
                return {"success": True, "content": content, **metrics, "latency_ms": latency}
        except httpx.HTTPStatusError as e:
            return {"success": False, "content": "", "error": f"http_{e.response.status_code}", "latency_ms": int((time.monotonic()-start)*1000)}
        except Exception as e:
            return {"success": False, "content": "", "error": "provider_request_failed", "latency_ms": int((time.monotonic()-start)*1000)}
