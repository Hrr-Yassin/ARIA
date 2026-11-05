"""
PentestAI v8 — Gemini Client
"""
import time
import httpx
from llm.base_llm import BaseLLMClient, usage_metrics
from config.settings import settings


class GeminiClient(BaseLLMClient):

    def __init__(self, api_key: str = "", model: str = "", temperature: float = 0.1):
        super().__init__(api_key, model or settings.GEMINI_MODEL, temperature)
        self.provider_name = "Gemini"

    async def query(self, prompt: str, system: str = "") -> dict:
        if not self.api_key:
            return {"success": False, "content": "", "error": "no_key"}

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        parts = []
        if system:
            parts.append({"text": system + "\n\n"})
        parts.append({"text": prompt})

        start = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                r = await client.post(url, headers={"x-goog-api-key": self.api_key}, json={
                    "contents": [{"parts": parts}],
                    "generationConfig": {"temperature": self.temperature, "maxOutputTokens": 4096},
                })
                latency = int((time.monotonic() - start) * 1000)

                if r.status_code == 429:
                    return {"success": False, "content": "", "error": "rate_limited", "latency_ms": latency}
                r.raise_for_status()

                data = r.json()
                metrics = usage_metrics(data.get("usageMetadata") or {}, "totalTokenCount")
                candidates = data.get("candidates", [])
                if not candidates:
                    return {"success": False, "content": "", "error": "no_candidates", **metrics, "latency_ms": latency}

                parts = candidates[0].get("content", {}).get("parts", [])
                content = "".join(part.get("text", "") for part in parts if not part.get("thought"))
                if not content.strip():
                    return {"success": False, "content": "", "error": "empty_response", **metrics, "latency_ms": latency}
                return {"success": True, "content": content, **metrics, "latency_ms": latency}
        except httpx.HTTPStatusError as e:
            return {"success": False, "content": "", "error": f"http_{e.response.status_code}", "latency_ms": int((time.monotonic()-start)*1000)}
        except Exception as e:
            return {"success": False, "content": "", "error": "provider_request_failed", "latency_ms": int((time.monotonic()-start)*1000)}
