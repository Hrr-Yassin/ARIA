"""
PentestAI v8 — Gemini Client
"""
import time
import httpx
from llm.base_llm import BaseLLMClient


class GeminiClient(BaseLLMClient):

    def __init__(self, api_key: str = "", model: str = "gemini-2.0-flash", temperature: float = 0.1):
        super().__init__(api_key, model, temperature)
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
                candidates = data.get("candidates", [])
                if not candidates:
                    return {"success": False, "content": "", "error": "no_candidates", "latency_ms": latency}

                content = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                tokens = data.get("usageMetadata", {}).get("totalTokenCount", 0)
                return {"success": True, "content": content, "tokens_used": tokens, "latency_ms": latency}
        except httpx.HTTPStatusError as e:
            return {"success": False, "content": "", "error": f"http_{e.response.status_code}", "latency_ms": int((time.monotonic()-start)*1000)}
        except Exception as e:
            return {"success": False, "content": "", "error": "provider_request_failed", "latency_ms": int((time.monotonic()-start)*1000)}
