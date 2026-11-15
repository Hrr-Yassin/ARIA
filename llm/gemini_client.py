"""
PentestAI v8 — Gemini Client
"""
import time
import httpx
from llm.base_llm import BaseLLMClient, usage_metrics
from llm.request_metrics import RequestMetrics, token_components
from config.settings import settings


class GeminiClient(BaseLLMClient):

    def __init__(self, api_key: str = "", model: str = "", temperature: float = 0.1):
        super().__init__(api_key, model or settings.GEMINI_MODEL, temperature)
        self.provider_name = "Gemini"

    async def query(self, prompt: str, system: str = "") -> dict:
        timing = RequestMetrics()
        metrics = {**usage_metrics({}), **token_components({})}
        def finish(result):
            return timing.finish({**result, **metrics, 'latency_ms': timing.values['provider_attempt_ms']})
        if not self.api_key:
            return finish({"success": False, "content": "", "error": "no_key"})

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        parts = []
        if system:
            parts.append({"text": system + "\n\n"})
        parts.append({"text": prompt})

        payload = {"contents": [{"parts": parts}],
                   "generationConfig": {"temperature": self.temperature, "maxOutputTokens": 4096}}
        timing.values['request_construction_ms'] = (time.monotonic_ns() - timing.started) / 1e6
        try:
            async with httpx.AsyncClient(timeout=60.0, trust_env=False, follow_redirects=False) as client:
                r = await timing.post(client, url, headers={"x-goog-api-key": self.api_key}, json=payload)
                with timing.phase('response_processing_ms'):
                    if r.status_code == 429:
                        result = {"success": False, "content": "", "error": "rate_limited"}
                    else:
                        r.raise_for_status()
                        data = r.json()
                        usage = data.get('usageMetadata')
                        usage = usage if isinstance(usage, dict) else {}
                        metrics = {**usage_metrics(usage, 'totalTokenCount'), **token_components({
                            'prompt_tokens': usage.get('promptTokenCount'),
                            'completion_tokens': usage.get('candidatesTokenCount')})}
                        candidates = data.get("candidates", [])
                        if not candidates:
                            result = {"success": False, "content": "", "error": "no_candidates"}
                        elif candidates[0].get('finishReason') == 'MAX_TOKENS':
                            result = {'success': False, 'content': '', 'error': 'model_output_truncated'}
                        else:
                            parts = candidates[0].get("content", {}).get("parts", [])
                            content = "".join(part.get("text", "") for part in parts if not part.get("thought"))
                            result = ({"success": True, "content": content} if content.strip() else
                                      {"success": False, "content": "", "error": "empty_response"})
        except httpx.TimeoutException:
            result = {"success": False, "content": "", "error": "provider_timeout"}
        except httpx.HTTPStatusError as e:
            result = {"success": False, "content": "", "error": f"http_{e.response.status_code}"}
        except Exception:
            result = {"success": False, "content": "", "error": "provider_request_failed"}
        return finish(result)
