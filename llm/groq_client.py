"""
PentestAI v8 — Groq Client
"""
import time
import httpx
from llm.base_llm import BaseLLMClient, usage_metrics
from llm.request_metrics import RequestMetrics, token_components


class GroqClient(BaseLLMClient):

    def __init__(self, api_key: str = "", model: str = "llama-3.3-70b-versatile", temperature: float = 0.1):
        super().__init__(api_key, model, temperature)
        self.provider_name = "Groq"
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"

    async def query(self, prompt: str, system: str = "") -> dict:
        timing = RequestMetrics()
        metrics = {**usage_metrics({}), **token_components({})}
        def finish(result):
            return timing.finish({**result, **metrics, 'latency_ms': timing.values['provider_attempt_ms']})
        if not self.api_key:
            return finish({"success": False, "content": "", "error": "no_key"})

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {"model": self.model, "messages": messages, "temperature": self.temperature, "max_tokens": 4096}
        timing.values['request_construction_ms'] = (time.monotonic_ns() - timing.started) / 1e6
        try:
            async with httpx.AsyncClient(timeout=60.0, trust_env=False, follow_redirects=False) as client:
                r = await timing.post(client,
                    self.base_url,
                    headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                    json=payload,
                )
                with timing.phase('response_processing_ms'):
                    if r.status_code == 429:
                        result = {"success": False, "content": "", "error": "rate_limited"}
                    else:
                        r.raise_for_status()
                        data = r.json()
                        usage = data.get('usage')
                        usage = usage if isinstance(usage, dict) else {}
                        metrics = {**usage_metrics(usage), **token_components(usage)}
                        if data['choices'][0].get('finish_reason') == 'length':
                            result = {'success': False, 'content': '', 'error': 'model_output_truncated'}
                        else:
                            content = data["choices"][0]["message"]["content"]
                            if not isinstance(content, str) or not content.strip():
                                raise ValueError('Invalid model content')
                            result = {"success": True, "content": content}
        except httpx.TimeoutException:
            result = {"success": False, "content": "", "error": "provider_timeout"}
        except httpx.HTTPStatusError as e:
            result = {"success": False, "content": "", "error": f"http_{e.response.status_code}"}
        except Exception:
            result = {"success": False, "content": "", "error": "provider_request_failed"}
        return finish(result)
