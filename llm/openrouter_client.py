"""
PentestAI v8 — OpenRouter Client
"""
import time
from decimal import Decimal, InvalidOperation
import httpx
from config.settings import settings
from llm.base_llm import BaseLLMClient, usage_metrics, response_schema, output_limit


def provider_receipt(data: dict) -> dict:
    """Retain only accounting fields, never prompts, headers or key metadata."""
    usage = data.get('usage') or {}
    receipt = {}
    for key in ('prompt_tokens', 'completion_tokens', 'total_tokens'):
        value = usage.get(key)
        if type(value) is int and value >= 0:
            receipt[key] = value
    for key in ('id', 'model', 'provider'):
        value = data.get(key)
        if isinstance(value, str) and len(value) <= 200:
            receipt[key] = value
    choices = data.get('choices') or []
    reason = choices[0].get('finish_reason') if choices else None
    if reason in {'stop', 'length', 'content_filter', 'error', 'tool_calls'}:
        receipt['finish_reason'] = reason
    costs = {'cost': usage.get('cost'), **{
        key: (usage.get('cost_details') or {}).get(key) for key in (
            'upstream_inference_cost', 'upstream_inference_prompt_cost',
            'upstream_inference_completions_cost')}}
    for key, value in costs.items():
        try:
            amount = Decimal(str(value))
            if amount.is_finite() and amount >= 0:
                receipt[key] = str(amount)
        except (ValueError, InvalidOperation):
            pass
    cached = (usage.get('prompt_tokens_details') or {}).get('cached_tokens')
    if type(cached) is int and cached >= 0:
        receipt['cached_tokens'] = cached
    return receipt


class OpenRouterClient(BaseLLMClient):

    def __init__(self, api_key: str = "", model: str = "deepseek/deepseek-v4-flash", temperature: float = 0.1):
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

        payload = {"model": self.model, "messages": messages,
                   "temperature": self.temperature, "max_tokens": min(settings.OPENROUTER_MAX_OUTPUT_TOKENS, output_limit(settings.OPENROUTER_MAX_OUTPUT_TOKENS)),
                   "provider": {"allow_fallbacks": False, "require_parameters": True}}
        tariff = getattr(self, 'tariff', None)
        if tariff:
            payload['provider'].update(only=[tariff['endpoint']], max_price={
                'prompt': float(tariff['input_usd_per_million']),
                'completion': float(tariff['output_usd_per_million'])})
        schema = response_schema.get()
        if schema:
            payload['response_format'] = {'type': 'json_schema', 'json_schema': {
                'name': 'aria_plan', 'strict': True, 'schema': schema}}
        start = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=90.0, trust_env=False, follow_redirects=False) as client:
                r = await client.post(
                    self.base_url,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                        "HTTP-Referer": "https://pentestai.local",
                        "X-Title": "PentestAI v8",
                    },
                    json=payload,
                )
                latency = int((time.monotonic() - start) * 1000)

                if r.status_code == 429:
                    return {"success": False, "content": "", "error": "rate_limited", "latency_ms": latency}
                r.raise_for_status()

                data = r.json()
                metrics = {**usage_metrics(data.get('usage') or {}), 'provider_usage': provider_receipt(data)}
                reason = data['choices'][0].get('finish_reason')
                if data.get('model') != self.model or reason != 'stop':
                    error = ('provider_model_mismatch' if data.get('model') != self.model else
                             'model_output_truncated' if reason == 'length' else 'provider_response_incomplete')
                    return {'success': False, 'content': '', 'error': error,
                            **metrics, 'latency_ms': latency}
                content = data["choices"][0]["message"]["content"]
                return {"success": True, "content": content, **metrics, "latency_ms": latency}
        except httpx.HTTPStatusError as e:
            return {"success": False, "content": "", "error": f"http_{e.response.status_code}", "latency_ms": int((time.monotonic()-start)*1000)}
        except Exception as e:
            return {"success": False, "content": "", "error": "provider_request_failed", "latency_ms": int((time.monotonic()-start)*1000)}
