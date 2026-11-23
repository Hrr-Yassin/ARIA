"""
PentestAI v8 — OpenRouter Client
"""
import time
from decimal import Decimal, InvalidOperation
import httpx
from config.settings import settings
from llm.base_llm import BaseLLMClient, usage_metrics, response_schema, output_limit
from llm.request_metrics import RequestMetrics, token_components
from llm.saved_review_privacy import prepared_review, saved_review


def provider_receipt(data: dict) -> dict:
    """Retain only accounting fields, never prompts, headers or key metadata."""
    usage = data.get('usage')
    usage = usage if isinstance(usage, dict) else {}
    receipt = {}
    for key in ('prompt_tokens', 'completion_tokens', 'total_tokens'):
        value = usage.get(key)
        if type(value) is int and value >= 0:
            receipt[key] = value
    for key in ('id', 'model', 'provider'):
        value = data.get(key)
        if isinstance(value, str) and len(value) <= 200:
            receipt[key] = value
    choices = data.get('choices')
    reason = (choices[0].get('finish_reason') if isinstance(choices, list)
              and choices and isinstance(choices[0], dict) else None)
    if reason in {'stop', 'length', 'content_filter', 'error', 'tool_calls'}:
        receipt['finish_reason'] = reason
    details = usage.get('cost_details')
    details = details if isinstance(details, dict) else {}
    costs = {'cost': usage.get('cost'), **{
        key: details.get(key) for key in (
            'upstream_inference_cost', 'upstream_inference_prompt_cost',
            'upstream_inference_completions_cost')}}
    for key, value in costs.items():
        try:
            amount = Decimal(str(value))
            if amount.is_finite() and amount >= 0:
                receipt[key] = str(amount)
        except (ValueError, InvalidOperation):
            pass
    prompt_details = usage.get('prompt_tokens_details')
    cached = prompt_details.get('cached_tokens') if isinstance(prompt_details, dict) else None
    if type(cached) is int and cached >= 0:
        receipt['cached_tokens'] = cached
    return receipt


def rate_limit_diagnostics(response) -> dict:
    """Sanitized, bounded facts from a 429 so the cause can be distinguished later.

    Keeps the provider's error code and message, the upstream provider name and
    rate-limit headers. Never the request, credentials or raw upstream payload.
    """
    import re as _re

    def clean(value, limit):
        return _re.sub(r'[^\x20-\x7e]', '', str(value))[:limit] if value is not None else None
    headers = getattr(response, 'headers', {}) or {}
    out = {'http_status': getattr(response, 'status_code', None),
           'retry_after': clean(headers.get('retry-after'), 40),
           'ratelimit': {name: clean(headers.get(name), 40) for name in
                         ('x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset') if headers.get(name)}}
    try:
        body = response.json()
    except Exception:  # noqa: BLE001 - diagnostics are best effort
        body = None
    error = body.get('error') if isinstance(body, dict) else None
    if isinstance(error, dict):
        raw_metadata = error.get('metadata')
        metadata: dict = raw_metadata if isinstance(raw_metadata, dict) else {}
        out.update(code=error.get('code') if isinstance(error.get('code'), (int, str)) else None,
                   message=clean(error.get('message'), 200),
                   provider_name=clean(metadata.get('provider_name'), 60))
    return out


class OpenRouterClient(BaseLLMClient):

    def __init__(self, api_key: str = "", model: str = "deepseek/deepseek-v4-flash", temperature: float = 0.1):
        super().__init__(api_key, model, temperature)
        self.provider_name = "OpenRouter"
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"

    async def query(self, prompt: str, system: str = "") -> dict:
        timing = RequestMetrics()
        metrics = {**usage_metrics({}), **token_components({})}
        if not self.api_key:
            return timing.finish({"success": False, "content": "", "error": "no_key", **metrics})

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
        request_body = {'json': payload}
        if saved_review.get():
            prepared = prepared_review.get()
            try:
                if prepared is None:
                    raise ValueError('Missing saved-review preflight')
                request_body = {'content': prepared.wire_body(
                    payload, url=self.base_url, model=self.model, tariff=tariff)}
            except (ValueError, TypeError, KeyError, OverflowError):
                return timing.finish({'success': False, 'content': '',
                                      'error': 'saved_review_privacy_rejected', **metrics})
        timing.values['request_construction_ms'] = (time.monotonic_ns() - timing.started) / 1e6
        try:
            async with httpx.AsyncClient(timeout=90.0, trust_env=False, follow_redirects=False) as client:
                r = await timing.post(client,
                    self.base_url,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                        "HTTP-Referer": "https://pentestai.local",
                        "X-Title": "PentestAI v8",
                    },
                    **request_body,
                )
                with timing.phase('response_processing_ms'):
                    if r.status_code == 429:
                        result = {"success": False, "content": "", "error": "rate_limited",
                                  "provider_error": rate_limit_diagnostics(r)}
                    else:
                        r.raise_for_status()
                        data = r.json()
                        if not isinstance(data, dict):
                            raise ValueError('Provider response must be an object')
                        usage = data.get('usage')
                        usage = usage if isinstance(usage, dict) else {}
                        # Retain known billable usage even if content/envelope is invalid.
                        metrics = {**usage_metrics(usage), **token_components(usage)}
                        metrics['provider_usage'] = provider_receipt(data)
                        reason = data['choices'][0].get('finish_reason')
                        if data.get('model') != self.model or reason != 'stop':
                            error = ('provider_model_mismatch' if data.get('model') != self.model else
                                     'model_output_truncated' if reason == 'length' else 'provider_response_incomplete')
                            result = {'success': False, 'content': '', 'error': error}
                        else:
                            content = data["choices"][0]["message"]["content"]
                            if not isinstance(content, str) or not content.strip():
                                raise ValueError('Empty provider content')
                            result = {"success": True, "content": content}
        except httpx.TimeoutException:
            result = {"success": False, "content": "", "error": "provider_timeout"}
        except httpx.HTTPStatusError as e:
            result = {"success": False, "content": "", "error": f"http_{e.response.status_code}"}
        except Exception:
            result = {"success": False, "content": "", "error": "provider_request_failed"}
        # Legacy latency remains the observed HTTP attempt, not the mission.
        return timing.finish({**result, **metrics,
            'latency_ms': timing.values['provider_attempt_ms']})
