"""Loopback-only OpenAI-compatible model transport; never follows redirects."""
import time

import httpx
import structlog
from config.settings import settings
from llm.base_llm import BaseLLMClient, usage_metrics, response_schema, output_limit
from llm.request_metrics import RequestMetrics, token_components, native_provider_timings

logger = structlog.get_logger(__name__)


class LocalClient(BaseLLMClient):
    def __init__(self, api_key: str = "", model: str = "", temperature: float = 0.1):
        super().__init__(api_key=api_key, model=model, temperature=temperature)
        self._ollama_base = ""

    async def available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=3, trust_env=False, follow_redirects=False) as client:
                response = await client.get(settings.LOCAL_LLM_URL + '/models')
                response.raise_for_status()
                installed = any(item.get('id') == self.model for item in response.json().get('data', []))
                if not installed:
                    return False
                # Ollama's native chat endpoint supports think=false for Qwen3;
                # its OpenAI-compatible endpoint does not reliably expose that control.
                if settings.LOCAL_LLM_URL.endswith('/v1'):
                    base = settings.LOCAL_LLM_URL[:-3]
                    probe = await client.get(base + '/api/version')
                    if probe.is_success and isinstance(probe.json().get('version'), str):
                        self._ollama_base = base
                return True
        except (httpx.HTTPError, ValueError, TypeError, AttributeError):
            return False

    async def query(self, prompt: str, system: str = '') -> dict:
        timing = RequestMetrics()
        with timing.phase('request_construction_ms'):
            messages = [{'role': 'system', 'content': system}, {'role': 'user', 'content': prompt}]
            schema = response_schema.get()
            token_limit = output_limit(768 if schema else 192)
        endpoint_kind = 'ollama_native' if self._ollama_base else 'openai_compatible'
        metrics = {**usage_metrics({}), **token_components({}), 'cost_microusd': 0}
        try:
            async with httpx.AsyncClient(timeout=180 if schema else 60, trust_env=False, follow_redirects=False) as client:
                if not self._ollama_base and settings.LOCAL_LLM_URL.endswith('/v1'):
                    base = settings.LOCAL_LLM_URL[:-3]
                    try:
                        with timing.phase('provider_discovery_ms'):
                            probe = await client.get(base + '/api/version')
                            if probe.is_success and isinstance(probe.json().get('version'), str):
                                self._ollama_base = base
                    except (httpx.HTTPError, ValueError, TypeError, AttributeError):
                        pass
                with timing.phase('request_construction_ms'):
                    if self._ollama_base:
                        endpoint_kind = 'ollama_native'
                        url = self._ollama_base + '/api/chat'
                        payload = {'model': self.model, 'messages': messages, 'think': False,
                            'stream': False, 'format': schema or 'json',
                            'options': {'temperature': self.temperature, 'num_predict': token_limit}}
                    else:
                        url = settings.LOCAL_LLM_URL + '/chat/completions'
                        payload = {'model': self.model, 'messages': messages, 'temperature': self.temperature,
                            'max_tokens': token_limit, 'stream': False, 'response_format': {'type': 'json_object'}}
                logger.info('local_model_request', model=self.model, endpoint=endpoint_kind)
                response = await timing.post(client, url, json=payload)
                with timing.phase('response_processing_ms'):
                    response.raise_for_status()
                    data = response.json()
                    if not isinstance(data, dict):
                        raise ValueError('Provider response must be an object')
                    if self._ollama_base:
                        timing.values.update(native_provider_timings(data))
                    prompt_count = data.get('prompt_eval_count')
                    output_count = data.get('eval_count')
                    native_usage = {'prompt_tokens': prompt_count, 'completion_tokens': output_count,
                        'total_tokens': (prompt_count + output_count
                            if type(prompt_count) is int and prompt_count >= 0
                            and type(output_count) is int and output_count >= 0 else None)}
                    usage = native_usage if self._ollama_base else data.get('usage')
                    if not isinstance(usage, dict):
                        usage = {}
                    metrics = {**usage_metrics(usage), **token_components(usage), 'cost_microusd': 0}
                    choices = data.get('choices')
                    if choices is not None and (not isinstance(choices, list) or not choices
                                                or not isinstance(choices[0], dict)):
                        raise ValueError('Invalid provider choices')
                    if data.get('done_reason') == 'length' or (choices and choices[0].get('finish_reason') == 'length'):
                        result = {'success': False, 'content': '', 'error': 'model_output_truncated'}
                    else:
                        content = data['message']['content'] if self._ollama_base else data['choices'][0]['message']['content']
                        if not isinstance(content, str) or not content.strip():
                            raise ValueError('Empty content')
                        result = {'success': True, 'content': content}
        except httpx.TimeoutException as exc:
            logger.warning('local_model_timeout', model=self.model, endpoint=endpoint_kind,
                           error=type(exc).__name__)
            result = {'success': False, 'content': '', 'error': 'provider_timeout'}
        except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError) as exc:
            status = getattr(getattr(exc, 'response', None), 'status_code', '')
            logger.warning('local_model_failure', model=self.model, endpoint=endpoint_kind,
                           http_status=status, error=type(exc).__name__)
            result = {'success': False, 'content': '', 'error': 'local_model_request_failed'}
        return timing.finish({**result, **metrics})
