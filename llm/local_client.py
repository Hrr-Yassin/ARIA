"""Loopback-only OpenAI-compatible model transport; never follows redirects."""
import time

import httpx
import structlog
from config.settings import settings
from llm.base_llm import BaseLLMClient, usage_metrics, response_schema, output_limit

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
        messages = [{'role': 'system', 'content': system}, {'role': 'user', 'content': prompt}]
        started = time.monotonic()
        endpoint_kind = 'ollama_native' if self._ollama_base else 'openai_compatible'
        schema = response_schema.get()
        token_limit = output_limit(768 if schema else 192)
        try:
            async with httpx.AsyncClient(timeout=180 if schema else 60, trust_env=False, follow_redirects=False) as client:
                if not self._ollama_base and settings.LOCAL_LLM_URL.endswith('/v1'):
                    base = settings.LOCAL_LLM_URL[:-3]
                    try:
                        probe = await client.get(base + '/api/version')
                        if probe.is_success and isinstance(probe.json().get('version'), str):
                            self._ollama_base = base
                    except (httpx.HTTPError, ValueError, TypeError, AttributeError):
                        pass
                if self._ollama_base:
                    endpoint_kind = 'ollama_native'
                    logger.info('local_model_request', model=self.model, endpoint=endpoint_kind)
                    response = await client.post(self._ollama_base + '/api/chat', json={
                        'model': self.model, 'messages': messages, 'think': False,
                        'stream': False, 'format': schema or 'json',
                        'options': {'temperature': self.temperature, 'num_predict': token_limit},
                    })
                else:
                    logger.info('local_model_request', model=self.model, endpoint=endpoint_kind)
                    response = await client.post(settings.LOCAL_LLM_URL + '/chat/completions', json={
                        'model': self.model, 'messages': messages, 'temperature': self.temperature,
                        'max_tokens': token_limit, 'stream': False, 'response_format': {'type': 'json_object'},
                    })
                response.raise_for_status()
                data = response.json()
                if data.get('done_reason') == 'length' or (data.get('choices') and data['choices'][0].get('finish_reason') == 'length'):
                    return {'success': False, 'content': '', 'error': 'model_output_truncated',
                            **usage_metrics(data.get('usage') or {'total_tokens': data.get('prompt_eval_count', 0) + data.get('eval_count', 0)}),
                            'cost_microusd': 0}
                if self._ollama_base:
                    content = data['message']['content']
                    usage = {'total_tokens': int(data.get('prompt_eval_count', 0)) + int(data.get('eval_count', 0))}
                else:
                    content = data['choices'][0]['message']['content']
                    usage = data.get('usage') or {}
                if not isinstance(content, str) or not content.strip():
                    raise ValueError('Empty content')
                logger.info(
                    'local_model_response', model=self.model, endpoint=endpoint_kind,
                    http_status=response.status_code, elapsed_ms=int((time.monotonic() - started) * 1000),
                    prompt_tokens=data.get('prompt_eval_count', '') if endpoint_kind == 'ollama_native' else usage.get('prompt_tokens', ''),
                    completion_tokens=data.get('eval_count', '') if endpoint_kind == 'ollama_native' else usage.get('completion_tokens', ''),
                    content_chars=len(content),
                )
                return {'success': True, 'content': content,
                        **usage_metrics(usage), 'cost_microusd': 0}
        except httpx.TimeoutException as exc:
            logger.warning('local_model_timeout', model=self.model, endpoint=endpoint_kind,
                           elapsed_ms=int((time.monotonic() - started) * 1000), error=type(exc).__name__)
            return {'success': False, 'content': '', 'error': 'provider_timeout'}
        except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError) as exc:
            status = getattr(getattr(exc, 'response', None), 'status_code', '')
            logger.warning('local_model_failure', model=self.model, endpoint=endpoint_kind,
                           elapsed_ms=int((time.monotonic() - started) * 1000), http_status=status,
                           error=type(exc).__name__)
            return {'success': False, 'content': '', 'error': 'local_model_request_failed'}
