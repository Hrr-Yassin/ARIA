"""Stable public diagnostics; never expose raw provider responses or credentials."""
MESSAGES = {
    'no_keys': 'No model key configured. Add a provider key or configure local-only routing.',
    'model_not_configured': 'Set LOCAL_LLM_MODEL to an installed local model.',
    'local_model_unavailable': 'Local model is unavailable or not installed. Check the local server and model name.',
    'model_tariff_missing': 'Configure an engagement tariff for the selected provider and model.',
    'model_budget_exhausted': 'Engagement model budget is exhausted. Review its call, token and cost limits.',
    'model_budget_denied': 'Model request denied by engagement authorization, data-sharing policy or budget.',
    'campaign_budget_exhausted': 'Campaign model budget is exhausted. Review its token and cost limits.',
    'campaign_budget_unavailable': 'Campaign budget cannot be verified; model calls were denied.',
    'campaign_not_running': 'Campaign is not running; model calls were denied.',
    'all_exhausted': 'No usable provider key remains. Check key status, quotas and provider availability.',
    'provider_authorization_or_storage_unavailable': 'Model authorization or accounting storage is unavailable.',
    'validation_budget_exhausted': 'Model validation budget is exhausted.',
    'local_model_request_failed': 'Local model request failed. Check server compatibility and availability.',
    'provider_timeout': 'Model provider timed out.',
}


def public_error(code):
    return MESSAGES.get(code, 'Model provider failed; check provider availability and configuration.')


def budget_error(exc):
    detail = exc.detail
    code = detail.get('code') if isinstance(detail, dict) else None
    return code if code in MESSAGES else 'model_budget_denied'
