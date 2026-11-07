"""Redact credentials at model/log boundaries; preserve protected source evidence."""
import re

SENSITIVE = re.compile(r'password|passwd|secret|authorization|cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|fernet|hash_value', re.I)
PAIR = re.compile(r'''(?ix)(["']?(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|hash_value)["']?\s*[:=]\s*)(?:"[^"\n]*"|'[^'\n]*'|[^\s,;}]+)''')
HEADERS = re.compile(r'(?im)\b(authorization|proxy-authorization|cookie|set-cookie)\s*["\']?\s*[:=]\s*[^\r\n]+')
QUERY = re.compile(r'(?i)([?&](?:key|api_key|token|password|secret)=)[^&\s"\']+')
PEM = re.compile(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----', re.S)


def redact(value, known_secrets=()):
    if isinstance(value, dict):
        return {str(k): '[REDACTED]' if SENSITIVE.search(str(k)) else redact(v, known_secrets) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, known_secrets) for v in value]
    if not isinstance(value, str):
        return value
    for secret in sorted((s for s in known_secrets if isinstance(s, str) and len(s) >= 4), key=len, reverse=True):
        value = value.replace(secret, '[REDACTED]')
    value = re.sub(r'(\w+://[^/\s:@]+:)[^@\s/]+(@)', r'\1[REDACTED]\2', value)
    value = re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '[REDACTED JWT]', value)
    value = PEM.sub('[REDACTED PRIVATE KEY]', value)
    value = QUERY.sub(r'\1[REDACTED]', value)
    value = PAIR.sub(r'\1"[REDACTED]"', value)
    value = HEADERS.sub(lambda m: m.group(1) + ': [REDACTED]', value)
    if re.search(r'\bhydra\b', value):
        value = re.sub(r'(?<!\S)(-p\s+)(?:\x27[^\x27]*\x27|"[^"]*"|\S+)', r'\1[REDACTED]', value)
    return value


def deployment_secrets():
    from config.settings import settings
    return [settings.SECRET_KEY, settings.FERNET_KEY, settings.KALI_AGENT_TOKEN, settings.BURP_CONNECTOR_TOKEN, settings.NVD_API_KEY, settings.HTTP_REPLAY_KEY,
            *settings.FERNET_PREVIOUS_KEYS]


def log_redaction(logger, method, event):
    return redact(event, deployment_secrets())


def configure_logging():
    import structlog
    processors = structlog.get_config()['processors']
    if log_redaction not in processors:
        structlog.configure(processors=[log_redaction, *processors])
