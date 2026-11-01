"""Adaptive password hashing and durable account-wide credential revocation."""
import hashlib
import hmac
import secrets

ITERATIONS = 600_000


def hash_password(password: str, salt: str = '') -> str:
    if not isinstance(password, str) or len(password) > 1024:
        raise ValueError('Invalid password length')
    salt = salt or secrets.token_hex(16)
    result = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), ITERATIONS).hex()
    return f'pbkdf2_sha256${ITERATIONS}${salt}${result}'


def verify_password(password: str, stored: str) -> bool:
    if not isinstance(password, str) or len(password) > 1024:
        return False
    try:
        if stored.startswith('pbkdf2_sha256$'):
            _, iterations, salt, expected = stored.split('$')
            count = int(iterations)
            if not 100_000 <= count <= 1_000_000 or len(salt) > 128 or len(expected) != 64:
                return False
            actual = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), count).hex()
        else:
            # Read legacy SHA-256 only; successful login upgrades it in the DB.
            salt, expected = stored.split('$')
            if len(salt) > 128 or len(expected) != 64:
                return False
            actual = hashlib.sha256(f'{salt}:{password}'.encode()).hexdigest()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, AttributeError):
        return False


def auth_revision(user) -> int:
    preferences = getattr(user, 'preferences', None)
    value = preferences.get('auth_revision', 0) if isinstance(preferences, dict) else 0
    if type(value) is not int or value < 0:
        raise ValueError('Invalid account revision')
    return value


def revoke_credentials(user):
    preferences = dict(user.preferences or {})
    preferences['auth_revision'] = auth_revision(user) + 1
    user.preferences = preferences
