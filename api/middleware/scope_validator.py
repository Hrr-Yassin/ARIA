"""Compatibility interface backed by the shared deny-by-default adapters."""
from orchestrator.execution_policy import PolicyError, validate_command


def validate_scope(command: str, scope: dict) -> dict:
    try:
        validated = validate_command(command, scope)
        return {'valid': True, 'reason': 'OK', 'violations': [], 'normalized_command': validated.command}
    except (PolicyError, TypeError, ValueError):
        return {'valid': False, 'reason': 'Command is not permitted by engagement policy',
                'violations': ['Command is not permitted by engagement policy'], 'normalized_command': ''}


def scope_is_defined(scope: dict) -> bool:
    return bool(isinstance(scope, dict) and scope.get('targets'))
