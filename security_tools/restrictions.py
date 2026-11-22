"""Owner capability restrictions, enforced by the authorization layer.

Kept outside the digested adapter contract (``contract_digest``) so an owner
policy feature never changes the approval/worker/image contract identity.
"""
from security_tools.adapters import AdapterError, decode


class CapabilityBlocked(AdapterError):
    """An owner restriction denies the typed capability."""


def check_capability(command: str, scope: dict) -> None:
    """Deny a typed command whose capability the engagement owner has blocked."""
    if not isinstance(command, str) or not command.startswith('aria-tool '):
        return
    blocked = scope.get('blocked_typed_capabilities', [])
    if not isinstance(blocked, list) or any(not isinstance(item, str) for item in blocked):
        raise AdapterError('Invalid engagement capability restrictions')
    if not blocked:
        return
    adapter, _ = decode(command)
    if adapter.capability in blocked:
        raise CapabilityBlocked('Capability is blocked for this engagement')
