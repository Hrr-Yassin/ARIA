"""Offline regression suite; secrets exist only for this test process."""
import os
import secrets
from cryptography.fernet import Fernet

os.environ['SECRET_KEY'] = secrets.token_hex(32)
os.environ['FERNET_KEY'] = Fernet.generate_key().decode()
os.environ['KALI_AGENT_TOKEN'] = secrets.token_hex(32)
os.environ['DATABASE_URL'] = 'postgresql+asyncpg://review@127.0.0.1/aria_test'
# Provider tests mock the cloud clients; do not inherit a developer's live Ollama
# routing from .env. Local-client tests explicitly override this setting.
os.environ['LLM_ROUTING'] = 'cloud'
