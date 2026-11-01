"""Offline regression suite; secrets exist only for this test process."""
import os
import secrets
from cryptography.fernet import Fernet

os.environ['SECRET_KEY'] = secrets.token_hex(32)
os.environ['FERNET_KEY'] = Fernet.generate_key().decode()
os.environ['KALI_AGENT_TOKEN'] = secrets.token_hex(32)
os.environ['DATABASE_URL'] = 'postgresql+asyncpg://review@127.0.0.1/aria_test'
