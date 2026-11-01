"""Authenticated encryption for cached evidence; never deserialize executable data."""
from cryptography.fernet import Fernet, MultiFernet
from config.settings import settings


def evidence_cipher():
    return MultiFernet([Fernet(settings.FERNET_KEY.encode()),
                        *(Fernet(key.encode()) for key in settings.FERNET_PREVIOUS_KEYS)])
