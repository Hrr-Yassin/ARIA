import os
import secrets
from unittest import TestCase
from unittest.mock import patch
from cryptography.fernet import Fernet
from pydantic import ValidationError
from config.settings import Settings
from llm.pool_manager import LLMPoolManager


class SecretTests(TestCase):
    def test_required_secrets_have_no_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValidationError):
                Settings(_env_file=None)

    def test_reject_known_defaults_and_bad_encryption_key(self):
        for values in ({'SECRET_KEY': 'pentestai-v10-change-this-in-production-64chars-minimum'},
                       {'KALI_AGENT_TOKEN': 'pentestai-kali-secret-v10'}, {'FERNET_KEY': 'invalid'}):
            with self.subTest(fields=list(values)):
                with self.assertRaises(ValidationError):
                    Settings(_env_file=None, **values)

    def test_persistent_encryption_survives_manager_restart(self):
        first = LLMPoolManager()
        ciphertext = first.encrypt_key(secrets.token_urlsafe(24))
        self.assertEqual(first.decrypt_key(ciphertext), LLMPoolManager().decrypt_key(ciphertext))

    def test_invalid_ciphertext_is_never_returned_as_a_credential(self):
        with self.assertRaises(ValueError):
            LLMPoolManager().decrypt_key('not-ciphertext')

    def test_missing_or_invalid_key_fails_without_logging_secrets(self):
        for key in ('', 'invalid'):
            with patch('llm.pool_manager.settings.FERNET_KEY', key), patch('llm.pool_manager.log') as log:
                with self.assertRaises(ValueError):
                    LLMPoolManager()
                log.info.assert_not_called()

    def test_wrong_persistent_key_fails(self):
        ciphertext = LLMPoolManager().encrypt_key('test-provider-value')
        with patch('llm.pool_manager.settings.FERNET_KEY', Fernet.generate_key().decode()):
            with self.assertRaises(ValueError):
                LLMPoolManager().decrypt_key(ciphertext)

    def test_startup_has_no_demo_seed(self):
        from pathlib import Path
        self.assertNotIn('seed_default_users', Path('api/main.py').read_text())
        self.assertNotIn('DEFAULT_USERS', Path('api/auth.py').read_text())
