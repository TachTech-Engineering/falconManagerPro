import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.fernet import Fernet  # noqa: E402

import secrets_crypto  # noqa: E402
from secrets_crypto import (  # noqa: E402
    PREFIX, decrypt_secret, encrypt_secret, is_encrypted, rotate_secret,
)


class SecretsCryptoTest(unittest.TestCase):
    def setUp(self):
        self.key1 = Fernet.generate_key().decode()
        self.key2 = Fernet.generate_key().decode()
        os.environ[secrets_crypto.KEYS_ENV] = self.key1

    def tearDown(self):
        os.environ.pop(secrets_crypto.KEYS_ENV, None)

    def test_round_trip(self):
        token = encrypt_secret("s3cr3t")
        self.assertTrue(token.startswith(PREFIX))
        self.assertNotIn("s3cr3t", token)
        self.assertEqual(decrypt_secret(token), "s3cr3t")

    def test_encrypt_is_idempotent(self):
        token = encrypt_secret("s3cr3t")
        self.assertEqual(encrypt_secret(token), token)

    def test_legacy_plaintext_passes_through(self):
        self.assertEqual(decrypt_secret("plain-value"), "plain-value")
        self.assertFalse(is_encrypted("plain-value"))

    def test_none_and_empty(self):
        for v in (None, ""):
            self.assertEqual(encrypt_secret(v), v)
            self.assertEqual(decrypt_secret(v), v)

    def test_missing_key_fails_closed(self):
        token = encrypt_secret("s3cr3t")
        del os.environ[secrets_crypto.KEYS_ENV]
        with self.assertRaises(RuntimeError):
            encrypt_secret("other")
        with self.assertRaises(RuntimeError):
            decrypt_secret(token)

    def test_wrong_key_does_not_leak_value(self):
        token = encrypt_secret("s3cr3t")
        os.environ[secrets_crypto.KEYS_ENV] = self.key2
        with self.assertRaises(RuntimeError) as ctx:
            decrypt_secret(token)
        self.assertNotIn(token, str(ctx.exception))

    def test_rotation(self):
        old = encrypt_secret("s3cr3t")
        os.environ[secrets_crypto.KEYS_ENV] = f"{self.key2},{self.key1}"
        # Old ciphertext still readable with the new key list
        self.assertEqual(decrypt_secret(old), "s3cr3t")
        rotated = rotate_secret(old)
        self.assertNotEqual(rotated, old)
        # After dropping the old key, the rotated value still decrypts
        os.environ[secrets_crypto.KEYS_ENV] = self.key2
        self.assertEqual(decrypt_secret(rotated), "s3cr3t")

    def test_rotate_encrypts_plaintext(self):
        self.assertTrue(is_encrypted(rotate_secret("plain")))


if __name__ == "__main__":
    unittest.main()
