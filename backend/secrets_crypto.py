"""
Field-level encryption for tenant credentials stored in the database.

Values are stored as "enc:v1:<fernet token>". Anything without that prefix is
treated as legacy plaintext and returned unchanged by decrypt_secret(), so the
code can be deployed before existing rows are migrated
(see encrypt_existing_secrets.py).

The key comes from TENANT_ENCRYPTION_KEYS: one or more Fernet keys separated by
commas. The first key encrypts; all keys can decrypt, which allows rotation.
Generate a key with:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""
import os
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

PREFIX = 'enc:v1:'
KEYS_ENV = 'TENANT_ENCRYPTION_KEYS'

# Tenant columns that hold credentials
SECRET_FIELDS = ('crowdstrike_client_secret', 'virustotal_api_key')


@lru_cache(maxsize=4)
def _build_fernet(raw_keys):
    keys = [k.strip() for k in raw_keys.split(',') if k.strip()]
    if not keys:
        raise RuntimeError(f"{KEYS_ENV} is not set; cannot encrypt or decrypt tenant secrets")
    return MultiFernet([Fernet(k) for k in keys])


def _fernet():
    return _build_fernet(os.getenv(KEYS_ENV, ''))


def is_encrypted(value):
    return isinstance(value, str) and value.startswith(PREFIX)


def encrypt_secret(value):
    """Encrypt a plaintext secret. None, empty and already-encrypted values pass through."""
    if not value or is_encrypted(value):
        return value
    return PREFIX + _fernet().encrypt(value.encode()).decode()


def decrypt_secret(value):
    """Decrypt a stored secret. Legacy plaintext values are returned as-is."""
    if not is_encrypted(value):
        return value
    try:
        return _fernet().decrypt(value[len(PREFIX):].encode()).decode()
    except InvalidToken:
        # Never include the value in the message
        raise RuntimeError(f"Could not decrypt tenant secret; check {KEYS_ENV}") from None


def rotate_secret(value):
    """Re-encrypt with the primary key (plaintext is encrypted, None/empty pass through)."""
    if not is_encrypted(value):
        return encrypt_secret(value)
    try:
        return PREFIX + _fernet().rotate(value[len(PREFIX):].encode()).decode()
    except InvalidToken:
        raise RuntimeError(f"Could not decrypt tenant secret; check {KEYS_ENV}") from None
