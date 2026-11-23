"""API key format, generation, salted HMAC hashing and constant-time verification.

Key format ``sf_<env>_<prefix8>_<secret43>``. The lookup prefix ``sf_<env>_<prefix8>``
is stored in clear; the full key is stored only as
``v1$<salt_hex>$<HMAC-SHA256(pepper, salt || key)>``. A fresh random salt is
drawn per hash, so equal inputs never produce equal stored values.
"""

import hashlib
import hmac
import re
import secrets
import string
from dataclasses import dataclass

KEY_SCHEME = "sf"
HASH_VERSION = "v1"
HASH_SEPARATOR = "$"
PREFIX_LENGTH = 8
SECRET_BYTES = 32  # token_urlsafe(32) yields 43 characters
SECRET_LENGTH = 43
SALT_BYTES = 16
PREFIX_ALPHABET = string.ascii_lowercase + string.digits

_ENV_PATTERN = re.compile(r"[a-z0-9]+")
_KEY_PATTERN = re.compile(
    rf"(?P<prefix>{KEY_SCHEME}_[a-z0-9]+_[a-z0-9]{{{PREFIX_LENGTH}}})"
    rf"_(?P<secret>[A-Za-z0-9_-]{{{SECRET_LENGTH}}})"
)
_SALT_PATTERN = re.compile(r"(?:[0-9a-f]{2})+")


@dataclass(frozen=True, slots=True)
class GeneratedKey:
    """The plaintext ``key`` is shown to the caller exactly once and never stored."""

    key: str
    prefix: str
    secret_hash: str


def generate_api_key(pepper: str, *, env: str = "live") -> GeneratedKey:
    """Create a new random key; return it with its lookup prefix and salted hash."""
    if not _ENV_PATTERN.fullmatch(env):
        raise ValueError(f"key env must be lowercase alphanumeric, got {env!r}")
    short = "".join(secrets.choice(PREFIX_ALPHABET) for _ in range(PREFIX_LENGTH))
    prefix = f"{KEY_SCHEME}_{env}_{short}"
    key = f"{prefix}_{secrets.token_urlsafe(SECRET_BYTES)}"
    return GeneratedKey(key=key, prefix=prefix, secret_hash=hash_api_key(pepper, key))


def parse_prefix(key: str) -> str:
    """Return the lookup prefix ``sf_<env>_<prefix8>``; raise ValueError if malformed."""
    match = _KEY_PATTERN.fullmatch(key)
    if match is None:
        raise ValueError("malformed API key")
    return match.group("prefix")


def hash_api_key(pepper: str, key: str) -> str:
    """Salted, peppered hash suitable for storage (``v1$<salt>$<digest>``)."""
    salt = secrets.token_hex(SALT_BYTES)
    return HASH_SEPARATOR.join((HASH_VERSION, salt, _digest(pepper, salt, key)))


def verify_api_key(pepper: str, key: str, stored_hash: str) -> bool:
    """Constant-time check of ``key`` against a value produced by ``hash_api_key``."""
    parts = stored_hash.split(HASH_SEPARATOR)
    if len(parts) != 3 or parts[0] != HASH_VERSION or not _SALT_PATTERN.fullmatch(parts[1]):
        return False
    expected = _digest(pepper, parts[1], key)
    return hmac.compare_digest(expected.encode("ascii"), parts[2].encode("utf-8"))


def _digest(pepper: str, salt: str, key: str) -> str:
    message = bytes.fromhex(salt) + key.encode("utf-8")
    return hmac.new(pepper.encode("utf-8"), message, hashlib.sha256).hexdigest()
