"""Envelope encryption for webhook signing secrets at rest.

``SecretBox`` wraps one fernet key (urlsafe base64, 32 bytes). ``encrypt`` returns the fernet
token behind ``SECRET_MARKER``; ``decrypt`` accepts both forms, so rows written before the key
was configured (legacy plaintext, no marker) keep working and need no migration. A marked value
that cannot be decrypted (wrong key, corrupt token, no key configured) raises ``InternalError``:
that is a deployment misconfiguration, and the message never carries the value.

With an empty key the box is the identity on ``encrypt`` and refuses marked values on
``decrypt``. ``reseal`` encrypts a legacy value on the next write and leaves sealed ones alone.
"""

from cryptography.fernet import Fernet, InvalidToken

from sandfort.errors import InternalError

SECRET_MARKER = "enc1:"


def _load(key: str) -> Fernet | None:
    if not key:
        return None
    try:
        return Fernet(key.encode())
    except (ValueError, TypeError):
        raise InternalError("webhook secret key is not a valid fernet key") from None


class SecretBox:
    def __init__(self, key: str = "") -> None:
        self._fernet = _load(key)

    @property
    def enabled(self) -> bool:
        """True when a key is configured, so new secrets are stored encrypted."""
        return self._fernet is not None

    def encrypt(self, plaintext: str) -> str:
        if self._fernet is None:
            return plaintext
        token = self._fernet.encrypt(plaintext.encode()).decode()
        return SECRET_MARKER + token

    def decrypt(self, stored: str) -> str:
        if not stored.startswith(SECRET_MARKER):
            return stored  # legacy plaintext
        if self._fernet is None:
            raise InternalError("webhook secret is encrypted but no key is configured")
        token = stored.removeprefix(SECRET_MARKER).encode()
        try:
            return self._fernet.decrypt(token).decode()
        except (InvalidToken, ValueError):
            raise InternalError("webhook secret cannot be decrypted with the key") from None

    def reseal(self, stored: str) -> str:
        """Encrypt a legacy plaintext value; a marked value or a keyless box passes through."""
        if stored.startswith(SECRET_MARKER):
            return stored
        return self.encrypt(stored)
