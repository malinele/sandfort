"""API key administration (``client.create_api_key``, ``list_api_keys``, ``revoke_api_key``).

Every call needs the ``api_keys:admin`` scope. The plaintext key is in the answer of the create
and nowhere else: store it then, it cannot be read back. A key can only grant scopes its
creator holds.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from sandfort_sdk._requests import segment
from sandfort_sdk._transport import AsyncTransport, Reply, SyncTransport
from sandfort_sdk.exceptions import InvalidResponseError
from sandfort_sdk.models import _as_dict, _as_list, _required, _required_timestamp, _timestamp

API_KEYS_PATH = "/v1/api-keys"

ApiKeyStatus = Literal["active", "expired", "revoked"]
DEFAULT_STATUS: ApiKeyStatus = "active"  # an older server omits the field


@dataclass(frozen=True, slots=True)
class ApiKeyInfo:
    """API key metadata; the secret and its hash are never part of it.

    ``status`` is the server's answer-time value: ``revoked`` once ``revoked_at`` is set, else
    ``expired`` once ``expires_at`` has passed, else ``active``. The known values are the
    ``ApiKeyStatus`` ones; the field stays a plain ``str`` so that a value a newer server
    adds still loads as sent.
    A server that predates the field leaves it at ``active``, so against such a server read
    ``revoked_at`` and ``expires_at`` instead. Keyword-only so that ``CreatedApiKey.key``
    can stay a required field.
    """

    id: str
    name: str
    prefix: str
    scopes: tuple[str, ...]
    sandbox_labels: dict[str, str] | None
    max_sandboxes: int | None
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None
    created_by: str | None
    status: str = field(default=DEFAULT_STATUS, kw_only=True)
    shared_volume_labels: dict[str, str] | None = field(default=None, kw_only=True)

    @classmethod
    def from_payload(cls, data: Any) -> "ApiKeyInfo":
        return cls(**_key_fields(_as_dict(data, "api key")))


@dataclass(frozen=True, slots=True)
class CreatedApiKey(ApiKeyInfo):
    """The create answer: the metadata plus the plaintext ``key`` (shown this once)."""

    key: str = field(repr=False)

    @classmethod
    def from_payload(cls, data: Any) -> "CreatedApiKey":
        raw = _as_dict(data, "api key")
        (key,) = _required(raw, "api key", "key")
        return cls(**_key_fields(raw), key=key)


@dataclass(frozen=True, slots=True)
class RevokedApiKey(ApiKeyInfo):
    """The revoke answer: the key plus what the server says about its descendants.

    ``dependants`` are the key's live descendants. With ``cascade`` true they were just revoked;
    otherwise they are still alive and only a later revoke of each one ends them.
    """

    cascade: bool = field(default=False, kw_only=True)
    dependants: tuple[ApiKeyInfo, ...] = field(default=(), kw_only=True)

    @classmethod
    def from_payload(cls, data: Any) -> "RevokedApiKey":
        raw = _as_dict(data, "api key")
        items = _as_list(raw.get("dependants") or [], "api key dependants")
        return cls(
            **_key_fields(raw),
            cascade=raw.get("cascade") is True,
            dependants=tuple(ApiKeyInfo.from_payload(item) for item in items),
        )


def _status(raw: dict[str, Any]) -> str:
    value = raw.get("status")
    if value is None:
        return DEFAULT_STATUS
    if not isinstance(value, str):
        raise InvalidResponseError(f"expected a string for api key status, got {value!r}")
    return value


def _key_fields(raw: dict[str, Any]) -> dict[str, Any]:
    key_id, name, prefix, scopes = _required(raw, "api key", "id", "name", "prefix", "scopes")
    labels = raw.get("sandbox_labels")
    shared = raw.get("shared_volume_labels")
    return {
        "id": key_id,
        "name": name,
        "prefix": prefix,
        "scopes": tuple(str(scope) for scope in _as_list(scopes, "api key scopes")),
        "sandbox_labels": None if labels is None else dict(_as_dict(labels, "sandbox_labels")),
        "max_sandboxes": raw.get("max_sandboxes"),
        "shared_volume_labels": (
            None if shared is None else dict(_as_dict(shared, "shared_volume_labels"))
        ),
        "created_at": _required_timestamp(raw.get("created_at"), "api key"),
        "last_used_at": _timestamp(raw.get("last_used_at"), "api key"),
        "expires_at": _timestamp(raw.get("expires_at"), "api key"),
        "revoked_at": _timestamp(raw.get("revoked_at"), "api key"),
        "created_by": raw.get("created_by"),
        "status": _status(raw),
    }


def api_key_create_body(
    name: str,
    scopes: Sequence[str],
    sandbox_labels: dict[str, str] | None,
    max_sandboxes: int | None,
    expires_at: datetime | None,
    shared_volume_labels: dict[str, str] | None = None,
) -> dict[str, Any]:
    if not name.strip():
        raise ValueError("'name' must not be empty")
    if not scopes:
        raise ValueError("'scopes' must not be empty")
    if max_sandboxes is not None and not sandbox_labels:
        raise ValueError("'max_sandboxes' needs a non-empty 'sandbox_labels'")
    if shared_volume_labels and not sandbox_labels:
        raise ValueError("'shared_volume_labels' needs a non-empty 'sandbox_labels'")
    if expires_at is not None and expires_at.tzinfo is None:
        raise ValueError("'expires_at' must be timezone-aware")
    body: dict[str, Any] = {
        "name": name,
        "scopes": list(scopes),
        "sandbox_labels": sandbox_labels or None,
        "max_sandboxes": max_sandboxes,
        "shared_volume_labels": shared_volume_labels or None,
        "expires_at": None if expires_at is None else expires_at.isoformat(),
    }
    return {key: value for key, value in body.items() if value is not None}


def api_key_path(key_id: str) -> str:
    return f"{API_KEYS_PATH}/{segment(key_id)}"


def _cascade(cascade: bool) -> dict[str, Any] | None:
    """The revoke query: ``cascade=true`` when asked for, else none (the server default)."""
    return {"cascade": "true"} if cascade else None


def _keys(reply: Reply) -> tuple[ApiKeyInfo, ...]:
    items = _as_list(reply.data, "api keys")
    return tuple(ApiKeyInfo.from_payload(item) for item in items)


class ApiKeys:
    """Synchronous API key client (reached through the ``Client`` methods)."""

    def __init__(self, transport: SyncTransport) -> None:
        self._transport = transport

    def create(
        self,
        name: str,
        scopes: Sequence[str],
        *,
        sandbox_labels: dict[str, str] | None = None,
        max_sandboxes: int | None = None,
        expires_at: datetime | None = None,
        shared_volume_labels: dict[str, str] | None = None,
    ) -> CreatedApiKey:
        """Create a key; ``max_sandboxes`` caps its live sandboxes and needs ``sandbox_labels``.

        ``shared_volume_labels`` (also needs ``sandbox_labels``) lets the key list, get and
        mount read-only the volumes carrying those labels.
        """
        body = api_key_create_body(
            name, scopes, sandbox_labels, max_sandboxes, expires_at, shared_volume_labels
        )
        reply = self._transport.request("POST", API_KEYS_PATH, json=body)
        return CreatedApiKey.from_payload(reply.data)

    def list(self) -> tuple[ApiKeyInfo, ...]:
        return _keys(self._transport.request("GET", API_KEYS_PATH))

    def revoke(self, key_id: str, *, cascade: bool = False) -> RevokedApiKey:
        """Revoke a key; repeating it answers the already revoked key.

        The key's live descendants are revoked only with ``cascade=True``; the answer lists
        them in ``dependants`` either way.
        """
        reply = self._transport.request("DELETE", api_key_path(key_id), params=_cascade(cascade))
        return RevokedApiKey.from_payload(reply.data)


class AsyncApiKeys:
    """Asynchronous API key client (reached through the ``AsyncClient`` methods)."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def create(
        self,
        name: str,
        scopes: Sequence[str],
        *,
        sandbox_labels: dict[str, str] | None = None,
        max_sandboxes: int | None = None,
        expires_at: datetime | None = None,
        shared_volume_labels: dict[str, str] | None = None,
    ) -> CreatedApiKey:
        body = api_key_create_body(
            name, scopes, sandbox_labels, max_sandboxes, expires_at, shared_volume_labels
        )
        reply = await self._transport.request("POST", API_KEYS_PATH, json=body)
        return CreatedApiKey.from_payload(reply.data)

    async def list(self) -> tuple[ApiKeyInfo, ...]:
        return _keys(await self._transport.request("GET", API_KEYS_PATH))

    async def revoke(self, key_id: str, *, cascade: bool = False) -> RevokedApiKey:
        reply = await self._transport.request(
            "DELETE", api_key_path(key_id), params=_cascade(cascade)
        )
        return RevokedApiKey.from_payload(reply.data)
