"""Single-use, short-lived tokens that authorize one PTY websocket connection.

``ConnectTokenStore`` is the port; ``InMemoryConnectTokenStore`` is the
single-process implementation. Only a SHA-256 digest of each token is stored. Every mint
sweeps the entries past their deadline (the store is small, so a linear walk is fine).
``PendingConnectTokens`` is an optional capability: the terminal reaper reads it to find
terminals that no token can attach any more.
"""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol, runtime_checkable

from sandfort.clock import Clock, SystemClock
from sandfort.errors import Unauthorized

DEFAULT_TTL = timedelta(seconds=60)
TOKEN_BYTES = 32


@dataclass(frozen=True, slots=True)
class ConnectGrant:
    org_id: str
    sandbox_id: str
    pty_id: str


class ConnectTokenInvalid(Unauthorized):
    """The token is unknown, already redeemed or expired."""


class ConnectTokenStore(Protocol):
    async def mint(self, org_id: str, sandbox_id: str, pty_id: str) -> str:
        """Create an opaque token bound to the grant."""
        ...

    async def redeem(self, token: str) -> ConnectGrant:
        """Consume the token exactly once; raise ``ConnectTokenInvalid`` otherwise."""
        ...


@runtime_checkable
class PendingConnectTokens(Protocol):
    """Optional store capability: which terminals still hold a redeemable token."""

    async def pending_pty_ids(self) -> frozenset[str]:
        """Pty ids whose token is neither redeemed nor past its deadline."""
        ...


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class InMemoryConnectTokenStore:
    def __init__(self, clock: Clock | None = None, ttl: timedelta = DEFAULT_TTL) -> None:
        self._clock: Clock = clock or SystemClock()
        self._ttl = ttl
        self._entries: dict[str, tuple[ConnectGrant, datetime]] = {}

    def __len__(self) -> int:
        """Stored tokens; expired ones count until the next sweep."""
        return len(self._entries)

    async def mint(self, org_id: str, sandbox_id: str, pty_id: str) -> str:
        self._sweep()
        token = secrets.token_urlsafe(TOKEN_BYTES)
        grant = ConnectGrant(org_id=org_id, sandbox_id=sandbox_id, pty_id=pty_id)
        self._entries[_digest(token)] = (grant, self._clock.now() + self._ttl)
        return token

    async def redeem(self, token: str) -> ConnectGrant:
        entry = self._entries.pop(_digest(token), None)
        if entry is None:
            raise ConnectTokenInvalid("connect token is invalid or already used")
        grant, expires_at = entry
        if self._clock.now() >= expires_at:
            raise ConnectTokenInvalid("connect token has expired")
        return grant

    async def pending_pty_ids(self) -> frozenset[str]:
        self._sweep()
        return frozenset(grant.pty_id for grant, _ in self._entries.values())

    def _sweep(self) -> None:
        """Drop every entry past its deadline (the same bound ``redeem`` enforces)."""
        now = self._clock.now()
        self._entries = {
            digest: entry for digest, entry in self._entries.items() if now < entry[1]
        }
