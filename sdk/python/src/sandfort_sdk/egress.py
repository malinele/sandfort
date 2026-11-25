"""Egress allowlist updates: the shared request logic of ``Client`` and ``AsyncClient``."""

from collections.abc import Sequence

from sandfort_sdk._requests import sandbox_path
from sandfort_sdk._transport import AsyncTransport, SyncTransport
from sandfort_sdk.models import SandboxInfo
from sandfort_sdk.sandbox import AsyncSandbox, Sandbox

EGRESS_FIELD = "egress_allowlist"


def allowlist_body(entries: Sequence[str]) -> dict[str, list[str]]:
    """The PATCH body that replaces a sandbox's allowlist; ``[]`` blocks every connection.

    Entries are sent as given, the server validates them. A bare string or ``None`` raises
    :class:`TypeError` (``None`` would ask the server to drop the list, which it refuses).
    """
    if isinstance(entries, str | bytes) or entries is None:
        raise TypeError(f"entries must be a sequence of strings, not {type(entries).__name__}")
    return {EGRESS_FIELD: list(entries)}


def set_allowlist(transport: SyncTransport, sandbox_id: str, entries: Sequence[str]) -> Sandbox:
    """Replace the egress allowlist of ``sandbox_id`` and return the updated sandbox."""
    body = allowlist_body(entries)
    reply = transport.request("PATCH", sandbox_path(sandbox_id), json=body)
    return Sandbox(SandboxInfo.from_payload(reply.data), transport)


async def aset_allowlist(
    transport: AsyncTransport, sandbox_id: str, entries: Sequence[str]
) -> AsyncSandbox:
    """Async twin of :func:`set_allowlist`."""
    body = allowlist_body(entries)
    reply = await transport.request("PATCH", sandbox_path(sandbox_id), json=body)
    return AsyncSandbox(SandboxInfo.from_payload(reply.data), transport)
