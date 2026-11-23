"""Deliver one signed payload to one endpoint.

Every attempt re-vets the endpoint URL (``ssrf.vet_url``) and connects to the vetted IP, sending
the original host in the ``Host`` header (and as the TLS server name), so DNS rebinding cannot
move a request after admission. Redirects are never followed: the 3xx status is returned and
the caller counts it as a failure. The response body is never read.

DEADLINE: one ``asyncio.timeout(timeout_s)`` covers the whole attempt, vetting (which resolves
DNS) included, so a stalling resolver or a silent endpoint costs at most ``timeout_s`` per
attempt. A separate vetting timeout would need a second knob and would still let an attempt
run past ``timeout_s``; the single deadline keeps one bound the dispatcher can plan around.
The httpx client keeps its per-phase timeout of the same value; the outer deadline binds.

ERROR CONTRACT (non-negotiable): every exception raised while vetting or sending is caught and
replaced by ``DeliveryError`` whose message is exactly ``<endpoint id>:<exception class name>``.
Never the stringified exception, a header or the URL: transport errors can embed any of them,
and the headers carry a signature derived from the endpoint secret. The error is raised outside
the ``except`` block with ``from None``, so it has neither a cause nor a context that could
carry the original exception. ``DeliveryError.reason`` is the one extra: a label chosen by
``classify_failure`` from a fixed set (dns, connect, tls, timeout, body too large, ssrf
refused) or ``transport error (<class name>)``. Exception text is only compared, never kept.

DELIVERY DETAIL: ``append_capped`` keeps the per-delivery attempt history at
``MAX_HISTORY_ENTRIES`` (the first try plus one retry per backoff step, newest entries win) and
``redeliver`` starts a new cycle for a dead or parked delivery while keeping that history.
"""

import asyncio
import socket
import ssl
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import datetime
from typing import Any

import httpx

from sandfort.db.models.webhooks import DeliveryState
from sandfort.db.repositories.ports import WebhookDeliveryRecord, WebhookEndpointRecord
from sandfort.webhooks.secret_box import SecretBox
from sandfort.webhooks.signing import sign_headers
from sandfort.webhooks.ssrf import (
    HostNotResolved,
    ResolverUnavailable,
    UrlRejected,
    VettedUrl,
    vet_url,
)

DEFAULT_TIMEOUT_S = 10.0
USER_AGENT = "sandfort-webhooks/1"
CONTENT_TYPE = "application/json"
MAX_HISTORY_ENTRIES = 6  # six attempts: the first try and one retry per backoff step (5)
MAX_ERROR_CHARS = 200
REASON_DNS = "dns"
REASON_CONNECT = "connect"
REASON_TLS = "tls"
REASON_TIMEOUT = "timeout"
REASON_BODY_TOO_LARGE = "body too large"
REASON_SSRF = "ssrf refused"
MAX_CHAIN = 8

type HistoryEntry = Mapping[str, Any]


class DeliveryError(Exception):
    """A delivery attempt failed before a status came back; the message is ``id:ClassName``."""

    def __init__(self, endpoint_id: str, error_class: str, reason: str = "") -> None:
        super().__init__(f"{endpoint_id}:{error_class}")
        self.reason = reason or f"transport error ({error_class})"


def _chain(exc: BaseException) -> list[BaseException]:
    """``exc`` followed by its causes and contexts (bounded, so a cycle cannot loop)."""
    found: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and len(found) < MAX_CHAIN:
        found.append(current)
        current = current.__cause__ or current.__context__
    return found


def classify_failure(exc: BaseException) -> str:
    """The short stored reason for a failed attempt; never carries exception text."""
    chain = _chain(exc)
    if isinstance(exc, HostNotResolved | ResolverUnavailable):
        return REASON_DNS  # a failed lookup is retried like a missing name
    if isinstance(exc, UrlRejected):
        return REASON_SSRF
    if any(isinstance(item, socket.gaierror) for item in chain):
        return REASON_DNS
    if isinstance(exc, TimeoutError | httpx.TimeoutException):
        return REASON_TIMEOUT
    if any(isinstance(item, ssl.SSLError) for item in chain):
        return REASON_TLS
    if isinstance(exc, httpx.RemoteProtocolError) and "too long" in str(exc).lower():
        return REASON_BODY_TOO_LARGE
    if isinstance(exc, httpx.ConnectError | OSError):
        return REASON_CONNECT
    return f"transport error ({type(exc).__name__})"


def append_capped(
    history: Sequence[HistoryEntry], entry: HistoryEntry, cap: int = MAX_HISTORY_ENTRIES
) -> tuple[HistoryEntry, ...]:
    """``history`` plus ``entry`` as a new tuple, trimmed to the newest ``cap`` entries."""
    return (*history, entry)[-cap:]


def redeliver(
    delivery: WebhookDeliveryRecord, *, actor_id: str, now: datetime
) -> WebhookDeliveryRecord:
    """A requeued copy of ``delivery``: a new cycle, the old history kept, a marker appended.

    State goes back to ``pending`` with no attempts and no schedule: ``next_attempt_at`` stays
    ``None`` (due at once) so the caller's clock never decides when a worker sends; the
    dispatcher stamps the time on the next attempt. The last status and the last error are
    cleared together, so the two always agree; the history keeps the old outcome.
    """
    marker: HistoryEntry = {"kind": "redelivered", "at": now.isoformat(), "actor_id": actor_id}
    return replace(
        delivery,
        state=DeliveryState.PENDING.value,
        attempts=0,
        next_attempt_at=None,
        last_status=None,
        last_error=None,
        updated_at=now,
        attempt_history=append_capped(delivery.attempt_history, marker),
    )


async def _post(
    vetted: VettedUrl,
    headers: dict[str, str],
    payload: bytes,
    timeout_s: float,
    transport: httpx.AsyncBaseTransport | None,
) -> int:
    extensions: dict[str, object] = {}
    if vetted.scheme == "https" and vetted.host != vetted.ip:
        extensions["sni_hostname"] = vetted.host  # verify the certificate for the real host
    async with httpx.AsyncClient(
        transport=transport, timeout=timeout_s, follow_redirects=False, trust_env=False
    ) as client:
        request = client.build_request(
            "POST",
            vetted.connect_url,
            headers=headers,
            content=payload,
            extensions=extensions,
        )
        response = await client.send(request, stream=True)
        try:
            return response.status_code
        finally:
            await response.aclose()


async def deliver(
    endpoint: WebhookEndpointRecord,
    *,
    message_id: str,
    timestamp: int,
    payload: bytes,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    transport: httpx.AsyncBaseTransport | None = None,
    secret_box: SecretBox | None = None,
) -> int:
    """POST ``payload`` signed with the endpoint secret; return the HTTP status.

    ``secret_box`` unseals the stored secret right before signing (the plaintext lives only in
    this frame); without one the stored value is used as is. ``timeout_s`` is the deadline of
    the whole attempt, URL vetting and its DNS lookup included (see DEADLINE above); running
    out of it fails the attempt as ``<endpoint id>:TimeoutError``.
    Raises ``DeliveryError`` (see the module docstring) for any failure to get a status.
    """
    failure: str | None = None
    reason = ""
    status = 0
    try:
        async with asyncio.timeout(timeout_s):  # one deadline: vetting (dns) plus the request
            vetted = await vet_url(endpoint.url)
            secret = endpoint.secret if secret_box is None else secret_box.decrypt(endpoint.secret)
            headers = {
                **sign_headers(secret, message_id, timestamp, payload),
                "Content-Type": CONTENT_TYPE,
                "User-Agent": USER_AGENT,
                "Host": vetted.host_header,
            }
            status = await _post(vetted, headers, payload, timeout_s, transport)
    except Exception as exc:
        failure = type(exc).__name__
        reason = classify_failure(exc)
    if failure is not None:
        raise DeliveryError(endpoint.id, failure, reason) from None
    return status
