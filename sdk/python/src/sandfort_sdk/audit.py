"""Audit events (``client.audit``): list, page through, verify the hash chain and export.

``list`` and ``iter`` return parsed events; ``export`` returns the raw newline-delimited JSON
body, one event per line, and ``export_lines`` yields that body line by line as it arrives.
"""

from collections.abc import AsyncIterator, Iterator
from datetime import datetime
from typing import Any, Literal

import httpx

from sandfort_sdk._transport import AsyncTransport, Reply, SyncTransport, stream_read_error
from sandfort_sdk.audit_head import public_key_from_status
from sandfort_sdk.audit_verify import AsyncAuditVerifyMixin, AuditVerifyMixin
from sandfort_sdk.models import AuditEvent, AuditPage, AuditVerifyResult, _as_list

STATUS_PATH = "/v1/status"
AUDIT_PATH = "/v1/audit-events"
AUDIT_VERIFY_PATH = "/v1/audit-events/verify"
AUDIT_EXPORT_PATH = "/v1/audit-events/export"
DEFAULT_LIMIT = 50
MIN_LIMIT = 1
MAX_LIMIT = 100
AuditOrder = Literal["asc", "desc"]
AUDIT_ORDERS: tuple[str, ...] = ("asc", "desc")


def _text(value: str | None, name: str) -> str | None:
    if value is not None and not value.strip():
        raise ValueError(f"{name!r} must not be empty")
    return value


def _moment(value: datetime | None, name: str) -> str | None:
    """ISO 8601 with the UTC offset; a naive datetime is ambiguous, so it is refused."""
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name!r} must be timezone-aware")
    return value.isoformat()


def _present(params: dict[str, str | int | None]) -> dict[str, Any] | None:
    kept = {key: value for key, value in params.items() if value is not None}
    return kept or None


def audit_list_params(
    *,
    actor_id: str | None,
    action: str | None,
    target_id: str | None,
    request_id: str | None,
    outcome: str | None,
    from_: datetime | None,
    to: datetime | None,
    order: str,
    cursor: str | None,
    limit: int,
) -> dict[str, Any]:
    """The query of a list call; raises ``ValueError`` before any request is made."""
    if order not in AUDIT_ORDERS:
        raise ValueError(f"order must be one of {', '.join(AUDIT_ORDERS)}; got {order!r}")
    if isinstance(limit, bool) or not MIN_LIMIT <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be between {MIN_LIMIT} and {MAX_LIMIT}; got {limit!r}")
    params = _present(
        {
            "actor_id": _text(actor_id, "actor_id"),
            "action": _text(action, "action"),
            "target_id": _text(target_id, "target_id"),
            "request_id": _text(request_id, "request_id"),
            "outcome": _text(outcome, "outcome"),
            "from": _moment(from_, "from_"),
            "to": _moment(to, "to"),
            "cursor": _text(cursor, "cursor"),
            "order": order,
            "limit": limit,
        }
    )
    return params or {}


def audit_export_params(
    *,
    request_id: str | None,
    outcome: str | None,
    from_: datetime | None,
    to: datetime | None,
) -> dict[str, Any] | None:
    return _present(
        {
            "from": _moment(from_, "from_"),
            "to": _moment(to, "to"),
            "request_id": _text(request_id, "request_id"),
            "outcome": _text(outcome, "outcome"),
        }
    )


def audit_verify_params(from_id: str | None) -> dict[str, Any] | None:
    return _present({"from_id": _text(from_id, "from_id")})


def split_lines(text: str) -> tuple[list[str], str]:
    """The complete lines of ``text`` (each ending in ``\\n``) and the unfinished rest."""
    *complete, rest = text.split("\n")
    return [f"{line}\n" for line in complete], rest


def audit_page(reply: Reply) -> AuditPage:
    items = _as_list(reply.data, "audit events")
    return AuditPage(tuple(AuditEvent.from_payload(item) for item in items), reply.next_cursor)


class Audit(AuditVerifyMixin):
    """Synchronous audit client."""

    def __init__(self, transport: SyncTransport) -> None:
        self._transport = transport

    def list(
        self,
        *,
        actor_id: str | None = None,
        action: str | None = None,
        target_id: str | None = None,
        request_id: str | None = None,
        outcome: str | None = None,
        from_: datetime | None = None,
        to: datetime | None = None,
        order: AuditOrder = "asc",
        cursor: str | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> AuditPage:
        """One page of events (``limit`` 1..100); ``from_`` and ``to`` must be timezone-aware.

        Page on with ``cursor=page.next_cursor`` and the same ``order``.
        """
        params = audit_list_params(
            actor_id=actor_id, action=action, target_id=target_id, request_id=request_id,
            outcome=outcome, from_=from_, to=to, order=order, cursor=cursor, limit=limit,
        )  # fmt: skip
        return audit_page(self._transport.request("GET", AUDIT_PATH, params=params))

    def iter(
        self,
        *,
        actor_id: str | None = None,
        action: str | None = None,
        target_id: str | None = None,
        request_id: str | None = None,
        outcome: str | None = None,
        from_: datetime | None = None,
        to: datetime | None = None,
        order: AuditOrder = "asc",
        limit: int = DEFAULT_LIMIT,
    ) -> Iterator[AuditEvent]:
        """Every event of :meth:`list`, page by page, until there is no next cursor."""
        cursor: str | None = None
        while True:
            page = self.list(
                actor_id=actor_id, action=action, target_id=target_id, request_id=request_id,
                outcome=outcome, from_=from_, to=to, order=order, cursor=cursor, limit=limit,
            )  # fmt: skip
            yield from page.events
            if page.next_cursor is None:
                return
            cursor = page.next_cursor

    def verify(self, from_id: str | None = None) -> AuditVerifyResult:
        """Walk the org's hash chain; ``from_id`` starts at that event instead of the first."""
        params = audit_verify_params(from_id)
        reply = self._transport.request("GET", AUDIT_VERIFY_PATH, params=params)
        return AuditVerifyResult.from_payload(reply.data)

    def export_lines(
        self,
        *,
        request_id: str | None = None,
        outcome: str | None = None,
        from_: datetime | None = None,
        to: datetime | None = None,
    ) -> Iterator[str]:
        """The export body line by line as it arrives, each line with its ``\\n`` (the last
        one may lack it). Filters are checked now; the request is sent on the first ``next``.
        """
        params = audit_export_params(request_id=request_id, outcome=outcome, from_=from_, to=to)
        return self._export_stream(params)

    def _export_stream(self, params: dict[str, Any] | None) -> Iterator[str]:
        response = self._transport.open_stream("GET", AUDIT_EXPORT_PATH, params=params)
        try:
            pending = ""
            for chunk in response.iter_text():
                lines, pending = split_lines(pending + chunk)
                yield from lines
            if pending:
                yield pending
        except httpx.HTTPError as exc:
            raise stream_read_error(exc) from exc
        finally:
            response.close()

    def export(
        self,
        *,
        request_id: str | None = None,
        outcome: str | None = None,
        from_: datetime | None = None,
        to: datetime | None = None,
    ) -> str:
        """The matching events as the server's newline-delimited JSON body, unparsed."""
        lines = self.export_lines(request_id=request_id, outcome=outcome, from_=from_, to=to)
        return "".join(lines)

    def public_key(self) -> str | None:
        """``audit_public_key`` of ``GET /v1/status`` (urlsafe base64), ``None`` when unset."""
        return public_key_from_status(self._transport.request("GET", STATUS_PATH).data)


class AsyncAudit(AsyncAuditVerifyMixin):
    """Asynchronous audit client."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def list(
        self,
        *,
        actor_id: str | None = None,
        action: str | None = None,
        target_id: str | None = None,
        request_id: str | None = None,
        outcome: str | None = None,
        from_: datetime | None = None,
        to: datetime | None = None,
        order: AuditOrder = "asc",
        cursor: str | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> AuditPage:
        """One page of events (``limit`` 1..100); ``from_`` and ``to`` must be timezone-aware.

        Page on with ``cursor=page.next_cursor`` and the same ``order``.
        """
        params = audit_list_params(
            actor_id=actor_id, action=action, target_id=target_id, request_id=request_id,
            outcome=outcome, from_=from_, to=to, order=order, cursor=cursor, limit=limit,
        )  # fmt: skip
        return audit_page(await self._transport.request("GET", AUDIT_PATH, params=params))

    async def iter(
        self,
        *,
        actor_id: str | None = None,
        action: str | None = None,
        target_id: str | None = None,
        request_id: str | None = None,
        outcome: str | None = None,
        from_: datetime | None = None,
        to: datetime | None = None,
        order: AuditOrder = "asc",
        limit: int = DEFAULT_LIMIT,
    ) -> AsyncIterator[AuditEvent]:
        """Every event of :meth:`list`, page by page, until there is no next cursor."""
        cursor: str | None = None
        while True:
            page = await self.list(
                actor_id=actor_id, action=action, target_id=target_id, request_id=request_id,
                outcome=outcome, from_=from_, to=to, order=order, cursor=cursor, limit=limit,
            )  # fmt: skip
            for audit_event in page.events:
                yield audit_event
            if page.next_cursor is None:
                return
            cursor = page.next_cursor

    async def verify(self, from_id: str | None = None) -> AuditVerifyResult:
        """Walk the org's hash chain; ``from_id`` starts at that event instead of the first."""
        params = audit_verify_params(from_id)
        reply = await self._transport.request("GET", AUDIT_VERIFY_PATH, params=params)
        return AuditVerifyResult.from_payload(reply.data)

    def export_lines(
        self,
        *,
        request_id: str | None = None,
        outcome: str | None = None,
        from_: datetime | None = None,
        to: datetime | None = None,
    ) -> AsyncIterator[str]:
        """The export body line by line as it arrives, each line with its ``\\n`` (the last
        one may lack it). Filters are checked now; the request is sent on the first ``anext``.
        """
        params = audit_export_params(request_id=request_id, outcome=outcome, from_=from_, to=to)
        return self._export_stream(params)

    async def _export_stream(self, params: dict[str, Any] | None) -> AsyncIterator[str]:
        response = await self._transport.open_stream("GET", AUDIT_EXPORT_PATH, params=params)
        try:
            pending = ""
            async for chunk in response.aiter_text():
                lines, pending = split_lines(pending + chunk)
                for line in lines:
                    yield line
            if pending:
                yield pending
        except httpx.HTTPError as exc:
            raise stream_read_error(exc) from exc
        finally:
            await response.aclose()

    async def export(
        self,
        *,
        request_id: str | None = None,
        outcome: str | None = None,
        from_: datetime | None = None,
        to: datetime | None = None,
    ) -> str:
        """The matching events as the server's newline-delimited JSON body, unparsed."""
        lines = self.export_lines(request_id=request_id, outcome=outcome, from_=from_, to=to)
        return "".join([line async for line in lines])

    async def public_key(self) -> str | None:
        """``audit_public_key`` of ``GET /v1/status`` (urlsafe base64), ``None`` when unset."""
        reply = await self._transport.request("GET", STATUS_PATH)
        return public_key_from_status(reply.data)
