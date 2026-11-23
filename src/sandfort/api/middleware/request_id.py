"""``X-Request-Id`` correlation for every HTTP request (WP 4.5).

``RequestIdMiddleware`` keeps a well-formed client-supplied ``X-Request-Id`` (1-64 characters
of ``[A-Za-z0-9._-]``) or mints ``req_<hex>``, then exposes it three ways while the request is
served: on ``request.state`` for the error envelope, in the logging context variable picked up
by the JSON log formatter, and on the response ``X-Request-Id`` header. It is a pure ASGI
middleware, so streamed responses and the context variable behave like any other request.

The middleware also binds the client ip (the ASGI scope client only) and the ``User-Agent``
header the same way. ``CorrelatedAuditRecorder`` fills the audit row's ``request_id``, ``ip`` and
``user_agent`` columns from those context variables whenever the caller did not pass them. The
bound values are cut to the audit column widths (``MAX_IP_LENGTH``, ``MAX_USER_AGENT_LENGTH``).

It also owns the request's ``RequestAuditMark`` (``request.state.audit_mark``, bound to a context
variable too): ``CorrelatedAuditRecorder`` sets it once the unit of work that holds a ``denied``
or ``error`` row has committed, and the exception handler then writes no second row. A row
whose commit fails or is rolled back leaves the mark unset, so the handler writes its own.
"""

import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextvars import ContextVar
from typing import Any, cast

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sandfort.api.errors import (
    AUDIT_MARK_ATTR,
    REQUEST_ID_ATTR,
    RequestAuditMark,
    audit_outcome_for,
)
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType, AuditEvent, AuditOutcome
from sandfort.drivers.base import ArchiveStreamDriver, SandboxDriver
from sandfort.drivers.errors import DriverUnsupported
from sandfort.logging import (
    bind_client_ip,
    bind_request_id,
    bind_user_agent,
    current_client_ip,
    current_request_id,
    current_user_agent,
    reset_client_ip,
    reset_request_id,
    reset_user_agent,
)
from sandfort.services.audit import AuditRecorder

REQUEST_ID_HEADER = "X-Request-Id"
USER_AGENT_HEADER = "User-Agent"
MINTED_PREFIX = "req_"
MAX_IP_LENGTH = 45  # the audit ``ip`` column: String(45), the longest textual IPv6 address
MAX_USER_AGENT_LENGTH = 512  # the audit ``user_agent`` column: String(512)
_CLIENT_REQUEST_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
_AUDIT_MARK: ContextVar[RequestAuditMark | None] = ContextVar("sandfort_audit_mark", default=None)


def note_refusal_recorded() -> None:
    """Mark the current request: its refusal is on the audit chain (no-op outside a request)."""
    mark = _AUDIT_MARK.get()
    if mark is not None:
        mark.note_refusal()


def note_refusal_after_commit(uow: UnitOfWorkPort) -> None:
    """Mark the request once ``uow`` has committed the refusal row it holds.

    The unit of work's ``commit`` is wrapped for this instance: the mark is set only after the
    commit returned, so a commit that fails (or a rollback) leaves the request unmarked and the
    exception handler records the refusal itself. A unit of work that cannot take the wrapper
    is marked at once, the earlier behaviour.
    """
    commit: Callable[[], Awaitable[None]] = uow.commit

    async def commit_then_mark() -> None:
        await commit()
        note_refusal_recorded()

    try:
        object.__setattr__(uow, "commit", commit_then_mark)
    except (AttributeError, TypeError):
        note_refusal_recorded()


def resolve_request_id(supplied: str | None) -> str:
    """The client's id when it is well formed, else a freshly minted one."""
    if supplied is not None and _CLIENT_REQUEST_ID.fullmatch(supplied) is not None:
        return supplied
    return f"{MINTED_PREFIX}{uuid.uuid4().hex}"


def resolve_client_ip(scope: Scope) -> str | None:
    """The ASGI scope client (the socket peer), or ``None`` when absent or too long for the column.

    ``X-Forwarded-For`` is deliberately not read here: a caller could forge it. uvicorn rewrites
    ``scope["client"]`` from that header only when the peer is in ``SANDFORT_FORWARDED_ALLOW_IPS``
    (operations runbook, "Behind a TLS-terminating proxy"), so the proxy trust is configured
    there and nowhere in this module.
    """
    client = scope.get("client")
    if not client:
        return None
    peer = str(client[0]).strip()
    if not peer or len(peer) > MAX_IP_LENGTH:
        return None
    return peer


def resolve_user_agent(supplied: str | None) -> str | None:
    """The ``User-Agent`` value cut to the audit column width."""
    if supplied is None:
        return None
    return supplied[:MAX_USER_AGENT_LENGTH]


class RequestIdMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        request_id = resolve_request_id(headers.get(REQUEST_ID_HEADER))
        mark = RequestAuditMark()
        state = scope.setdefault("state", {})
        state[REQUEST_ID_ATTR] = request_id
        state[AUDIT_MARK_ATTR] = mark

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                message.setdefault("headers", [])  # optional in the ASGI spec
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = request_id
            await send(message)

        token = bind_request_id(request_id)
        ip_token = bind_client_ip(resolve_client_ip(scope))
        agent_token = bind_user_agent(resolve_user_agent(headers.get(USER_AGENT_HEADER)))
        mark_token = _AUDIT_MARK.set(mark)
        try:
            await self.app(scope, receive, send_with_id)
        finally:
            _AUDIT_MARK.reset(mark_token)
            reset_user_agent(agent_token)
            reset_client_ip(ip_token)
            reset_request_id(token)


class DeferredAudit:
    """An audit sink that holds a toolbox call's row until the call reaches its act or is refused.

    The toolbox records its row while it guards the sandbox; handed to it in place of the
    recorder, this sink keeps that row back while the call's own checks run.

    * ``write_intent`` commits the held row as ``success`` right before the act that changes
      the sandbox (the route calls it ahead of the driver write), intent-then-act: a failing
      audit write refuses the call before anything is stored.
    * ``settle`` records a refusal: the held row itself when the call was refused before the
      act, else a second row of the same action after the committed intent. It is ``denied``
      (4xx, and a 503 CAPACITY) or ``error`` (5xx), with the status, error code and reason of
      the answer in the details. The second row carries ``details.supersedes``, the id of the
      intent row it follows, so a reader can pair the two.

    Every refusal row marks the request (``note_refusal_recorded``), so the exception handler
    adds no ``request.denied``/``request.failed`` row: the handler covers only calls that
    recorded nothing, i.e. those refused before the toolbox recorded its row.
    """

    def __init__(self, recorder: AuditRecorder) -> None:
        self._recorder = recorder
        self._held: dict[str, Any] | None = None
        self._intent: dict[str, Any] | None = None  # the row committed by ``write_intent``
        self._intent_id: str | None = None  # its audit event id

    async def record(
        self,
        uow: UnitOfWorkPort,
        *,
        org_id: str,
        actor_type: ActorType,
        actor_id: str | None,
        action: str,
        target_type: str | None = None,
        target_id: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> object:
        self._held = {
            "org_id": org_id,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "details": dict(details or {}),
        }
        return None

    async def write_intent(self, uow: UnitOfWorkPort) -> None:
        """Commit the held row (if any) as ``success``; raises if the write fails.

        The row stays held until the commit succeeded, so a refusal after a failed write is
        still recorded by ``settle``.
        """
        held = self._held
        if held is None:
            return
        async with uow:
            event = await self._recorder.record(uow, outcome=AuditOutcome.SUCCESS, **held)
            await uow.commit()
        self._held, self._intent = None, held
        self._intent_id = event.id

    async def settle(self, uow: UnitOfWorkPort, error: Exception) -> None:
        """Record the refusal ``error`` of the call; raises if the write fails.

        Nothing is written when the call was refused before the toolbox recorded its row.
        """
        row = self._held if self._held is not None else self._intent
        supersedes = self._intent_id if self._held is None else None
        self._held = self._intent = self._intent_id = None
        if row is None:
            return
        outcome, extra = audit_outcome_for(error)
        link = {} if supersedes is None else {"supersedes": supersedes}
        async with uow:
            await self._recorder.record(
                uow, outcome=outcome, **{**row, "details": {**row["details"], **extra, **link}}
            )
            await uow.commit()
        note_refusal_recorded()


def audit_before_write(
    driver: SandboxDriver, audit: DeferredAudit, uow: UnitOfWorkPort
) -> SandboxDriver:
    """``driver`` for an upload whose ``put_archive`` commits ``audit``'s held row first."""
    return cast(SandboxDriver, _IntentBeforeWrite(driver, audit, uow))


class _IntentBeforeWrite:
    """A driver that commits the held audit row just before the archive is written.

    Every other driver call (the guard's probes, the directory and existence checks, the
    partial-file cleanup) passes through unchanged, so a refusal by those checks is audited
    once as ``denied``. The row is on the chain before ``put_archive`` runs: a failing audit
    write answers an error and stores nothing (intent-then-act).
    """

    def __init__(self, driver: SandboxDriver, audit: DeferredAudit, uow: UnitOfWorkPort) -> None:
        self._driver = driver
        self._audit = audit
        self._uow = uow

    def __getattr__(self, name: str) -> Any:
        return getattr(self._driver, name)

    def _archive(self) -> ArchiveStreamDriver:
        if not isinstance(self._driver, ArchiveStreamDriver):
            raise DriverUnsupported("the driver does not support archive streaming")
        return self._driver

    # Both archive methods are defined here, not reached through ``__getattr__``: the runtime
    # ``ArchiveStreamDriver`` check reads attributes statically.
    async def put_archive(self, ref: str, dest_path: str, data: AsyncIterator[bytes]) -> None:
        archive = self._archive()
        await self._audit.write_intent(self._uow)
        await archive.put_archive(ref, dest_path, data)

    async def get_archive_with_stat(
        self, ref: str, path: str
    ) -> tuple[Mapping[str, Any], AsyncIterator[bytes]]:
        return await self._archive().get_archive_with_stat(ref, path)


class CorrelatedAuditRecorder(AuditRecorder):
    """An ``AuditRecorder`` that stamps the request id, client ip and user agent of the current
    request on rows recorded without them.

    Recording a ``denied`` or ``error`` row during a request also sets the request's
    ``RequestAuditMark``, but only after the unit of work holding the row has committed: the
    service has audited the refusal, the exception handler skips it. If that commit fails the
    mark stays unset and the handler writes the row.
    """

    async def record(
        self,
        uow: UnitOfWorkPort,
        *,
        org_id: str,
        actor_type: ActorType,
        actor_id: str | None,
        action: str,
        target_type: str | None = None,
        target_id: str | None = None,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        request_id: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> AuditEvent:
        event = await super().record(
            uow,
            org_id=org_id,
            actor_type=actor_type,
            actor_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            outcome=outcome,
            request_id=request_id if request_id is not None else current_request_id(),
            ip=ip if ip is not None else current_client_ip(),
            user_agent=user_agent if user_agent is not None else current_user_agent(),
            details=details,
        )
        if outcome is not AuditOutcome.SUCCESS:
            note_refusal_after_commit(uow)
        return event
