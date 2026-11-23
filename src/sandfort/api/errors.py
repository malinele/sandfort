"""Maps domain/driver errors to the response envelope and HTTP status."""

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.routing import Match

from sandfort.api.deps import UOW_FACTORY_ATTR, get_audit_recorder
from sandfort.api.envelope import fail
from sandfort.api.path_redaction import redact_path
from sandfort.api.safe_json import SafeJSONResponse
from sandfort.api.security_headers import CONTENT_TYPE_OPTIONS_HEADER, CONTENT_TYPE_OPTIONS_VALUE
from sandfort.auth.authenticate import (
    PRINCIPAL_STATE_ATTR,
    REFUSED_KEY_STATE_ATTR,
    RefusedKey,
    mark_refusal_audited,
)
from sandfort.auth.principal import Principal
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType, AuditOutcome
from sandfort.domain.lifecycle import IllegalTransition
from sandfort.drivers.docker.client import DISK_FULL_MESSAGE, DriverReadOnlyPath
from sandfort.drivers.errors import (
    DriverConflict,
    DriverError,
    DriverNotFound,
    DriverTimeout,
    DriverUnsupported,
)
from sandfort.errors import (
    DISK_FULL,
    RUNTIME_CONFLICT,
    CapacityExceeded,
    DnsUnavailable,
    InternalError,
    NodeUnavailable,
    QuotaExceeded,
    RateLimited,
    SandfortError,
)

logger = logging.getLogger(__name__)

REQUEST_ID_ATTR = "request_id"
INTERNAL_MESSAGE = "internal server error"
VALIDATION_MESSAGE = "request validation failed"
INVALID_JSON_MESSAGE = "request body is not valid JSON"
JSON_INVALID_TYPE = "json_invalid"  # pydantic's error type for a body that does not parse
# Every 4xx answer of an authenticated request is recorded on the caller's org audit chain as
# ``denied`` and every 5xx as ``error``; never ``success``. A 503 CAPACITY (the host is full)
# is a refusal and recorded ``denied``. A 429 is recorded only for QUOTA_EXCEEDED: RATE_LIMITED
# would flood the chain. A request whose service already recorded its refusal (see
# ``RequestAuditMark``) gets no second row from the handler.
CLIENT_ERROR_MIN = 400
SERVER_ERROR_MIN = 500
QUOTA_DENIED_STATUS = 429
DENIED_ACTION = "request.denied"
FAILED_ACTION = "request.failed"
AUDIT_MARK_ATTR = "audit_mark"  # request.state: the RequestAuditMark the middleware set up

READ_ONLY_PATH = "READ_ONLY_PATH"  # a write into a read-only mount (409)
METHOD_NOT_ALLOWED_STATUS = 405
PROBED_METHODS = ("DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT")
_HTTP_CODES = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}
_DRIVER_ERRORS: tuple[tuple[type[DriverError], int, str], ...] = (
    (DriverNotFound, 404, "NOT_FOUND"),
    (DriverConflict, 409, "CONFLICT"),
    (DriverUnsupported, 501, "UNSUPPORTED"),
    (DriverTimeout, 504, "DRIVER_TIMEOUT"),
)


@dataclass(slots=True)
class RequestAuditMark:
    """Per-request flag: a row stating this request's refusal is already on the audit chain.

    ``RequestIdMiddleware`` puts one on ``request.state`` (``AUDIT_MARK_ATTR``) for every HTTP
    request; the request's audit recorders set it when they record a ``denied`` or ``error``
    row. The exception handler then skips its own ``request.denied``/``request.failed`` row, so
    a refusal is audited once. Deliberately mutable: it is the one value that flows back from
    the services to the handler.
    """

    refusal_recorded: bool = False

    def note_refusal(self) -> None:
        self.refusal_recorded = True


def refusal_already_audited(request: Request) -> bool:
    mark = getattr(request.state, AUDIT_MARK_ATTR, None)
    return isinstance(mark, RequestAuditMark) and mark.refusal_recorded


@dataclass(frozen=True, slots=True)
class _Described:
    status: int
    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)


def error_response(exc: Exception, *, request_id: str | None = None) -> SafeJSONResponse:
    return _response(_describe(exc), request_id)


def _response(described: _Described, request_id: str | None) -> SafeJSONResponse:
    body = fail(described.code, described.message, details=described.details, request_id=request_id)
    return SafeJSONResponse(
        status_code=described.status,
        content=body.model_dump(mode="json"),
        # The generic Exception handler answers from ServerErrorMiddleware, outside the
        # security-headers middleware, so every error response sets the header itself.
        headers={**described.headers, CONTENT_TYPE_OPTIONS_HEADER: CONTENT_TYPE_OPTIONS_VALUE},
    )


def register_exception_handlers(app: FastAPI) -> None:
    for exc_type in (
        SandfortError,
        DriverError,
        IllegalTransition,
        RequestValidationError,
        StarletteHTTPException,
        Exception,
    ):
        app.add_exception_handler(exc_type, _handle)


async def _handle(request: Request, exc: Exception) -> SafeJSONResponse:
    request_id = getattr(request.state, REQUEST_ID_ATTR, None)
    described = _describe(exc)
    if described.status == METHOD_NOT_ALLOWED_STATUS:
        described = _with_allow(request, described)
    response = _response(described, request_id)
    await _audit_denial(request, described)
    return response


def _with_allow(request: Request, described: _Described) -> _Described:
    """``described`` with an ``Allow`` header naming every method the requested path supports.

    Starlette answers a wrong method from the first route that matches the path, so its own
    ``Allow`` lists only that route's methods; a path served by several routes (GET and DELETE,
    GET and HEAD) is under-reported. Each standard method is probed against the router (the
    public ``matches`` of every route, included routers too) and the ones that match fully are
    listed, sorted so the header is stable.
    """
    routes = request.app.router.routes
    methods = sorted(
        method
        for method in PROBED_METHODS
        if any(
            route.matches({**request.scope, "method": method})[0] == Match.FULL for route in routes
        )
    )
    if not methods:
        return described
    return _Described(
        described.status,
        described.code,
        described.message,
        described.details,
        {**described.headers, "Allow": ", ".join(methods)},
    )


async def _audit_denial(request: Request, described: _Described) -> None:
    """Best-effort: put an authenticated refusal on the caller's org audit chain.

    Also covers a revoked or expired stored key (``RefusedKey`` on request.state), whose org is
    known; its row carries an extra ``reason``. Where the key is refused only checks the throttle;
    the slot is marked here, after the row was committed, so a failed write leaves the key due and
    the next refusal tries again.

    Skipped when a service of this request already recorded the refusal (a capacity refusal,
    a refused toolbox upload): the request leaves one row, not two.

    Never raises; the client's error response does not depend on this succeeding.
    """
    try:
        if refusal_already_audited(request):
            return
        principal = getattr(request.state, PRINCIPAL_STATE_ATTR, None)
        refused = getattr(request.state, REFUSED_KEY_STATE_ATTR, None)
        extra: dict[str, str] = {}
        if isinstance(principal, Principal):
            org_id, key_id = principal.org_id, principal.key_id
        elif isinstance(refused, RefusedKey):
            org_id, key_id = refused.org_id, refused.key_id
            extra["reason"] = refused.reason
        else:
            return
        outcome = _audited_outcome(described)
        if outcome is None:
            return
        uow_factory = getattr(request.app.state, UOW_FACTORY_ATTR, None)
        if not callable(uow_factory):
            logger.warning("refused request not audited: no unit-of-work factory configured")
            return
        details = {
            "method": request.method,
            "path": redact_path(request.url.path),
            **_outcome_details(described),
            **extra,
        }
        uow: UnitOfWorkPort = uow_factory()
        async with uow:
            await get_audit_recorder(request).record(
                uow,
                org_id=org_id,
                actor_type=ActorType.API_KEY,
                actor_id=key_id,
                action=DENIED_ACTION if outcome is AuditOutcome.DENIED else FAILED_ACTION,
                outcome=outcome,
                details=details,
            )
            await uow.commit()
        if isinstance(refused, RefusedKey) and not isinstance(principal, Principal):
            mark_refusal_audited(refused.key_id, refused.at)
    except Exception:
        logger.exception("failed to audit a denied request")


def outcome_for_status(status: int) -> AuditOutcome | None:
    """``denied`` for a 4xx, ``error`` for a 5xx, ``None`` for any other status."""
    if status >= SERVER_ERROR_MIN:
        return AuditOutcome.ERROR
    if status >= CLIENT_ERROR_MIN:
        return AuditOutcome.DENIED
    return None


def _audited_outcome(described: _Described) -> AuditOutcome | None:
    if described.status == QUOTA_DENIED_STATUS and described.code != QuotaExceeded.code:
        return None
    return _refusal_outcome(described)


def _refusal_outcome(described: _Described) -> AuditOutcome | None:
    """``outcome_for_status``, except that a full host (503 CAPACITY) refused the call."""
    if described.status == CapacityExceeded.status and described.code == CapacityExceeded.code:
        return AuditOutcome.DENIED
    return outcome_for_status(described.status)


def _outcome_details(described: _Described) -> dict[str, Any]:
    details: dict[str, Any] = {
        "status": described.status,
        "error_code": described.code,  # not "code": redact_details digests that key
    }
    reason = described.details.get("reason")
    if isinstance(reason, str):
        details["reason"] = reason
    return details


def audit_outcome_for(exc: Exception) -> tuple[AuditOutcome, dict[str, Any]]:
    """The audit outcome and details (status, error code, reason) of the answer ``exc`` produces.

    For a route that audits its own row after the work ran, so the row carries what the client
    was told. A 503 CAPACITY maps to ``denied``, as in the handler; a status the handlers never
    raise as an error maps to ``error``.
    """
    described = _describe(exc)
    return _refusal_outcome(described) or AuditOutcome.ERROR, _outcome_details(described)


def _describe(exc: Exception) -> _Described:
    if isinstance(exc, SandfortError):
        return _Described(exc.status, exc.code, exc.message, exc.details, _retry_headers(exc))
    if isinstance(exc, DriverError):
        return _describe_driver(exc)
    if isinstance(exc, IllegalTransition):
        details = {"state": exc.source.value, "target": exc.target.value}
        return _Described(409, "INVALID_STATE", str(exc), details)
    if isinstance(exc, RequestValidationError):
        issues = [_issue(err) for err in exc.errors()]
        return _Described(422, "VALIDATION_ERROR", _validation_message(issues), {"errors": issues})
    if isinstance(exc, StarletteHTTPException):
        code = _HTTP_CODES.get(exc.status_code, f"HTTP_{exc.status_code}")
        return _Described(exc.status_code, code, str(exc.detail), headers=dict(exc.headers or {}))
    logger.error("unhandled error", exc_info=exc)
    return _Described(InternalError.status, InternalError.code, INTERNAL_MESSAGE)


def _issue(err: Mapping[str, Any]) -> dict[str, Any]:
    """One validation issue on the wire; an unparseable body is located at ``["body"]`` alone."""
    loc = [str(part) for part in err["loc"]]
    if err["type"] == JSON_INVALID_TYPE:
        # Pydantic appends the character offset of the parse error, which is no field.
        loc = loc[:1]
    return {"loc": loc, "msg": err["msg"], "type": err["type"]}


def _validation_message(issues: list[dict[str, Any]]) -> str:
    """The base message plus the first issue, so the message alone says what is wrong."""
    if not issues:
        return VALIDATION_MESSAGE
    first = issues[0]
    if first["type"] == JSON_INVALID_TYPE:
        # The loc is an internal position index (``body.1``), no use to a client.
        return INVALID_JSON_MESSAGE
    message = f"{VALIDATION_MESSAGE}: {'.'.join(first['loc'])}: {first['msg']}"
    if len(issues) > 1:
        message += f" (and {len(issues) - 1} more)"
    return message


def _retry_headers(exc: SandfortError) -> dict[str, str]:
    if isinstance(exc, RateLimited | NodeUnavailable | CapacityExceeded | DnsUnavailable):
        return {"Retry-After": str(exc.retry_after_s)}
    return {}


def _describe_driver(exc: DriverError) -> _Described:
    if isinstance(exc, DriverReadOnlyPath):
        details = {} if exc.path is None else {"path": exc.path}
        return _Described(409, READ_ONLY_PATH, exc.message, details)
    for error_type, status, code in _DRIVER_ERRORS:
        if isinstance(exc, error_type):
            return _Described(status, code, exc.message, _driver_details(exc))
    return _Described(502, "DRIVER_ERROR", exc.message)


def _driver_details(exc: DriverError) -> dict[str, Any]:
    """A driver conflict carries the same ``reason`` key as a domain ``Conflict``."""
    if not isinstance(exc, DriverConflict):
        return {}
    return {"reason": DISK_FULL if exc.message == DISK_FULL_MESSAGE else RUNTIME_CONFLICT}
