"""SCIM error bodies: map platform exceptions and refusals to a SCIM status plus scimType.

Pure functions, no http routing, no database (``docs/scim-design.md``, Errors). The route
layer renders ``describe_failure(exc)`` with media type ``application/scim+json``. The table:

=============================================  ====  ==============================
Raised                                         HTTP  scimType
=============================================  ====  ==============================
``Unauthorized``                               401   none
``Forbidden``, ``ScopeEscalation``             403   none
``NotFound``                                   404   none
``Conflict`` (member exists, external id)      409   ``uniqueness``
``InvalidState`` (last admin)                  409   none
``ValidationFailed``                           400   ``invalidValue`` unless it names one
request validation, bad JSON                   400   ``invalidValue``, ``invalidSyntax``
unsupported filter, path, immutable change     400   ``invalidFilter``, ``invalidPath``,
                                                     ``mutability``
any other exception                            500   none, generic detail
=============================================  ====  ==============================

``detail`` is the message the service already produced. The 500 detail is generic and the cause
goes to the server log; no request header or token is ever part of a message. One addition to
the table: ``RateLimited`` is 429 with ``Retry-After`` and no scimType, because the design
requires a misconfigured provider loop to answer 429 and "any other exception" would make it 500.
"""

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from fastapi.exceptions import RequestValidationError

from sandfort.api.errors import INTERNAL_MESSAGE
from sandfort.api.scim.patch import INVALID_SYNTAX, INVALID_VALUE
from sandfort.errors import (
    Conflict,
    Forbidden,
    InvalidState,
    NotFound,
    RateLimited,
    SandfortError,
    Unauthorized,
    ValidationFailed,
)

logger = logging.getLogger(__name__)

ERROR_SCHEMA: Final = "urn:ietf:params:scim:api:messages:2.0:Error"
UNIQUENESS: Final = "uniqueness"
MUTABILITY: Final = "mutability"

_BAD_JSON_DETAIL: Final = "request body is not valid JSON"
_INVALID_REQUEST_DETAIL: Final = "request validation failed"
_JSON_INVALID_TYPE: Final = "json_invalid"
_MAX_ISSUES: Final = 5

# (exception type, HTTP status, scimType); the first match wins.
_TABLE: Final[tuple[tuple[type[SandfortError], int, str | None], ...]] = (
    (Unauthorized, 401, None),
    (Forbidden, 403, None),
    (NotFound, 404, None),
    (Conflict, 409, UNIQUENESS),
    (InvalidState, 409, None),
)
_BAD_REQUEST: Final = 400
_TOO_MANY_REQUESTS: Final = 429
_INTERNAL: Final = 500


class ScimValidationError(ValidationFailed):
    """A refusal that names its own scimType (HTTP 400), such as ``mutability``."""

    def __init__(self, scim_type: str, message: str) -> None:
        super().__init__(message)
        self.scim_type = scim_type


@dataclass(frozen=True, slots=True)
class ScimFailure:
    """What to answer: status, optional scimType, detail and extra response headers."""

    status: int
    detail: str
    scim_type: str | None = None
    headers: Mapping[str, str] = field(default_factory=dict)

    def body(self) -> dict[str, Any]:
        """The SCIM Error body; ``status`` is a string and ``scimType`` is absent when none."""
        body: dict[str, Any] = {"schemas": [ERROR_SCHEMA], "status": str(self.status)}
        if self.scim_type is not None:
            body["scimType"] = self.scim_type
        body["detail"] = self.detail
        return body


def describe_failure(exc: BaseException) -> ScimFailure:
    """Map ``exc`` to the SCIM status and scimType from the design's error table."""
    for error_type, status, scim_type in _TABLE:
        if isinstance(exc, error_type):
            return ScimFailure(status, exc.message, scim_type)
    if isinstance(exc, ValidationFailed):
        return ScimFailure(_BAD_REQUEST, exc.message, _scim_type_of(exc))
    if isinstance(exc, RequestValidationError):
        return _request_failure(exc)
    if isinstance(exc, json.JSONDecodeError):
        return ScimFailure(_BAD_REQUEST, _BAD_JSON_DETAIL, INVALID_SYNTAX)
    if isinstance(exc, RateLimited):
        headers = {"Retry-After": str(exc.retry_after_s)}
        return ScimFailure(_TOO_MANY_REQUESTS, exc.message, headers=headers)
    logger.error("unhandled scim error", exc_info=exc)
    return ScimFailure(_INTERNAL, INTERNAL_MESSAGE)


def _scim_type_of(exc: ValidationFailed) -> str:
    """The scimType the refusal names (filter and patch errors do), else ``invalidValue``."""
    scim_type = getattr(exc, "scim_type", None)
    return scim_type if isinstance(scim_type, str) else INVALID_VALUE


def _request_failure(exc: RequestValidationError) -> ScimFailure:
    """Bad JSON is ``invalidSyntax``; any other request validation issue is ``invalidValue``.

    Only the location and message of each issue are reported, never the submitted input.
    """
    issues = list(exc.errors())
    if any(issue.get("type") == _JSON_INVALID_TYPE for issue in issues):
        return ScimFailure(_BAD_REQUEST, _BAD_JSON_DETAIL, INVALID_SYNTAX)
    parts = [_issue_text(issue) for issue in issues[:_MAX_ISSUES]]
    return ScimFailure(_BAD_REQUEST, "; ".join(parts) or _INVALID_REQUEST_DETAIL, INVALID_VALUE)


def _issue_text(issue: Mapping[str, Any]) -> str:
    location = ".".join(str(part) for part in issue.get("loc", ()))
    message = str(issue.get("msg", _INVALID_REQUEST_DETAIL))
    return f"{location}: {message}" if location else message
