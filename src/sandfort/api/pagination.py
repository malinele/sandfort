"""Opaque cursor encoding over the last returned id (ULID-ordered), bound to a list filter.

A cursor made with filter values (``encode_cursor(last_id, values)``) carries those values in a
compact form (scalars as text, mappings as a short digest) and is refused with 422 when it is
presented with other values; the refusal names each differing field in ``ctx`` of the issue.
An older cursor bound to a hash only (``filter_fingerprint``) is still compared by that hash.
A cursor without a binding (an older cursor, or a route that has no filter) is accepted for any
filter, since there is nothing to compare.

A cursor is also bound to the resource that issued it (round 58): ``encode_cursor(..., resource=
"audit-events")`` labels it, and a route that decodes with ``resource=`` refuses a cursor issued
for another resource with 422 ("cursor was issued for sandboxes, not audit-events"). A cursor
without a label (an older one, or one from a route that does not label) is attributed to the
resource its id prefix belongs to, so an older cursor still pages the resource that issued it.
"""

import base64
import hashlib
import json
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlencode

from sandfort.errors import Unprocessable
from sandfort.ids import AUDIT, JOB, SANDBOX, SNAPSHOT, VOLUME, WEBHOOK, parse_id

_PAD = "="
_B64_QUANTUM = 4
_VALIDATION_PREFIX = "request validation failed"  # the base of every 422 validation message
_CURSOR_MESSAGE = "invalid cursor"
_FILTER_MESSAGE = "cursor was issued for a different filter or order"
_SEPARATOR = "|"
_FINGERPRINT_LENGTH = 12
_DIGEST_LENGTH = 8
_DIGEST_MARK = "~"  # a field value that is a digest, not the value itself
_FIELD_MARK = "="  # present in a field binding, never in a hex fingerprint
_RESOURCE_MARK = "/"  # ends the resource label in front of the id, never part of an id

SANDBOXES = "sandboxes"
SNAPSHOTS = "snapshots"
VOLUMES = "volumes"
JOBS = "jobs"
AUDIT_EVENTS = "audit-events"
WEBHOOK_DELIVERIES = "webhook-deliveries"
# The resource whose list issues ids of each prefix (an unlabeled cursor is attributed by it).
RESOURCE_BY_PREFIX: Mapping[str, str] = {
    SANDBOX: SANDBOXES,
    SNAPSHOT: SNAPSHOTS,
    VOLUME: VOLUMES,
    JOB: JOBS,
    AUDIT: AUDIT_EVENTS,
    WEBHOOK: WEBHOOK_DELIVERIES,
}


class QueryRefusal(Unprocessable):
    """422 in the validation shape: ``details.errors`` locates the problem at ``query.<name>``."""

    code = "VALIDATION_ERROR"

    def __init__(self, name: str, message: str, ctx: dict[str, Any] | None = None) -> None:
        issue: dict[str, Any] = {"type": "value_error", "loc": ["query", name], "msg": message}
        if ctx is not None:
            issue["ctx"] = ctx
        text = f"{_VALIDATION_PREFIX}: query.{name}: {message}"
        super().__init__(text, details={"errors": [issue]})


class InvalidCursor(QueryRefusal):
    def __init__(self, message: str = _CURSOR_MESSAGE, ctx: dict[str, Any] | None = None) -> None:
        super().__init__("cursor", message, ctx)


def _plain(value: Any) -> Any:
    return getattr(value, "value", str(value))


def filter_fingerprint(values: Mapping[str, Any]) -> str:
    """A short, stable digest of the filter values a cursor is bound to."""
    text = json.dumps(values, sort_keys=True, default=_plain)
    return hashlib.sha256(text.encode()).hexdigest()[:_FINGERPRINT_LENGTH]


def _field_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Mapping):
        if not value:
            return None
        text = json.dumps(value, sort_keys=True, default=_plain)
        return _DIGEST_MARK + hashlib.sha256(text.encode()).hexdigest()[:_DIGEST_LENGTH]
    return str(_plain(value))


def filter_fields(values: Mapping[str, Any]) -> dict[str, str]:
    """The compact text form of each set filter value (unset and empty values are left out)."""
    fields = {name: _field_text(value) for name, value in values.items()}
    return {name: text for name, text in sorted(fields.items()) if text is not None}


def _describe(name: str, issued: str | None, presented: str | None) -> str:
    if (issued or presented or "").startswith(_DIGEST_MARK):
        return f"a different {name}"
    shown = f"{name}={issued}" if issued is not None else f"{name} unset"
    return f"{shown}, not {presented if presented is not None else 'unset'}"


def _compare_fields(bound: str, values: Mapping[str, Any]) -> None:
    try:
        issued = dict(parse_qsl(bound, keep_blank_values=True, strict_parsing=True))
    except ValueError:
        raise InvalidCursor from None
    presented = filter_fields(values)
    differing = sorted(
        n for n in issued.keys() | presented.keys() if issued.get(n) != presented.get(n)
    )
    if not differing:
        return
    parts = [_describe(name, issued.get(name), presented.get(name)) for name in differing]
    reason = "cursor was issued with " + "; ".join(parts)
    raise InvalidCursor(_FILTER_MESSAGE, ctx={"fields": differing, "reason": reason})


def encode_cursor(
    last_id: str, values: Mapping[str, Any] | None = None, *, resource: str | None = None
) -> str:
    """Encode ``last_id``, bound to the filter ``values`` and the ``resource`` when given."""
    head = last_id if resource is None else f"{resource}{_RESOURCE_MARK}{last_id}"
    payload = head if values is None else f"{head}{_SEPARATOR}{urlencode(filter_fields(values))}"
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip(_PAD)


def _parse(cursor: str) -> tuple[str, str | None, str | None]:
    """``(last_id, issuing resource or None, filter binding or None)``; 422 when malformed."""
    padded = cursor + _PAD * (-len(cursor) % _B64_QUANTUM)
    try:
        payload = base64.b64decode(padded, altchars=b"-_", validate=True).decode()
        head, separator, bound = payload.partition(_SEPARATOR)
        label, mark, last_id = head.rpartition(_RESOURCE_MARK)
        prefix, _ = parse_id(last_id)
    except ValueError:
        raise InvalidCursor from None
    issued = RESOURCE_BY_PREFIX.get(prefix)
    if mark and label != issued:  # a label that does not match the id is not one we issued
        raise InvalidCursor
    return last_id, issued, bound if separator else None


def _check_resource(issued: str | None, resource: str) -> None:
    if issued is None:
        raise InvalidCursor
    if issued != resource:
        message = f"cursor was issued for {issued}, not {resource}"
        raise InvalidCursor(message, ctx={"resource": issued, "reason": message})


def decode_cursor(
    cursor: str, values: Mapping[str, Any] | None = None, *, resource: str | None = None
) -> str:
    """Return the last id; raise InvalidCursor (422) on a malformed or empty one.

    With ``resource``, a cursor issued for another resource is refused (an unlabeled cursor is
    attributed by its id prefix). With ``values``, a cursor bound to other filter values is
    refused as well; a cursor bound to a hash only (an older one) is compared by
    ``filter_fingerprint(values)``.
    """
    last_id, issued, bound = _parse(cursor)
    if resource is not None:
        _check_resource(issued, resource)
    if bound is None or values is None:
        return last_id
    if _FIELD_MARK in bound or not bound:
        _compare_fields(bound, values)
    elif bound != filter_fingerprint(values):
        raise InvalidCursor(_FILTER_MESSAGE)
    return last_id
