"""``GET /v1/org/usage?from=&to=``: the org's metered usage for a period, ``usage:read`` scope.

The report is one total per dimension (at most three rows, so a single page: ``next_cursor``
is always null), combining stored hourly rollups with the live intervals. A timestamp without
an offset is read as UTC.

``group_by=sandbox`` or ``group_by=label:<key>`` splits the totals per sandbox or per label
value for chargeback (sandboxes without the label form the ``null`` group). Grouped totals
come from the raw intervals, so they cover the retained interval history. Any other
``group_by`` is a 422 ``VALIDATION_ERROR`` rather than being ignored. The grouped reply is a
list of ``UsageGroup`` objects, paged with ``cursor`` and ``limit`` like the list routes.

A key limited to labelled sandboxes (``sandbox_labels``) sees only those sandboxes, in the
totals, the per-sandbox groups and the per-label groups alike.
"""

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from pydantic import AfterValidator

from sandfort.api.envelope import Envelope, ok
from sandfort.api.pagination import QueryRefusal
from sandfort.api.query_guard import KnownQuery, single_valued
from sandfort.api.routes.audit import OUT_OF_RANGE_MESSAGE
from sandfort.api.schemas.common import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, Meta
from sandfort.api.schemas.text_checks import label_key_problem, plain_error
from sandfort.api.schemas.usage import (
    UsageGroup,
    UsageTotalResponse,
    decode_group_cursor,
    encode_group_cursor,
    grouped_usage_response,
    page_groups,
    usage_response,
)
from sandfort.api.wiring import USAGE_SERVICE_ATTR
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.domain.org import Scope
from sandfort.errors import InternalError, Unprocessable
from sandfort.services.usage import (
    GROUP_BY_MESSAGE,
    LABEL_GROUPING_PREFIX,
    GroupTotals,
    UsageService,
    parse_group_by,
)

router = APIRouter(prefix="/v1/org/usage", tags=["org"])

UngroupedReply = Envelope[list[UsageTotalResponse]]
GroupedReply = Envelope[list[UsageGroup]]


def get_usage_service(request: Request) -> UsageService:
    value = getattr(request.app.state, USAGE_SERVICE_ATTR, None)
    if not isinstance(value, UsageService):
        raise InternalError("usage service is misconfigured")
    return value


Reader = Annotated[Principal, Depends(require_scopes(Scope.USAGE_READ))]
Service = Annotated[UsageService, Depends(get_usage_service)]
UsageOnce = Annotated[None, Depends(single_valued("from", "to", "group_by", "cursor", "limit"))]


MAX_GROUP_KEY_LENGTH = 63  # the label key bound of sandbox labels
ONE_GROUPING_MESSAGE = (
    "group_by takes one grouping per call: 'sandbox' or 'label:<key>', not a list"
)


def _utc_bound(value: datetime) -> datetime:
    """``from``/``to`` as aware UTC; an out-of-range conversion is a plain 422 (no prefix)."""
    try:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    except OverflowError as exc:
        raise plain_error(OUT_OF_RANGE_MESSAGE) from exc


RequiredFrom = Annotated[datetime, Query(alias="from"), AfterValidator(_utc_bound)]
RequiredTo = Annotated[datetime, Query(alias="to"), AfterValidator(_utc_bound)]


def _label_group_problem(key: str) -> str | None:
    """Why ``key`` is no label key to group by; the key itself is never echoed."""
    if len(key) > MAX_GROUP_KEY_LENGTH:
        return f"the label key must be at most {MAX_GROUP_KEY_LENGTH} characters"
    problem = label_key_problem(key)
    return None if problem is None else f"the label key {problem}"


def _checked_group_by(value: str | None) -> str | None:
    """Reject an unknown or malformed ``group_by`` as a request validation error (422)."""
    if value is None:
        return value
    if "," in value:
        raise plain_error(ONE_GROUPING_MESSAGE)
    key = value[len(LABEL_GROUPING_PREFIX) :]
    if value.startswith(LABEL_GROUPING_PREFIX) and key and (problem := _label_group_problem(key)):
        raise plain_error(f"group_by: {problem}")
    try:
        parse_group_by(value)
    except ValueError as exc:
        raise plain_error(GROUP_BY_MESSAGE) from exc
    return value


GroupBy = Annotated[
    str | None,
    Query(
        description="'sandbox' or 'label:<key>'; absent returns the org totals",
    ),
    AfterValidator(_checked_group_by),
]
GroupCursor = Annotated[
    str | None,
    Query(description="`next_cursor` of the previous grouped page; needs `group_by`"),
]
GroupLimit = Annotated[
    int | None,
    Query(
        ge=1,
        le=MAX_PAGE_SIZE,
        description=f"Groups per page (default {DEFAULT_PAGE_SIZE}); needs `group_by`",
    ),
]


def unseen_label_note(group_by: str, groups: Sequence[GroupTotals]) -> str | None:
    """A warning when ``group_by=label:<key>`` put all the usage into the unlabeled group.

    That is what a mistyped key looks like (round 65): one ``null`` group holding the whole
    total. ``None`` for a ``sandbox`` grouping, for no usage at all, and when any group has a
    value.
    """
    if not group_by.startswith(LABEL_GROUPING_PREFIX) or not groups:
        return None
    if any(group.value is not None for group in groups):
        return None
    key = group_by[len(LABEL_GROUPING_PREFIX) :]
    return f"label key '{key}' was not found on any sandbox in this window; check the key"


@router.get("", response_model=UngroupedReply | GroupedReply)
async def get_usage(
    principal: Reader,
    service: Service,
    _known: KnownQuery,
    _once: UsageOnce,
    since: RequiredFrom,
    until: RequiredTo,
    group_by: GroupBy = None,
    cursor: GroupCursor = None,
    limit: GroupLimit = None,
) -> UngroupedReply | GroupedReply:
    """Report the org's metered usage for ``from``..``to``, one total per dimension.

    Without `group_by` the reply is one total per dimension. `group_by` is `sandbox` or
    `label:<key>` and returns a list of `UsageGroup` objects (`group_key`, `group_value`,
    `totals`; for `sandbox` also the sandbox `name` and its `labels` at the time of the
    report), paged with `cursor` and `limit`; a cursor is bound to `from`, `to` and `group_by`
    and a cursor from another filter is a 422. Any other `group_by` is a 422.

    Label scope: an API key limited to labelled sandboxes sees only the sandboxes carrying
    all of its labels, destroyed ones that carried them included, in the totals, the
    per-sandbox groups and the per-label groups. An unscoped key sees the whole org. Volumes
    are not a usage dimension and are not reported. A scoped report is computed from the raw
    intervals, like the grouped one.
    """
    # ``from``/``to`` arrive as aware UTC (``RequiredFrom``/``RequiredTo`` from the audit routes).
    start, end = since, until
    if end <= start:
        # The same refusal as the audit export route: 422 UNPROCESSABLE, audited (round 53).
        raise Unprocessable("`to` must be after `from`")
    scope = principal.sandbox_labels
    if group_by is None:
        if cursor is not None or limit is not None:
            name = "cursor" if cursor is not None else "limit"
            raise QueryRefusal(name, f"`{name}` needs `group_by`")
        totals = await service.report(principal.org_id, start, end, scope=scope)
        return ok(usage_response(totals), meta=Meta(next_cursor=None))
    bound = {"from": start.isoformat(), "to": end.isoformat(), "group_by": group_by, "scope": scope}
    after = None if cursor is None else decode_group_cursor(cursor, bound)
    groups = await service.report_grouped(principal.org_id, start, end, group_by, scope=scope)
    page, following = page_groups(groups, after, DEFAULT_PAGE_SIZE if limit is None else limit)
    next_cursor = None if following is None else encode_group_cursor(following, bound)
    note = unseen_label_note(group_by, groups)
    return ok(grouped_usage_response(page), meta=Meta(next_cursor=next_cursor, note=note))
