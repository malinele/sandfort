"""Usage report (``client.usage``): metered resource totals of the org for a period.

``get`` returns one page: the org totals without ``group_by``, or a page of groups (one per
sandbox, or one per value of a label key) with the cursor of the next page. ``iter`` walks
every group of a grouped report. An API key limited to labelled sandboxes sees only the
sandboxes that carry all of its labels.
"""

from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sandfort_sdk._transport import AsyncTransport, Reply, SyncTransport
from sandfort_sdk.audit import MAX_LIMIT, MIN_LIMIT, _moment, _text
from sandfort_sdk.exceptions import InvalidResponseError
from sandfort_sdk.models import _as_dict, _as_list, _optional_str, _required

USAGE_PATH = "/v1/org/usage"
GROUP_BY_SANDBOX = "sandbox"
GROUP_BY_LABEL_PREFIX = "label:"
GROUP_BY_HELP = "'sandbox' or 'label:<key>'"


@dataclass(frozen=True, slots=True)
class UsageTotal:
    """One dimension of the report (``vcpu``, ``memory_mib``, ``disk_gib``) with its unit.

    ``dimension`` and ``unit`` stay plain strings so that a value a newer server adds still
    loads as sent.
    """

    dimension: str
    unit: str
    total: float

    @classmethod
    def from_payload(cls, data: Any) -> "UsageTotal":
        raw = _as_dict(data, "usage total")
        dimension, unit, amount = _required(raw, "usage total", "dimension", "unit", "total")
        if not isinstance(dimension, str) or not isinstance(unit, str):
            raise InvalidResponseError("usage total: 'dimension' and 'unit' must be strings")
        if isinstance(amount, bool) or not isinstance(amount, int | float):
            raise InvalidResponseError(f"expected a number for usage total, got {amount!r}")
        return cls(dimension, unit, float(amount))


@dataclass(frozen=True, slots=True)
class UsageGroup:
    """One group of a grouped report.

    For ``group_by="sandbox"``: ``group_value`` is the sandbox id, and ``name`` and ``labels``
    are the sandbox's at the time of the report. For ``label:<key>``: ``group_key`` is the key
    and ``group_value`` the label value, ``None`` for the sandboxes without that label.
    """

    group_key: str
    group_value: str | None
    totals: tuple[UsageTotal, ...]
    name: str | None = None
    labels: dict[str, str] | None = None

    @classmethod
    def from_payload(cls, data: Any) -> "UsageGroup":
        raw = _as_dict(data, "usage group")
        key, value, totals = _required(raw, "usage group", "group_key", "group_value", "totals")
        if not isinstance(key, str):
            raise InvalidResponseError(f"expected a string for usage group key, got {key!r}")
        labels = raw.get("labels")
        return cls(
            group_key=key,
            group_value=_optional_str(value, "usage group value"),
            totals=_totals(totals),
            name=_optional_str(raw.get("name"), "usage group name"),
            labels=None if labels is None else _labels(labels),
        )


@dataclass(frozen=True, slots=True)
class UsageReport:
    """One answer: ``totals`` without ``group_by``, ``groups`` and ``next_cursor`` with it.

    ``note`` is the server's warning about the answer (for example a ``label:<key>`` that no
    sandbox carried), or ``None``.
    """

    totals: tuple[UsageTotal, ...]
    groups: tuple[UsageGroup, ...]
    next_cursor: str | None
    note: str | None = None


def _labels(value: Any) -> dict[str, str]:
    raw = _as_dict(value, "usage group labels")
    if not all(isinstance(item, str) for item in raw.values()):
        raise InvalidResponseError("usage group labels must map strings to strings")
    return dict(raw)


def _totals(value: Any) -> tuple[UsageTotal, ...]:
    return tuple(UsageTotal.from_payload(item) for item in _as_list(value, "usage totals"))


def _group_by(value: str) -> str:
    if value == GROUP_BY_SANDBOX:
        return value
    key = value[len(GROUP_BY_LABEL_PREFIX) :]
    if value.startswith(GROUP_BY_LABEL_PREFIX) and key.strip():
        return value
    raise ValueError(f"group_by must be {GROUP_BY_HELP}; got {value!r}")


def usage_params(
    *,
    from_: datetime,
    to: datetime,
    group_by: str | None,
    cursor: str | None,
    limit: int | None,
) -> dict[str, Any]:
    """The query of a report call; raises ``ValueError`` before any request is made."""
    params: dict[str, Any] = {"from": _moment(from_, "from_"), "to": _moment(to, "to")}
    if group_by is None:
        if cursor is not None or limit is not None:
            raise ValueError("'cursor' and 'limit' need 'group_by'")
        return params
    params["group_by"] = _group_by(group_by)
    if cursor is not None:
        params["cursor"] = _text(cursor, "cursor")
    if limit is not None:
        if isinstance(limit, bool) or not MIN_LIMIT <= limit <= MAX_LIMIT:
            raise ValueError(f"limit must be between {MIN_LIMIT} and {MAX_LIMIT}; got {limit!r}")
        params["limit"] = limit
    return params


def usage_report(reply: Reply, *, grouped: bool) -> UsageReport:
    if not grouped:
        return UsageReport(_totals(reply.data), (), None)
    items = _as_list(reply.data, "usage groups")
    groups = tuple(UsageGroup.from_payload(item) for item in items)
    return UsageReport((), groups, reply.next_cursor, reply.note)


def _need_group_by(group_by: str | None) -> None:
    if group_by is None:
        raise ValueError(f"iter needs 'group_by': {GROUP_BY_HELP}")


def _check_progress(previous: str | None, page: UsageReport) -> None:
    """A page that hands back the cursor it was asked with would make ``iter`` loop forever."""
    if previous is not None and page.next_cursor == previous:
        raise InvalidResponseError(
            f"usage report repeated the cursor {previous!r}; paging cannot advance"
        )


class Usage:
    """Synchronous usage client."""

    def __init__(self, transport: SyncTransport) -> None:
        self._transport = transport

    def get(
        self,
        *,
        from_: datetime,
        to: datetime,
        group_by: str | None = None,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> UsageReport:
        """The report for ``from_``..``to`` (both timezone-aware).

        ``group_by`` is ``"sandbox"`` or ``"label:<key>"``; without it the answer is the org
        totals. ``cursor`` (``next_cursor`` of the previous page of the same ``from_``, ``to``
        and ``group_by``) and ``limit`` (1..100, server default 50) need ``group_by``.
        """
        params = usage_params(from_=from_, to=to, group_by=group_by, cursor=cursor, limit=limit)
        reply = self._transport.request("GET", USAGE_PATH, params=params)
        return usage_report(reply, grouped=group_by is not None)

    def iter(
        self,
        *,
        from_: datetime,
        to: datetime,
        group_by: str | None = None,
        limit: int | None = None,
    ) -> Iterator[UsageGroup]:
        """Every group of a grouped report, page by page, until there is no next cursor.

        Raises :class:`InvalidResponseError` when the server repeats the cursor it was sent.
        """
        _need_group_by(group_by)
        cursor: str | None = None
        while True:
            page = self.get(from_=from_, to=to, group_by=group_by, cursor=cursor, limit=limit)
            _check_progress(cursor, page)
            yield from page.groups
            if page.next_cursor is None:
                return
            cursor = page.next_cursor


class AsyncUsage:
    """Asynchronous usage client."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def get(
        self,
        *,
        from_: datetime,
        to: datetime,
        group_by: str | None = None,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> UsageReport:
        """Same as :meth:`Usage.get`, as a coroutine."""
        params = usage_params(from_=from_, to=to, group_by=group_by, cursor=cursor, limit=limit)
        reply = await self._transport.request("GET", USAGE_PATH, params=params)
        return usage_report(reply, grouped=group_by is not None)

    async def iter(
        self,
        *,
        from_: datetime,
        to: datetime,
        group_by: str | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[UsageGroup]:
        """Every group of a grouped report, page by page, until there is no next cursor."""
        _need_group_by(group_by)
        cursor: str | None = None
        while True:
            page = await self.get(
                from_=from_, to=to, group_by=group_by, cursor=cursor, limit=limit
            )
            _check_progress(cursor, page)
            for group in page.groups:
                yield group
            if page.next_cursor is None:
                return
            cursor = page.next_cursor
