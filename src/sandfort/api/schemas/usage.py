"""Response schemas of ``GET /v1/org/usage``: the ungrouped totals and the grouped ``UsageGroup``.

Without ``group_by`` the reply is one ``UsageTotalResponse`` per metered dimension. With
``group_by`` it is a list of ``UsageGroup`` objects: ``group_key`` (``sandbox`` or the label
key), ``group_value`` (the sandbox id or the label value, ``null`` for the sandboxes without
the label) and the same per-dimension ``totals``. For the per-sandbox grouping ``name`` and
``labels`` hold the sandbox as stored at report time (reserved platform labels left out); both
are ``null`` for a label grouping and for a sandbox that is no longer stored.

The group cursor follows the list-route contract: it is opaque, bound to the resource and to
the filter (``from``, ``to``, ``group_by`` and the key's label scope), and a cursor presented
with another filter is a 422 ``VALIDATION_ERROR`` at ``query.cursor`` whose ``ctx`` names the
differing fields. Group values are free label text, not prefixed ids, so the cursor carries
the last group value itself rather than going through ``encode_cursor``.
"""

import base64
import binascii
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict

from sandfort.api.pagination import InvalidCursor, filter_fields
from sandfort.domain.usage import UsageDimension
from sandfort.services.usage import DimensionTotal, GroupTotals
from sandfort.services.volumes import user_labels

UNITS: Mapping[UsageDimension, str] = {
    UsageDimension.VCPU: "vcpu_seconds",
    UsageDimension.MEMORY_MIB: "mib_seconds",
    UsageDimension.DISK_GIB: "gib_seconds",
}
USAGE_GROUPS = "usage-groups"
_PAD = "="
_B64_QUANTUM = 4
_FILTER_MESSAGE = "cursor was issued for a different filter or order"


class UsageTotalResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    dimension: UsageDimension
    unit: str
    total: float


class UsageGroup(BaseModel):
    """One group of the grouped report; ``group_value`` is null for the unlabeled group."""

    model_config = ConfigDict(frozen=True)

    group_key: str
    group_value: str | None
    totals: list[UsageTotalResponse]
    name: str | None = None
    labels: dict[str, str] | None = None


@dataclass(frozen=True, slots=True)
class GroupPosition:
    """Where a page stops: the last group value returned (``None`` is the unlabeled group)."""

    value: str | None


def usage_response(totals: Sequence[DimensionTotal]) -> list[UsageTotalResponse]:
    return [
        UsageTotalResponse(dimension=item.dimension, unit=UNITS[item.dimension], total=item.total)
        for item in totals
    ]


def grouped_usage_response(groups: Sequence[GroupTotals]) -> list[UsageGroup]:
    return [
        UsageGroup(
            group_key=group.key,
            group_value=group.value,
            totals=usage_response(group.totals),
            name=group.name,
            labels=None if group.labels is None else user_labels(group.labels),
        )
        for group in groups
    ]


def _order(value: str | None) -> tuple[bool, str]:
    """The service's group order: by value, the ``None`` group last."""
    return (value is None, value or "")


def page_groups(
    groups: Sequence[GroupTotals], after: GroupPosition | None, limit: int
) -> tuple[Sequence[GroupTotals], GroupPosition | None]:
    """The groups after ``after`` (all when ``None``), at most ``limit``, and the next position.

    The next position is ``None`` when nothing follows the page.
    """
    remaining = [g for g in groups if after is None or _order(g.value) > _order(after.value)]
    page = remaining[:limit]
    more = len(remaining) > limit
    return page, GroupPosition(page[-1].value) if more and page else None


def encode_group_cursor(position: GroupPosition, values: Mapping[str, Any]) -> str:
    """An opaque cursor for ``position``, bound to the filter ``values``."""
    payload = {"r": USAGE_GROUPS, "v": position.value, "f": filter_fields(values)}
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip(_PAD)


def _payload(cursor: str) -> dict[str, Any]:
    padded = cursor + _PAD * (-len(cursor) % _B64_QUANTUM)
    try:
        loaded = json.loads(base64.b64decode(padded, altchars=b"-_", validate=True).decode())
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise InvalidCursor from None
    if not isinstance(loaded, dict) or loaded.get("r") != USAGE_GROUPS:
        raise InvalidCursor
    bound, value = loaded.get("f"), loaded.get("v")
    bound_ok = isinstance(bound, dict) and all(
        isinstance(k, str) and isinstance(v, str) for k, v in bound.items()
    )
    if not bound_ok or not (value is None or isinstance(value, str)):
        raise InvalidCursor
    return loaded


def decode_group_cursor(cursor: str, values: Mapping[str, Any]) -> GroupPosition:
    """The position in ``cursor``; ``InvalidCursor`` (422) if malformed or bound to other values."""
    payload = _payload(cursor)
    issued: dict[str, str] = payload["f"]
    presented = filter_fields(values)
    names = issued.keys() | presented.keys()
    differing = sorted(name for name in names if issued.get(name) != presented.get(name))
    if differing:
        parts = [f"{n}={issued.get(n)}, not {presented.get(n)}" for n in differing]
        reason = "cursor was issued with " + "; ".join(parts)
        raise InvalidCursor(_FILTER_MESSAGE, ctx={"fields": differing, "reason": reason})
    return GroupPosition(payload["v"])
