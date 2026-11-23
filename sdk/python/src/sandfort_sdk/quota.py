"""Quota view (``client.quota``): the caller's own cap and reservation.

``get`` answers what ``GET /v1/org/quota`` answers for the key in use. An org-wide key gets the
org snapshot (``scope`` is ``None``). An API key limited to labelled sandboxes gets the org
limits, the reservation of its own sandboxes only (``reserved``) and, in ``scope``, its own
``max_sandboxes`` cap, how many live sandboxes of its scope count against it and how many it
may still create. Other teams' numbers are never part of a scoped answer.
"""

from dataclasses import dataclass
from typing import Any

from sandfort_sdk._transport import AsyncTransport, SyncTransport
from sandfort_sdk.exceptions import InvalidResponseError
from sandfort_sdk.models import _as_dict, _required

QUOTA_PATH = "/v1/org/quota"


def _number(value: Any, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise InvalidResponseError(f"expected a number for {what}, got {value!r}")
    return float(value)


def _integer(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidResponseError(f"expected an integer for {what}, got {value!r}")
    return value


def _optional_integer(value: Any, what: str) -> int | None:
    return None if value is None else _integer(value, what)


@dataclass(frozen=True, slots=True)
class QuotaLimits:
    """The org's limits; ``None`` is unlimited."""

    max_vcpus: float | None
    max_memory_mib: int | None
    max_disk_gib: int | None
    max_sandboxes: int | None

    @classmethod
    def from_payload(cls, data: Any) -> "QuotaLimits":
        raw = _as_dict(data, "quota limits")
        vcpus, memory, disk, sandboxes = _required(
            raw, "quota limits", "max_vcpus", "max_memory_mib", "max_disk_gib", "max_sandboxes"
        )
        return cls(
            max_vcpus=None if vcpus is None else _number(vcpus, "max_vcpus"),
            max_memory_mib=_optional_integer(memory, "max_memory_mib"),
            max_disk_gib=_optional_integer(disk, "max_disk_gib"),
            max_sandboxes=_optional_integer(sandboxes, "max_sandboxes"),
        )


@dataclass(frozen=True, slots=True)
class QuotaReserved:
    """Resources currently reserved: the org's for an org-wide key, the scope's for a scoped one."""

    vcpus: float
    memory_mib: int
    disk_gib: int
    sandboxes: int

    @classmethod
    def from_payload(cls, data: Any) -> "QuotaReserved":
        raw = _as_dict(data, "quota reserved")
        vcpus, memory, disk, sandboxes = _required(
            raw, "quota reserved", "vcpus", "memory_mib", "disk_gib", "sandboxes"
        )
        return cls(
            vcpus=_number(vcpus, "reserved vcpus"),
            memory_mib=_integer(memory, "reserved memory_mib"),
            disk_gib=_integer(disk, "reserved disk_gib"),
            sandboxes=_integer(sandboxes, "reserved sandboxes"),
        )


@dataclass(frozen=True, slots=True)
class QuotaScope:
    """A scoped key's own view: its label scope, cap, live count and what is left."""

    labels: dict[str, str]
    max_sandboxes: int | None
    sandboxes: int
    remaining: int | None

    @classmethod
    def from_payload(cls, data: Any) -> "QuotaScope":
        raw = _as_dict(data, "quota scope")
        labels, cap, count, remaining = _required(
            raw, "quota scope", "labels", "max_sandboxes", "sandboxes", "remaining"
        )
        mapping = _as_dict(labels, "quota scope labels")
        if not all(isinstance(item, str) for item in mapping.values()):
            raise InvalidResponseError("quota scope labels must map strings to strings")
        return cls(
            labels=dict(mapping),
            max_sandboxes=_optional_integer(cap, "scope max_sandboxes"),
            sandboxes=_integer(count, "scope sandboxes"),
            remaining=_optional_integer(remaining, "scope remaining"),
        )


@dataclass(frozen=True, slots=True)
class QuotaSnapshot:
    """The answer: org ``limits``, ``reserved`` totals and, for a scoped key, its ``scope``."""

    limits: QuotaLimits
    reserved: QuotaReserved
    scope: QuotaScope | None = None

    @classmethod
    def from_payload(cls, data: Any) -> "QuotaSnapshot":
        raw = _as_dict(data, "quota")
        limits, reserved = _required(raw, "quota", "limits", "reserved")
        scope = raw.get("scope")  # absent on a server that predates the scoped view
        return cls(
            limits=QuotaLimits.from_payload(limits),
            reserved=QuotaReserved.from_payload(reserved),
            scope=None if scope is None else QuotaScope.from_payload(scope),
        )


class Quota:
    """Synchronous quota client."""

    def __init__(self, transport: SyncTransport) -> None:
        self._transport = transport

    def get(self) -> QuotaSnapshot:
        """The quota view of the key in use (org snapshot, or the key's own scope)."""
        return QuotaSnapshot.from_payload(self._transport.request("GET", QUOTA_PATH).data)


class AsyncQuota:
    """Asynchronous quota client."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def get(self) -> QuotaSnapshot:
        """Same as :meth:`Quota.get`, as a coroutine."""
        reply = await self._transport.request("GET", QUOTA_PATH)
        return QuotaSnapshot.from_payload(reply.data)
