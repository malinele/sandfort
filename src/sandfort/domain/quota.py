"""FROZEN: org quota limits, ledger entry states and the reservation value object.

A limit of ``None`` means unlimited. vCPUs are fractional (a sandbox may hold
0.5 vCPU); sums are rounded to millicore precision so repeated additions of
small reservations compare exactly against a limit.
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

VCPU_DECIMALS = 3


class LedgerEntryState(StrEnum):
    RESERVED = "reserved"
    RELEASED = "released"


class OrgQuota(BaseModel):
    """Per-org limits; every dimension is optional and ``None`` is unlimited."""

    model_config = ConfigDict(frozen=True)

    max_vcpus: float | None = Field(default=None, ge=0)
    max_memory_mib: int | None = Field(default=None, ge=0)
    max_disk_gib: int | None = Field(default=None, ge=0)
    max_sandboxes: int | None = Field(default=None, ge=0)


def _within(amount: float, limit: float | None) -> bool:
    return limit is None or amount <= limit


class Reservation(BaseModel):
    """Resources held (or requested) against an org quota; the default is zero."""

    model_config = ConfigDict(frozen=True)

    vcpus: float = Field(default=0.0, ge=0)
    memory_mib: int = Field(default=0, ge=0)
    disk_gib: int = Field(default=0, ge=0)
    sandboxes: int = Field(default=0, ge=0)

    def add(self, other: "Reservation") -> "Reservation":
        """Return the sum of both reservations; neither operand changes."""
        return Reservation(
            vcpus=round(self.vcpus + other.vcpus, VCPU_DECIMALS),
            memory_mib=self.memory_mib + other.memory_mib,
            disk_gib=self.disk_gib + other.disk_gib,
            sandboxes=self.sandboxes + other.sandboxes,
        )

    def fits_within(self, quota: OrgQuota) -> bool:
        """True when no dimension exceeds its limit (unlimited dimensions always fit)."""
        return (
            _within(self.vcpus, quota.max_vcpus)
            and _within(self.memory_mib, quota.max_memory_mib)
            and _within(self.disk_gib, quota.max_disk_gib)
            and _within(self.sandboxes, quota.max_sandboxes)
        )
