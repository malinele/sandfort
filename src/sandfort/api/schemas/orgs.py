"""Request/response models for ``/v1/org/quota`` (WP 4.1)."""

from pydantic import BaseModel, Field

from sandfort.api.schemas.common import RequestModel
from sandfort.api.schemas.sandboxes import (
    MAX_CPU_MILLICORES,
    MAX_DISK_GIB,
    MAX_MEMORY_MIB,
    NoBool,
)
from sandfort.domain.quota import OrgQuota, Reservation
from sandfort.services.quota import QuotaUsage, RecountResult

# Schema-level sanity ceilings, the same as the per-sandbox ones (round 51): they keep a value
# out of the 32-bit database integer range so an overflow is a 422, not a 500.
MAX_QUOTA_MEMORY_MIB = MAX_MEMORY_MIB  # 16 TiB
MAX_QUOTA_DISK_GIB = MAX_DISK_GIB  # 1 PiB
MAX_QUOTA_SANDBOXES = 1_000_000
# The per-sandbox CPU ceiling in vCPUs (1000). Finite only: an infinite or NaN float (or a huge
# exponent literal that parses to infinity) is a 422, not a 500 (round 52).
MAX_QUOTA_VCPUS = MAX_CPU_MILLICORES // 1000


class QuotaLimitsBody(RequestModel):
    """Org limits; a missing or null dimension is unlimited."""

    # A JSON boolean is a 422 naming the field, never a stored 1 or 0 (round 53).
    max_vcpus: NoBool[float | None] = Field(
        default=None, ge=0, le=MAX_QUOTA_VCPUS, allow_inf_nan=False
    )
    max_memory_mib: NoBool[int | None] = Field(default=None, ge=0, le=MAX_QUOTA_MEMORY_MIB)
    max_disk_gib: NoBool[int | None] = Field(default=None, ge=0, le=MAX_QUOTA_DISK_GIB)
    max_sandboxes: NoBool[int | None] = Field(default=None, ge=0, le=MAX_QUOTA_SANDBOXES)

    def to_domain(self) -> OrgQuota:
        return OrgQuota(**self.model_dump())


class ReservedBody(BaseModel):
    vcpus: float
    memory_mib: int
    disk_gib: int
    sandboxes: int


class QuotaResponse(BaseModel):
    limits: QuotaLimitsBody
    reserved: ReservedBody


class RecountResponse(BaseModel):
    ledger: ReservedBody
    recomputed: ReservedBody
    consistent: bool


def _reserved(value: Reservation) -> ReservedBody:
    return ReservedBody(**value.model_dump())


def quota_response(usage: QuotaUsage) -> QuotaResponse:
    # The stored limits were validated when written; a row written before the request ceilings
    # existed may exceed them and must still read back, so the body is not re-validated.
    limits = QuotaLimitsBody.model_construct(**usage.limits.model_dump())
    return QuotaResponse(limits=limits, reserved=_reserved(usage.reserved))


def recount_response(result: RecountResult) -> RecountResponse:
    return RecountResponse(
        ledger=_reserved(result.ledger),
        recomputed=_reserved(result.recomputed),
        consistent=result.consistent,
    )
