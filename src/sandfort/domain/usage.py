"""FROZEN: allocation-based metering entities (D9).

A usage interval records ``amount`` of one resource dimension allocated to a
sandbox from ``started_at`` until ``ended_at`` (``None`` while still open). A
rollup is the aggregated total of one dimension for one org and period.
"""

from datetime import datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class UsageDimension(StrEnum):
    VCPU = "vcpu"
    MEMORY_MIB = "memory_mib"
    DISK_GIB = "disk_gib"


class UsageInterval(BaseModel):
    model_config = ConfigDict(frozen=True)

    org_id: str
    sandbox_id: str
    dimension: UsageDimension
    amount: float = Field(ge=0)
    started_at: datetime
    ended_at: datetime | None = None

    @model_validator(mode="after")
    def _ends_after_start(self) -> Self:
        if self.ended_at is not None and self.ended_at < self.started_at:
            raise ValueError("ended_at must not precede started_at")
        return self


class UsageRollup(BaseModel):
    model_config = ConfigDict(frozen=True)

    org_id: str
    period_start: datetime
    dimension: UsageDimension
    total: float = Field(ge=0)
