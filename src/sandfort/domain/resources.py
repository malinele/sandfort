"""FROZEN: resource specification and bounds shared by API, services and drivers."""

from pydantic import BaseModel, ConfigDict, Field

MIN_CPU_MILLICORES = 100
MIN_MEMORY_MIB = 64
MIN_DISK_GIB = 1

DEFAULT_CPU_MILLICORES = 1000
DEFAULT_MEMORY_MIB = 512
DEFAULT_DISK_GIB = 3


class ResourceSpec(BaseModel):
    """Compute allocation of one sandbox."""

    model_config = ConfigDict(frozen=True)

    cpu_millicores: int = Field(default=DEFAULT_CPU_MILLICORES, ge=MIN_CPU_MILLICORES)
    memory_mib: int = Field(default=DEFAULT_MEMORY_MIB, ge=MIN_MEMORY_MIB)
    disk_gib: int = Field(default=DEFAULT_DISK_GIB, ge=MIN_DISK_GIB)

    def fits_within(self, maximum: "ResourceSpec") -> bool:
        return (
            self.cpu_millicores <= maximum.cpu_millicores
            and self.memory_mib <= maximum.memory_mib
            and self.disk_gib <= maximum.disk_gib
        )
