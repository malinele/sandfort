"""The create command and the collaborator protocols of ``SandboxService`` (from ``sandboxes``)."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import NetworkPolicy, Sandbox
from sandfort.ids import SNAPSHOT
from sandfort.services.volumes import MountRequest

DEFAULT_IMAGE = "python:3.12-slim"
SNAPSHOT_ID_PREFIX = f"{SNAPSHOT}_"  # ``snapshot`` values with it are ids, not image refs


@dataclass(frozen=True, slots=True)
class CreateSandboxCommand:
    name: str | None = None
    snapshot: str | None = None
    resources: ResourceSpec = field(default_factory=ResourceSpec)
    inherit_resources: bool = False  # adopt the resources recorded on ``snapshot``, if any
    env: Mapping[str, str] = field(default_factory=dict)
    labels: Mapping[str, str] = field(default_factory=dict)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    auto_stop_minutes: int = 15
    auto_delete_minutes: int = -1
    public: bool = False
    volumes: Sequence[MountRequest] = ()
    standby: bool = False  # set only by the warm pool's refill: build a standby, not a sandbox
    spec_hash: str | None = None  # the pool key a standby is built for
    egress_allowlist: tuple[str, ...] | None = None  # None keeps today's egress (domain rules)
    isolation: str | None = None  # isolation tier (``domain.isolation``); None = the default


class StandbyClaimer(Protocol):
    """The warm pool as ``create`` sees it (implemented in ``services.warm_pool``)."""

    async def try_claim(
        self, org_id: str, actor_id: str, command: CreateSandboxCommand
    ) -> Sandbox | None: ...


class PendingSnapshotReader(Protocol):
    """What the SQL snapshot repository adds to the frozen port for sandbox delete."""

    async def has_pending_from_source(self, org_id: str, sandbox_id: str) -> bool: ...
