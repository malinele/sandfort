"""Shared instance attributes of ``SandboxService``, declared once for its mixins."""

from collections.abc import Callable

from sandfort.clock import Clock
from sandfort.config import Settings
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.sandbox import Sandbox
from sandfort.drivers.base import SandboxDriver
from sandfort.services.audit import AuditRecorder
from sandfort.services.quota import QuotaService
from sandfort.services.sandbox_mounting import MountingLifecycle
from sandfort.services.volume_limit import MountGuard


class SandboxServiceBase:
    """Attributes ``SandboxService.__init__`` sets, declared for the mixins (no values here)."""

    _uow_factory: Callable[[], UnitOfWorkPort]
    _driver: SandboxDriver
    _settings: Settings
    _clock: Clock
    _core: MountingLifecycle
    _use_jobs: bool
    _quota: QuotaService | None
    _volume_guard: MountGuard | None
    _audit: AuditRecorder

    async def _load(self, org_id: str, sandbox_id: str) -> Sandbox:
        return await self._core.load(org_id, sandbox_id)
