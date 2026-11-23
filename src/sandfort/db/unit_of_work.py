"""UnitOfWork: session + repositories + commit/rollback. Implements ``UnitOfWorkPort``.

D4 (intent first, then act): a transaction begins lazily on the first
statement and ends at ``commit()`` / ``rollback()`` / block exit. Services
commit the intent row, leave the block, and only then call a driver; they
open a fresh unit of work to record the outcome. Leaving the block without
``commit()`` discards the work.
"""

from types import TracebackType
from typing import Self

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sandfort.db.locking import QuotaLock, quota_lock_for
from sandfort.db.repositories.api_keys import SqlApiKeyRepository
from sandfort.db.repositories.audit import SqlAuditRepository
from sandfort.db.repositories.events import SqlEventRepository
from sandfort.db.repositories.exec import SqlExecCommandRepository, SqlExecSessionRepository
from sandfort.db.repositories.idempotency import SqlIdempotencyRepository
from sandfort.db.repositories.jobs import SqlJobRepository
from sandfort.db.repositories.nodes import SqlNodeRepository
from sandfort.db.repositories.orgs import SqlOrgRepository
from sandfort.db.repositories.ports import (
    ApiKeyRepository,
    AuditRepository,
    EventRepository,
    ExecCommandRepository,
    ExecSessionRepository,
    IdempotencyRepository,
    JobRepository,
    MembershipRepository,
    NodeRepository,
    OrgRepository,
    PtySessionRepository,
    QuotaRepository,
    SandboxRepository,
    ScimTokenRepository,
    SnapshotRepository,
    UsageRepository,
    UserRepository,
    VolumeRepository,
    WebhookRepository,
)
from sandfort.db.repositories.pty import SqlPtySessionRepository
from sandfort.db.repositories.quotas import SqlQuotaRepository
from sandfort.db.repositories.sandboxes import SqlSandboxRepository
from sandfort.db.repositories.scim_tokens import SqlScimTokenRepository
from sandfort.db.repositories.snapshots import SqlSnapshotRepository
from sandfort.db.repositories.usage import SqlUsageRepository
from sandfort.db.repositories.users import SqlMembershipRepository, SqlUserRepository
from sandfort.db.repositories.volumes import SqlVolumeRepository
from sandfort.db.repositories.webhooks import SqlWebhookRepository


class UnitOfWork:
    orgs: OrgRepository
    users: UserRepository
    memberships: MembershipRepository
    api_keys: ApiKeyRepository
    scim_tokens: ScimTokenRepository
    sandboxes: SandboxRepository
    idempotency: IdempotencyRepository
    audit: AuditRepository
    exec_sessions: ExecSessionRepository
    exec_commands: ExecCommandRepository
    pty_sessions: PtySessionRepository
    jobs: JobRepository
    snapshots: SnapshotRepository
    volumes: VolumeRepository
    quotas: QuotaRepository
    events: EventRepository
    webhooks: WebhookRepository
    usage: UsageRepository
    nodes: NodeRepository

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session = session_factory()
        self.orgs = SqlOrgRepository(self._session)
        self.users = SqlUserRepository(self._session)
        self.memberships = SqlMembershipRepository(self._session)
        self.api_keys = SqlApiKeyRepository(self._session)
        self.scim_tokens = SqlScimTokenRepository(self._session)
        self.sandboxes = SqlSandboxRepository(self._session)
        self.idempotency = SqlIdempotencyRepository(self._session)
        self.audit = SqlAuditRepository(self._session)
        self.exec_sessions = SqlExecSessionRepository(self._session)
        self.exec_commands = SqlExecCommandRepository(self._session)
        self.pty_sessions = SqlPtySessionRepository(self._session)
        self.jobs = SqlJobRepository(self._session)
        self.snapshots = SqlSnapshotRepository(self._session)
        self.volumes = SqlVolumeRepository(self._session)
        self.quotas = SqlQuotaRepository(self._session)
        self.events = SqlEventRepository(self._session)
        self.webhooks = SqlWebhookRepository(self._session)
        self.usage = SqlUsageRepository(self._session)
        self.nodes = SqlNodeRepository(self._session)
        self.quota_lock: QuotaLock = quota_lock_for(self._session)  # by dialect (WP 5.3)

    @property
    def in_transaction(self) -> bool:
        """True while a transaction (and its database lock) is open."""
        return self._session.in_transaction()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            await self._session.rollback()
        finally:
            await self._session.close()

    async def commit(self) -> None:
        await self._session.commit()

    async def rollback(self) -> None:
        await self._session.rollback()
