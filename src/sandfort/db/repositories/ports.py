"""FROZEN: repository and unit-of-work Protocols.

Every tenant-scoped method takes ``org_id``; a cross-org read returns ``None``.
``update`` raises ``sandfort.errors.Conflict`` when ``expected_version`` is stale.
Implementations never call a driver; services never hold a transaction across one.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from types import TracebackType
from typing import Any, Literal, Protocol, Self, runtime_checkable

from sandfort.domain.events import AuditEvent, AuditOutcome
from sandfort.domain.node import Node, NodeRoute
from sandfort.domain.org import ApiKey, Org
from sandfort.domain.quota import OrgQuota, Reservation
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.domain.scim import ScimToken
from sandfort.domain.snapshot import Snapshot, SnapshotState
from sandfort.domain.usage import UsageDimension, UsageInterval, UsageRollup
from sandfort.domain.user import OrgMembership, OrgRole, User
from sandfort.domain.volume import Volume, VolumeState

SortOrder = Literal["asc", "desc"]  # id order of a sandbox list page; ids sort by creation time
# The label keys a list filter may name: they become a JSON path, so no quote or bracket.
LABEL_FILTER_KEY = re.compile(r"[A-Za-z0-9_./-]{1,63}")


@dataclass(frozen=True, slots=True)
class IdempotencyRecord:
    org_id: str
    key: str
    request_hash: str
    response_status: int
    response_body: Mapping[str, Any]
    expires_at: datetime


class OrgRepository(Protocol):
    async def add(self, org: Org) -> None: ...

    async def get(self, org_id: str) -> Org | None: ...

    async def get_by_slug(self, slug: str) -> Org | None: ...


class UserRepository(Protocol):
    async def add(self, user: User) -> None: ...

    async def get(self, user_id: str) -> User | None: ...

    async def get_by_email(self, email: str) -> User | None: ...


class MembershipRepository(Protocol):
    async def add(self, membership: OrgMembership) -> None: ...

    async def get(self, user_id: str, org_id: str) -> OrgMembership | None: ...

    async def list_for_org(self, org_id: str) -> Sequence[OrgMembership]: ...

    async def update_role(
        self, user_id: str, org_id: str, role: OrgRole, at: datetime
    ) -> OrgMembership | None:
        """Set the role of an existing membership; ``None`` when there is no such membership."""
        ...

    async def get_by_external_id(self, org_id: str, external_id: str) -> OrgMembership | None:
        """The membership of ``org_id`` holding ``external_id``; ``None`` when none does."""
        ...

    async def set_external_id(
        self, user_id: str, org_id: str, external_id: str | None, at: datetime
    ) -> OrgMembership | None:
        """Set (or clear, with ``None``) the external id of an existing membership.

        ``None`` is returned when there is no such membership; ``Conflict`` is raised when
        another member of the org already holds the value.
        """
        ...

    async def delete(self, user_id: str, org_id: str) -> bool:
        """Remove the membership; ``False`` when there was none (the user itself stays)."""
        ...


class ApiKeyRepository(Protocol):
    async def add(self, key: ApiKey) -> None: ...

    async def get_by_prefix(self, prefix: str) -> ApiKey | None:
        """Authentication lookup; the only method not scoped by org."""
        ...

    async def list_for_org(self, org_id: str) -> Sequence[ApiKey]: ...

    async def revoke(self, org_id: str, key_id: str, at: datetime) -> bool: ...

    async def touch_last_used(self, key_id: str, at: datetime) -> None: ...


class ScimTokenRepository(Protocol):
    async def add(self, token: ScimToken) -> None: ...

    async def get_by_prefix(self, prefix: str) -> ScimToken | None:
        """Authentication lookup; the only method not scoped by org."""
        ...

    async def list_for_org(self, org_id: str) -> Sequence[ScimToken]: ...

    async def revoke(self, org_id: str, token_id: str, at: datetime) -> bool: ...

    async def touch_last_used(self, token_id: str, at: datetime) -> None: ...


class SandboxRepository(Protocol):
    async def add(self, sandbox: Sandbox) -> None: ...

    async def get(self, org_id: str, sandbox_id: str) -> Sandbox | None: ...

    async def get_by_name(self, org_id: str, name: str) -> Sandbox | None: ...

    async def list(
        self,
        org_id: str,
        *,
        state: SandboxState | None = None,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Sequence[Sandbox]: ...

    async def update(self, org_id: str, sandbox: Sandbox, *, expected_version: int) -> Sandbox: ...

    async def list_for_reconciler(self) -> Sequence[Sandbox]:
        """System path only: all non-destroyed sandboxes across orgs."""
        ...

    async def list_for_egress_policy(self, sandbox_ids: Sequence[str]) -> Sequence[Sandbox]:
        """System path for the internal egress policy route: sandboxes by id across all orgs."""
        ...


@dataclass(frozen=True, slots=True)
class StandbyClaim:
    """What a claim writes onto the standby it takes (everything a create may still choose)."""

    name: str | None  # ``None`` keeps the sandbox id as the name, like a normal create
    labels: Mapping[str, str]
    public: bool
    auto_stop_minutes: int
    auto_delete_minutes: int
    at: datetime


class OrderedSandboxListing(Protocol):
    """``SandboxRepository.list`` with a page order, kept apart from the frozen port.

    ``order="desc"`` lists newest first (ids sort by creation time) and the cursor, the last id
    of the previous page, continues with older rows; ``"asc"`` is the port's own behaviour.
    ``stop_cause`` keeps the sandboxes that show that cause (only ``stopping`` and ``stopped``
    rows show one; ``unknown`` is a stored null).
    """

    async def list(
        self,
        org_id: str,
        *,
        state: SandboxState | None = None,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 50,
        order: SortOrder = "asc",
        stop_cause: str | None = None,
    ) -> Sequence[Sandbox]: ...


@runtime_checkable
class LiveSandboxListing(Protocol):
    """Live-only listing of the SQL sandbox repository, kept apart from the frozen port.

    Same result as ``SandboxRepository.list`` without a state filter, minus the ``destroyed``
    tombstones, so a page of live rows is not pushed out by deleted ones.
    """

    async def list_live(
        self,
        org_id: str,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 50,
        order: SortOrder = "asc",
    ) -> Sequence[Sandbox]: ...


@runtime_checkable
class ScopedSandboxCounting(Protocol):
    """Count of an org's live sandboxes inside a label scope, kept apart from the frozen port.

    Live means neither ``destroyed`` nor a warm-pool standby; a sandbox is inside the scope when
    it carries every ``labels`` pair. It backs the per-key sandbox cap.
    """

    async def count_in_scope(self, org_id: str, labels: Mapping[str, str]) -> int: ...


@runtime_checkable
class StandbyRepository(Protocol):
    """Warm-pool operations of the SQL sandbox repository.

    Kept apart from ``SandboxRepository`` so the repository decorators (events, metering),
    which only forward the lifecycle surface, need not know about the pool. The warm pool
    reaches it through an undecorated unit of work: a claim changes no lifecycle state.
    """

    async def claim_standby(
        self, org_id: str, spec_hash: str, claim: StandbyClaim
    ) -> Sandbox | None:
        """Atomically turn one started standby into a normal sandbox; ``None`` if none is free.

        Raises ``Conflict`` when ``claim.name`` is already taken in the org.
        """
        ...

    async def count_standby(self, org_id: str, spec_hash: str) -> int:
        """Standbys of ``spec_hash`` that are building or ready (not error or destroyed)."""
        ...

    async def list_autostop_candidates(self, node_id: str | None = None) -> Sequence[Sandbox]:
        """System path: non-destroyed sandboxes the idle scanner may stop, standbys excluded.

        With ``node_id`` only that node's sandboxes are returned.
        """
        ...

    async def list_for_node(self, node_id: str) -> Sequence[Sandbox]:
        """System path: every non-destroyed sandbox owned by ``node_id``."""
        ...


class IdempotencyRepository(Protocol):
    async def get(self, org_id: str, key: str) -> IdempotencyRecord | None: ...

    async def put(self, record: IdempotencyRecord) -> None: ...

    async def purge_expired(self, now: datetime) -> int: ...


@dataclass(frozen=True, slots=True)
class AuditLink:
    """The newest audit row of an org: its id and its chain hash (``None`` if unchained)."""

    id: str
    entry_hash: str | None


@dataclass(frozen=True, slots=True)
class ChainedAuditEvent:
    """An audit row together with its stored chain columns."""

    event: AuditEvent
    prev_hash: str | None
    entry_hash: str | None


class AuditRepository(Protocol):
    async def add(
        self, event: AuditEvent, *, prev_hash: str | None = None, entry_hash: str | None = None
    ) -> None: ...

    async def latest_link(self, org_id: str) -> AuditLink | None: ...

    async def list_chained(
        self,
        org_id: str,
        *,
        cursor: str | None = None,
        limit: int = 500,
        request_id: str | None = None,
        outcome: AuditOutcome | None = None,
    ) -> Sequence[ChainedAuditEvent]: ...

    async def get_chained(self, org_id: str, event_id: str) -> ChainedAuditEvent | None: ...

    async def org_ids(self) -> Sequence[str]: ...

    async def prune_before(self, org_id: str, cutoff: datetime) -> int: ...

    async def list(
        self,
        org_id: str,
        *,
        actor_id: str | None = None,
        action: str | None = None,
        target_id: str | None = None,
        request_id: str | None = None,
        outcome: AuditOutcome | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        cursor: str | None = None,
        limit: int = 50,
        order: SortOrder = "asc",
    ) -> Sequence[AuditEvent]: ...


@dataclass(frozen=True, slots=True)
class ExecSessionRecord:
    id: str
    org_id: str
    sandbox_id: str
    cwd: str | None
    env: Mapping[str, str]
    state: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ExecCommandRecord:
    id: str
    org_id: str
    sandbox_id: str
    session_id: str | None
    argv: Sequence[str]
    state: str
    exit_code: int | None
    stdout_bytes: int
    stderr_bytes: int
    created_at: datetime
    finished_at: datetime | None


@dataclass(frozen=True, slots=True)
class PtySessionRecord:
    id: str
    org_id: str
    sandbox_id: str
    state: str
    rows: int
    cols: int
    created_at: datetime
    closed_at: datetime | None


class ExecSessionRepository(Protocol):
    async def add(self, session: ExecSessionRecord) -> None: ...

    async def get(self, org_id: str, session_id: str) -> ExecSessionRecord | None: ...

    async def list_for_sandbox(
        self, org_id: str, sandbox_id: str
    ) -> Sequence[ExecSessionRecord]: ...

    async def set_state(
        self, org_id: str, session_id: str, state: str, at: datetime
    ) -> ExecSessionRecord | None: ...

    async def set_cwd(
        self, org_id: str, session_id: str, cwd: str | None, at: datetime
    ) -> ExecSessionRecord | None:
        """Persist the working directory a command left behind."""
        ...

    async def delete(self, org_id: str, session_id: str) -> bool:
        """Remove the session row; ``False`` when there was none."""
        ...


class ExecCommandRepository(Protocol):
    async def add(self, command: ExecCommandRecord) -> None: ...

    async def get(self, org_id: str, command_id: str) -> ExecCommandRecord | None: ...

    async def list_for_session(
        self, org_id: str, session_id: str
    ) -> Sequence[ExecCommandRecord]: ...

    async def finish(
        self,
        org_id: str,
        command_id: str,
        *,
        state: str,
        exit_code: int | None,
        stdout_bytes: int,
        stderr_bytes: int,
        at: datetime,
    ) -> ExecCommandRecord | None: ...

    async def delete_for_session(self, org_id: str, session_id: str) -> int:
        """Remove every command row of the session; the number removed."""
        ...


class PtySessionRepository(Protocol):
    async def add(self, pty: PtySessionRecord) -> None: ...

    async def get(self, org_id: str, pty_id: str) -> PtySessionRecord | None: ...

    async def list_for_sandbox(
        self, org_id: str, sandbox_id: str
    ) -> Sequence[PtySessionRecord]: ...

    async def resize(
        self, org_id: str, pty_id: str, rows: int, cols: int
    ) -> PtySessionRecord | None: ...

    async def close(self, org_id: str, pty_id: str, at: datetime) -> PtySessionRecord | None: ...


@dataclass(frozen=True, slots=True)
class JobRecord:
    id: str
    org_id: str
    kind: str
    payload: Mapping[str, Any]
    state: str
    attempts: int
    run_after: datetime
    lease_expires_at: datetime | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime


class JobRepository(Protocol):
    async def enqueue(self, job: JobRecord) -> None: ...

    async def lease_next(
        self,
        kinds: Sequence[str],
        *,
        now: datetime,
        lease_expires_at: datetime,
        node_id: str | None = None,
    ) -> JobRecord | None:
        """System path (not org scoped): lease the oldest due queued job of ``kinds``.

        With ``node_id`` only jobs stamped for that node are considered.

        The job becomes ``leased`` with one more attempt; ``None`` when nothing is due.
        """
        ...

    async def complete(self, job_id: str, at: datetime) -> JobRecord | None: ...

    async def fail(
        self,
        job_id: str,
        *,
        error: str,
        now: datetime,
        backoff_s: float,
        max_attempts: int,
    ) -> JobRecord | None:
        """Requeue after ``backoff_s``, or mark ``dead`` once ``max_attempts`` is reached."""
        ...

    async def reap_expired(self, now: datetime) -> int:
        """Return leased jobs whose lease expired to ``queued``; yields the number reaped."""
        ...


class SnapshotRepository(Protocol):
    async def add(self, snapshot: Snapshot) -> None: ...

    async def get(self, org_id: str, snapshot_id: str) -> Snapshot | None: ...

    async def get_by_name(self, org_id: str, name: str) -> Snapshot | None: ...

    async def list(
        self,
        org_id: str,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Sequence[Snapshot]:
        """Snapshots of ``org_id`` by id; with ``labels``, only those carrying every pair.

        A label key outside ``LABEL_FILTER_KEY`` raises ``Unprocessable``.
        """
        ...

    async def set_state(
        self, org_id: str, snapshot_id: str, state: SnapshotState
    ) -> Snapshot | None: ...

    async def delete(self, org_id: str, snapshot_id: str) -> bool: ...


class VolumeRepository(Protocol):
    async def add(self, volume: Volume) -> None: ...

    async def get(self, org_id: str, volume_id: str) -> Volume | None: ...

    async def get_by_name(self, org_id: str, name: str) -> Volume | None: ...

    async def list(
        self,
        org_id: str,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Sequence[Volume]:
        """Volumes of ``org_id`` by id; with ``labels``, only those carrying every pair.

        A label key outside ``LABEL_FILTER_KEY`` raises ``Unprocessable``.
        """
        ...

    async def set_state(self, org_id: str, volume_id: str, state: VolumeState) -> Volume | None: ...

    async def set_sampled_size(
        self, org_id: str, volume_id: str, size_bytes: int
    ) -> Volume | None: ...

    async def set_restoring_since(
        self, org_id: str, volume_id: str, since: datetime | None
    ) -> Volume | None:
        """Set (a UTC time) or clear (``None``) the restore marker; ``None`` when no such volume."""
        ...

    async def clear_restoring_if(self, org_id: str, volume_id: str, observed: datetime) -> bool:
        """Clear the marker only where it still equals ``observed``; whether a row matched.

        ``False`` means the marker changed since it was read (a newer restore re-marked the
        volume) or the volume is gone; a newer marker is never erased.
        """
        ...

    async def list_restoring(self) -> Sequence[Volume]:
        """Every volume, of any org, whose restore marker is set (start-up recovery)."""
        ...

    async def delete(self, org_id: str, volume_id: str) -> bool: ...


class QuotaRepository(Protocol):
    async def get_or_default(self, org_id: str) -> OrgQuota: ...
    async def upsert_limits(self, org_id: str, quota: OrgQuota, at: datetime) -> OrgQuota: ...
    async def ledger_reserve(
        self, org_id: str, sandbox_id: str, reservation: Reservation, at: datetime
    ) -> None: ...
    async def ledger_release_by_sandbox(
        self, org_id: str, sandbox_id: str, at: datetime
    ) -> int: ...
    async def ledger_totals(self, org_id: str) -> Reservation: ...


@dataclass(frozen=True, slots=True)
class OutboxEventRecord:
    id: str
    org_id: str
    event_type: str
    payload: Mapping[str, Any]
    created_at: datetime
    dispatched_at: datetime | None = None
    attempts: int = 0


class EventRepository(Protocol):
    async def append(self, event: OutboxEventRecord) -> None: ...
    async def list_undispatched(self, *, limit: int = 100) -> Sequence[OutboxEventRecord]: ...
    async def mark_dispatched(self, event_id: str, at: datetime) -> bool: ...


@dataclass(frozen=True, slots=True)
class WebhookEndpointRecord:
    id: str
    org_id: str
    url: str
    secret: str
    enabled: bool
    failure_count: int
    event_types: Sequence[str]
    created_at: datetime


@dataclass(frozen=True, slots=True)
class WebhookDeliveryRecord:
    id: str
    endpoint_id: str
    event_id: str
    state: str
    attempts: int
    next_attempt_at: datetime | None
    last_status: int | None
    created_at: datetime
    updated_at: datetime
    # Delivery detail (round 60); defaults keep older constructors valid.
    event_type: str | None = None
    payload_sha256: str | None = None  # sha256 of the signed body, never the body
    last_error: str | None = None  # short sanitised transport reason, at most 200 characters
    attempt_history: Sequence[Mapping[str, Any]] = ()


class WebhookRepository(Protocol):
    async def add_endpoint(self, endpoint: WebhookEndpointRecord) -> None: ...
    async def get_endpoint(self, org_id: str, endpoint_id: str) -> WebhookEndpointRecord | None: ...
    async def list_endpoints(self, org_id: str) -> Sequence[WebhookEndpointRecord]: ...
    async def update_endpoint(
        self, org_id: str, endpoint: WebhookEndpointRecord
    ) -> WebhookEndpointRecord | None: ...
    async def delete_endpoint(self, org_id: str, endpoint_id: str) -> bool: ...
    async def record_delivery(self, delivery: WebhookDeliveryRecord) -> None: ...
    async def due_deliveries(
        self, now: datetime, *, limit: int = 100
    ) -> Sequence[WebhookDeliveryRecord]: ...
    async def update_delivery_state(
        self, delivery: WebhookDeliveryRecord
    ) -> WebhookDeliveryRecord | None: ...


class UsageRepository(Protocol):
    async def open_interval(self, interval: UsageInterval) -> None: ...
    async def close_open_intervals(
        self,
        org_id: str,
        sandbox_id: str,
        at: datetime,
        *,
        dimension: UsageDimension | None = None,
    ) -> int: ...
    async def list_intervals(
        self,
        start: datetime,
        end: datetime,
        *,
        org_id: str | None = None,
        sandbox_id: str | None = None,
    ) -> Sequence[UsageInterval]: ...
    async def upsert_rollup(self, rollup: UsageRollup) -> None: ...
    async def get_rollups(
        self, org_id: str, start: datetime, end: datetime
    ) -> Sequence[UsageRollup]: ...


class NodeRepository(Protocol):
    """Node registry. System paths, not org scoped."""

    async def upsert_heartbeat(self, node: Node) -> None:
        """Insert the node, or refresh its name, capacity, state, address and heartbeat."""
        ...

    async def list_nodes(self) -> Sequence[Node]: ...

    async def route_for_sandbox(self, sandbox_id: str) -> NodeRoute | None:
        """The owning node's address and liveness for a sandbox; ``None`` if unknown."""
        ...

    async def running_counts(self, org_id: str | None = None) -> Mapping[str, int]:
        """Started sandboxes per node id (nodes with none are absent).

        ``org_id`` limits the count to one org's rows; ``None`` counts host-wide.
        """
        ...

    async def assign_sandbox(self, sandbox_id: str, node_id: str) -> None: ...

    async def assign_job(self, job_id: str, node_id: str) -> None: ...


class UnitOfWorkPort(Protocol):
    """Session plus repositories; commit explicitly, rolled back on error."""

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
    jobs: JobRepository
    snapshots: SnapshotRepository
    volumes: VolumeRepository
    quotas: QuotaRepository
    events: EventRepository
    webhooks: WebhookRepository
    usage: UsageRepository
    nodes: NodeRepository

    async def __aenter__(self) -> Self: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...

    async def commit(self) -> None: ...

    async def rollback(self) -> None: ...
