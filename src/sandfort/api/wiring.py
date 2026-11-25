"""Builds the object graph (engine, driver, services, auth) and attaches it to ``app.state``."""

import os
from collections.abc import Awaitable, Callable, Mapping
from typing import Annotated, Any, cast

from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from sandfort.api.deps import (
    AUDIT_RECORDER_ATTR,
    DRIVER_ATTR,
    SANDBOX_SERVICE_ATTR,
    SETTINGS_ATTR,
    UOW_FACTORY_ATTR,
    get_driver,
)
from sandfort.api.envelope import Envelope
from sandfort.api.middleware.rate_limit import TokenBucketRateLimiter, install_rate_limit
from sandfort.api.middleware.request_id import CorrelatedAuditRecorder, note_refusal_recorded
from sandfort.api.safe_json import SafeJSONResponse
from sandfort.auth.authenticate import PRINCIPAL_STATE_ATTR, AuthContext, install_auth
from sandfort.auth.connect_tokens import InMemoryConnectTokenStore
from sandfort.auth.oidc import OidcVerifier
from sandfort.auth.scim import ScimAuthenticator, install_scim_auth
from sandfort.clock import Clock, SystemClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.models.sandboxes import SandboxRow
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.sandbox import Sandbox
from sandfort.drivers.base import SandboxDriver
from sandfort.drivers.docker.events import ContainerExitWatcher
from sandfort.drivers.registry import ALL_CAPABILITIES, resolve_driver
from sandfort.egress.proxy_limits import ENV_POLICY_URL
from sandfort.errors import InternalError, ValidationFailed
from sandfort.observability.metrics import with_delivery_metrics
from sandfort.observability.tracing import (
    TracedHandlerRegistry,
    build_tracer,
    instrument_driver,
    with_trace_propagation,
)
from sandfort.proxy.app import SandboxLookup
from sandfort.proxy.tokens import InMemoryPreviewTokenStore, PreviewTokenStore
from sandfort.services import snapshot_jobs  # noqa: F401  (registers the snapshot.create handler)
from sandfort.services.activity import ActivityTracker
from sandfort.services.api_key_admin import ApiKeyAdminService
from sandfort.services.audit import AuditRecorder
from sandfort.services.events import OutboxEventPublisher, with_sandbox_events
from sandfort.services.idempotency import (
    MAX_KEY_LENGTH,
    IdempotencyService,
    StoredResponse,
    canonical_body_hash,
    model_body_hash,
)
from sandfort.services.image_builds import ImageBuildService  # also registers image.build
from sandfort.services.label_scope import with_label_scope
from sandfort.services.node_registry import NodeRegistry
from sandfort.services.quota import QuotaService
from sandfort.services.resize import ResizeService
from sandfort.services.sandboxes import SandboxService
from sandfort.services.scim_tokens import ScimTokenService
from sandfort.services.snapshots import SnapshotService
from sandfort.services.sso import SsoService
from sandfort.services.transfer_slots import TransferSlots
from sandfort.services.usage import UsageService, with_usage_metering
from sandfort.services.user_admin import UserAdminService
from sandfort.services.volume_transfer import VolumeTransfer
from sandfort.services.volumes import VolumeService
from sandfort.services.warm_pool import WarmPool, activate
from sandfort.toolbox.pty import OrgSlots, PtyRegistry, PtyService, PtyUnitOfWork
from sandfort.toolbox.sessions import SessionRuntime
from sandfort.webhooks.secret_box import SecretBox
from sandfort.webhooks.ssrf import configure as configure_ssrf
from sandfort.wiring import wire_egress
from sandfort.workers.audit_retention import AuditRetention
from sandfort.workers.autostop import AutoStopScanner
from sandfort.workers.gc import GarbageCollector
from sandfort.workers.handlers import DEFAULT_REGISTRY
from sandfort.workers.metering import MeteringWorker
from sandfort.workers.reconciler import Reconciler
from sandfort.workers.runner import JobRunner
from sandfort.workers.webhook_dispatcher import WebhookDispatcher

ENGINE_ATTR = "engine"
SESSION_FACTORY_ATTR = "session_factory"
PTY_REGISTRY_ATTR = "pty_registry"
CONNECT_TOKENS_ATTR = "connect_tokens"
SESSION_RUNTIME_ATTR = "session_runtime"  # the name routes.toolbox.sessions reads it under
LOG_STREAM_SLOTS_ATTR = "log_stream_slots"  # org slots of live container-log follow streams
LOG_STREAM_RETRY_AFTER_S = 30
JOB_RUNNER_ATTR = "job_runner"
SNAPSHOT_SERVICE_ATTR = "snapshot_service"
IMAGE_BUILD_SERVICE_ATTR = "image_build_service"
VOLUME_SERVICE_ATTR = "volume_service"
VOLUME_TRANSFER_ATTR = "volume_transfer"
QUOTA_SERVICE_ATTR = "quota_service"
RESIZE_SERVICE_ATTR = "resize_service"
ACTIVITY_TRACKER_ATTR = "activity_tracker"
AUTOSTOP_SCANNER_ATTR = "autostop_scanner"
RECONCILER_ATTR = "reconciler"
GC_ATTR = "garbage_collector"
WEBHOOK_DISPATCHER_ATTR = "webhook_dispatcher"
USAGE_SERVICE_ATTR = "usage_service"
METERING_ATTR = "metering_worker"
AUDIT_RETENTION_ATTR = "audit_retention"
NODE_REGISTRY_ATTR = "node_registry"
API_KEY_ADMIN_SERVICE_ATTR = "api_key_admin_service"
USER_ADMIN_SERVICE_ATTR = "user_admin_service"
SSO_SERVICE_ATTR = "sso_service"
SCIM_TOKEN_SERVICE_ATTR = "scim_token_service"
TRACER_ATTR = "tracer"
IDEMPOTENCY_SERVICE_ATTR = "idempotency_service"
PREVIEW_TOKENS_ATTR = "preview_tokens"
IDEMPOTENCY_HEADER = "Idempotency-Key"
REPLAY_HEADER = "Idempotent-Replayed"


class WatchedReconciler(Reconciler):
    """A reconciler that, once ``watch`` is given a docker client, also follows container exits.

    The watcher starts and stops with the reconciler (so only when it is enabled) and every
    exit of a managed container kicks the reconciler now and after the recheck delays.
    """

    _watcher: ContainerExitWatcher | None = None

    def watch(self, client: Any) -> None:
        self._watcher = ContainerExitWatcher(client, self._on_container_exit)

    def start(self) -> None:
        super().start()
        if self._watcher is not None:
            self._watcher.start()

    async def stop(self) -> None:
        if self._watcher is not None:
            await self._watcher.stop()
        await super().stop()

    def _on_container_exit(self, event: Mapping[str, Any]) -> None:
        self.kick_with_rechecks()


def node_egress_ready(settings: Settings, environ: Mapping[str, str]) -> bool:
    """True when this node has a proxy address, a secret and a policy URL; its heartbeat says so.

    The policy URL is read from the same variable the proxy process uses (``environ``).
    """
    policy_url = environ.get(ENV_POLICY_URL, "").strip()
    return bool(settings.egress_proxy_address and settings.egress_secret and policy_url)


def docker_client_of(driver: object) -> Any | None:
    """The docker-py client behind the docker driver; ``None`` for any other driver."""
    if getattr(driver, "name", None) != "docker":
        return None
    return getattr(driver, "_client", None)


def get_idempotency_service(request: Request) -> IdempotencyService:
    value = getattr(request.app.state, IDEMPOTENCY_SERVICE_ATTR, None)
    if not isinstance(value, IdempotencyService):
        raise InternalError("idempotency service is misconfigured")
    return value


def get_node_registry(request: Request) -> NodeRegistry:
    value = getattr(request.app.state, NODE_REGISTRY_ATTR, None)
    if not isinstance(value, NodeRegistry):
        raise InternalError("node registry is misconfigured")
    return value


def get_resize_service(request: Request) -> ResizeService:
    value = getattr(request.app.state, RESIZE_SERVICE_ATTR, None)
    if not isinstance(value, ResizeService):
        raise InternalError("resize service is misconfigured")
    return value


KeepPolicy = Callable[[int, dict[str, Any]], StoredResponse]
ReplayHook = Callable[[StoredResponse], Awaitable[StoredResponse]]


class IdempotencyGuard:
    """Runs a create at most once per ``Idempotency-Key``; without the header it just runs.

    ``keep`` maps a fresh response (status, JSON body) to the entry that is stored (default:
    the response itself); ``replay`` maps a stored entry back to the response that is sent,
    and may record the replay or raise instead (default: the entry itself).
    """

    def __init__(
        self,
        service: IdempotencyService,
        key: str | None,
        request: Request,
        *,
        keep: KeepPolicy | None = None,
        replay: ReplayHook | None = None,
    ) -> None:
        self._service = service
        self._key = key
        self._request = request
        self._keep = keep
        self._replay = replay

    async def run[T](
        self,
        org_id: str,
        status: int,
        create: Callable[[], Awaitable[Envelope[T]]],
        *,
        request_model: BaseModel | None = None,
    ) -> Envelope[T] | SafeJSONResponse:
        """Run ``create`` once per key.

        With ``request_model`` (the validated body) requests are compared by it, defaults applied,
        not by the bytes the client sent; without it the canonical raw JSON is compared.
        """
        key = self._key
        if key is None:
            return await create()
        principal = getattr(self._request.state, PRINCIPAL_STATE_ATTR, None)
        key_id = None if principal is None else principal.key_id
        legacy = canonical_body_hash(await self._request.body())
        digest = (
            legacy if request_model is None else model_body_hash(self._operation(), request_model)
        )
        stored = await self._service.begin(org_id, key_id, key, digest, (legacy,))
        if stored is not None:
            if self._replay is not None:
                stored = await self._replay(stored)
            return SafeJSONResponse(
                status_code=stored.status,
                content=stored.body,
                headers={REPLAY_HEADER: "true"},
            )
        try:
            result = await create()
        except BaseException:
            self._service.abandon(org_id, key_id, key)
            raise
        body = result.model_dump(mode="json")
        kept = StoredResponse(status, body) if self._keep is None else self._keep(status, body)
        await self._service.complete(org_id, key_id, key, digest, kept.status, kept.body)
        return result

    def _operation(self) -> str:
        """The method and path template of the matched route (``POST /v1/volumes``)."""
        route = self._request.scope.get("route")
        path = getattr(route, "path", None) or self._request.url.path
        return f"{self._request.method} {path}"


def single_idempotency_key(request: Request, key: str | None) -> str | None:
    """``key`` unless the request sent the header twice with different values (422).

    A header given twice is read as its first value by the framework, which would silently
    ignore the second; two equal values are one key.
    """
    if key is not None and len(set(request.headers.getlist(IDEMPOTENCY_HEADER))) > 1:
        raise RequestValidationError(
            [
                {
                    "type": "value_error",
                    "loc": ("header", IDEMPOTENCY_HEADER),
                    "msg": f"{IDEMPOTENCY_HEADER} must be given once",
                }
            ]
        )
    return key


def idempotency_guard(
    request: Request,
    service: Annotated[IdempotencyService, Depends(get_idempotency_service)],
    idempotency_key: Annotated[
        str | None,
        Header(
            alias=IDEMPOTENCY_HEADER,
            min_length=1,
            max_length=MAX_KEY_LENGTH,
            description="Makes the create safe to retry: the same key and body replays the "
            "first response; the same key with another body answers 422. 1 to 255 "
            "characters; an empty or longer key answers 422 VALIDATION_ERROR.",
        ),
    ] = None,
) -> IdempotencyGuard:
    return IdempotencyGuard(service, single_idempotency_key(request, idempotency_key), request)


def get_preview_tokens(request: Request) -> PreviewTokenStore:
    value = getattr(request.app.state, PREVIEW_TOKENS_ATTR, None)
    if value is None:
        raise InternalError("preview token store is not configured")
    return cast(PreviewTokenStore, value)


def sandbox_lookup(session_factory: async_sessionmaker[AsyncSession]) -> SandboxLookup:
    """Find a sandbox by id alone, as the preview proxy must (a hostname carries no org).

    The org is read first so the row itself comes through the org-scoped repository.
    """

    async def lookup(sandbox_id: str) -> Sandbox | None:
        async with session_factory() as session:
            owner = select(SandboxRow.org_id).where(SandboxRow.id == sandbox_id)
            org_id = await session.scalar(owner)
        if org_id is None:
            return None
        async with UnitOfWork(session_factory) as uow:
            return await uow.sandboxes.get(org_id, sandbox_id)

    return lookup


def build_driver(settings: Settings, clock: Clock) -> SandboxDriver:
    """Resolve ``settings.driver`` through the driver registry (Settings validates the name).

    ``fake`` is the in-memory driver used by tests, ``docker`` the production driver; the
    services need the full surface, so only fully capable drivers are served.
    """
    entry = resolve_driver(settings.driver)
    missing = ALL_CAPABILITIES - entry.capabilities
    if missing:
        names = ", ".join(sorted(missing))
        raise ValidationFailed(f"driver {entry.name!r} cannot serve the API; it lacks: {names}")
    return cast(SandboxDriver, entry.build(settings, clock))


def install_services(app: FastAPI, settings: Settings) -> AsyncEngine:
    """Wire settings, engine, driver, service and auth onto ``app``; return the engine."""
    if not settings.api_key_pepper:
        raise ValidationFailed("SANDFORT_API_KEY_PEPPER must be set to serve the API")
    clock = SystemClock()
    tracer = build_tracer(settings)
    engine = create_engine(settings)
    session_factory = create_session_factory(engine)

    def raw_uow_factory() -> UnitOfWorkPort:
        return UnitOfWork(session_factory)

    def raw_pty_uow_factory() -> PtyUnitOfWork:
        return UnitOfWork(session_factory)

    # A label-scoped key sees only its own sandboxes through every route and service built on
    # these factories; workers run with no scope set, so for them the wrapper passes through.
    pty_uow_factory = with_label_scope(raw_pty_uow_factory)
    # A job enqueued through any unit of work carries the enqueueing trace to its job span.
    traced_uow_factory = (
        with_trace_propagation(raw_uow_factory) if settings.tracing_enabled else raw_uow_factory
    )
    uow_factory = with_label_scope(traced_uow_factory)
    # Services, workers and driver-taking routes get the instrumented driver (spans, metrics);
    # app state keeps the concrete driver, whose test hooks the suites reach through it.
    raw_driver = build_driver(settings, clock)
    driver = instrument_driver(raw_driver, tracer)
    audit = CorrelatedAuditRecorder(clock)  # stamps the request id on rows recorded in requests
    # One terminal registry (per-org cap) and token store per process, shared with sandbox stop.
    pty_registry = PtyRegistry(settings.max_ptys_per_org)
    connect_tokens = InMemoryConnectTokenStore(clock)
    pty_closer = PtyService(
        pty_uow_factory, driver, AuditRecorder(clock), clock, pty_registry, connect_tokens
    )
    quota_service = QuotaService(uow_factory, settings, clock, audit=audit)

    async def on_stopped(org_id: str, sandbox_id: str) -> None:
        """Stopped or destroyed by any path (jobs, autostop, reconciler): free its quota."""
        await quota_service.release(org_id, sandbox_id)
        await pty_closer.close_sandbox(org_id, sandbox_id)

    # The soft volume size limit and its sampling interval come from ``settings``; the sandbox
    # service samples through this service's own guard before its create transaction opens.
    volume_service = VolumeService(
        uow_factory,
        driver,
        clock,
        audit=audit,
        max_bytes=settings.volume_max_bytes,
        sample_interval_s=settings.metering_sample_interval_s,
    )
    # Off (size 0) means no pool object at all: every create path is exactly the pre-pool one.
    pool_enabled = settings.warm_pool_size > 0
    warm_pool = WarmPool(uow_factory, settings, clock, audit=audit) if pool_enabled else None
    sandbox_service = SandboxService(
        uow_factory,
        driver,
        settings,
        clock,
        on_stopped=pty_closer.close_sandbox,  # the service releases quota itself
        use_jobs=settings.sandbox_jobs_enabled,
        quota=quota_service,
        audit=audit,
        warm_pool=warm_pool,
        volume_guard=volume_service.guard,
        on_refusal_coalesced=note_refusal_recorded,
    )
    if warm_pool is not None:  # refill jobs build standbys through the service above
        warm_pool.attach(sandbox_service)
        activate(warm_pool)
    resize_service = ResizeService(uow_factory, quota_service, settings, clock, audit=audit)
    # The validated allowlist from ``settings``, so a directly built Settings is enforced too.
    registries = settings.allowed_registries
    snapshot_service = SnapshotService(
        uow_factory, driver, clock, audit=audit, allowed_registries=registries
    )
    image_build_service = ImageBuildService(
        uow_factory, driver, clock, audit=audit, allowed_registries=registries
    )
    # Lifecycle moves driven by jobs, autostop and the reconciler publish events and open or close
    # usage intervals like the service does (which wraps its own raw factory the same way).
    evented_uow_factory = with_usage_metering(
        with_sandbox_events(uow_factory, OutboxEventPublisher(clock)),
        clock,
        driver,
        tail_s=settings.metering_sample_interval_s,
    )
    job_runner = JobRunner(
        evented_uow_factory,
        driver,
        clock,
        registry=TracedHandlerRegistry(DEFAULT_REGISTRY, tracer),
        on_stopped=on_stopped,
        node_id=settings.node_id,
    )
    activity_tracker = ActivityTracker(clock)
    reminting = wire_egress(settings)  # the job handlers' lifecycle and the scanner share it
    autostop_scanner = AutoStopScanner(
        evented_uow_factory,
        driver,
        clock,
        activity_tracker,
        interval_s=settings.autostop_interval_s,
        on_stopped=on_stopped,
        node_id=settings.node_id,
        read_uow_factory=uow_factory,
        egress=reminting,
    )
    reconciler = WatchedReconciler(
        evented_uow_factory,
        driver,
        clock,
        interval_s=settings.reconcile_interval_s,
        grace_s=settings.orphan_grace_s,
        on_stopped=on_stopped,
        node_id=settings.node_id,
        read_uow_factory=uow_factory,
    )
    docker_client = docker_client_of(raw_driver)
    if docker_client is not None:  # only the docker driver has a daemon to watch
        reconciler.watch(docker_client)
    garbage_collector = GarbageCollector(
        uow_factory,
        session_factory,
        driver,
        clock,
        interval_s=settings.gc_interval_s,
        grace_s=settings.orphan_grace_s,
        node_id=settings.node_id,
    )
    configure_ssrf(
        allow_private_networks=settings.webhook_allow_private_networks,
        require_https=settings.webhook_require_https,
    )
    webhook_dispatcher = WebhookDispatcher(
        with_delivery_metrics(uow_factory),
        clock,
        interval_s=settings.webhook_dispatch_interval_s,
        timeout_s=settings.webhook_timeout_s,
        secret_box=SecretBox(settings.webhook_secret_key),
    )
    usage_service = UsageService(uow_factory, clock)
    metering_worker = MeteringWorker(
        uow_factory,
        driver,
        clock,
        rollup_interval_s=settings.metering_rollup_interval_s,
        sample_interval_s=settings.metering_sample_interval_s,
        lookback_hours=settings.metering_rollup_lookback_hours,
    )
    audit_retention = AuditRetention(
        uow_factory,
        clock,
        retention_days=settings.audit_retention_days,
        interval_s=settings.audit_retention_interval_s,
    )
    node_registry = NodeRegistry(
        uow_factory,
        clock,
        node_id=settings.node_id,
        max_sandboxes=settings.node_max_sandboxes,
        interval_s=settings.node_heartbeat_interval_s,
        internal_url=settings.node_internal_url,
        egress_ready=node_egress_ready(settings, os.environ),
    )
    auth = AuthContext(
        pepper=settings.api_key_pepper,
        uow_factory=uow_factory,
        clock=clock,
        session_secret=settings.session_secret,
        sso_org_id=settings.oidc_org_id,
    )
    install_auth(app, auth)
    # Built always (two small objects); the routes that use them mount only with scim_enabled.
    install_scim_auth(app, ScimAuthenticator(settings.api_key_pepper, uow_factory, clock))
    if settings.rate_limit_enabled:
        limiter = TokenBucketRateLimiter(
            clock, refill_per_s=settings.rate_limit_refill_per_s, burst=settings.rate_limit_burst
        )
        install_rate_limit(app, limiter)
    idempotency_service = IdempotencyService(uow_factory, clock)
    api_key_admin = ApiKeyAdminService(uow_factory, settings.api_key_pepper, clock)
    user_admin = UserAdminService(uow_factory, clock, recorder=audit)
    scim_token_service = ScimTokenService(
        uow_factory, settings.api_key_pepper, clock, recorder=audit
    )
    # Unconfigured OIDC settings leave the verifier refusing every exchange (401).
    sso_service = SsoService(
        uow_factory, OidcVerifier(settings, clock), clock, settings, recorder=audit
    )
    setattr(app.state, SETTINGS_ATTR, settings)
    setattr(app.state, UOW_FACTORY_ATTR, uow_factory)
    setattr(app.state, DRIVER_ATTR, raw_driver)

    def instrumented_driver() -> SandboxDriver:
        return driver

    app.dependency_overrides[get_driver] = instrumented_driver
    setattr(app.state, AUDIT_RECORDER_ATTR, audit)
    setattr(app.state, TRACER_ATTR, tracer)
    setattr(app.state, SANDBOX_SERVICE_ATTR, sandbox_service)
    setattr(app.state, SNAPSHOT_SERVICE_ATTR, snapshot_service)
    setattr(app.state, IMAGE_BUILD_SERVICE_ATTR, image_build_service)
    setattr(app.state, VOLUME_SERVICE_ATTR, volume_service)
    setattr(
        app.state,
        VOLUME_TRANSFER_ATTR,
        VolumeTransfer(
            volume_service,
            driver,
            TransferSlots(settings.max_volume_transfers_per_org, settings.max_volume_transfers),
            settings.fault_injection,
        ),
    )
    setattr(app.state, QUOTA_SERVICE_ATTR, quota_service)
    setattr(app.state, RESIZE_SERVICE_ATTR, resize_service)
    setattr(app.state, PTY_REGISTRY_ATTR, pty_registry)
    setattr(app.state, CONNECT_TOKENS_ATTR, connect_tokens)
    setattr(app.state, SESSION_RUNTIME_ATTR, SessionRuntime(settings.max_async_commands_per_org))
    log_stream_slots = OrgSlots(
        settings.max_log_streams_per_org,
        "live log streams",
        frees_when="a log stream closes",
        retry_after_s=LOG_STREAM_RETRY_AFTER_S,
    )
    setattr(app.state, LOG_STREAM_SLOTS_ATTR, log_stream_slots)
    # One preview-token store per process: the mint route writes it, a preview proxy served
    # by the same process (sandfort.main) reads it.
    setattr(app.state, PREVIEW_TOKENS_ATTR, InMemoryPreviewTokenStore(clock))
    setattr(app.state, JOB_RUNNER_ATTR, job_runner)
    setattr(app.state, ACTIVITY_TRACKER_ATTR, activity_tracker)
    setattr(app.state, AUTOSTOP_SCANNER_ATTR, autostop_scanner)
    setattr(app.state, RECONCILER_ATTR, reconciler)
    setattr(app.state, GC_ATTR, garbage_collector)
    setattr(app.state, WEBHOOK_DISPATCHER_ATTR, webhook_dispatcher)
    setattr(app.state, USAGE_SERVICE_ATTR, usage_service)
    setattr(app.state, METERING_ATTR, metering_worker)
    setattr(app.state, AUDIT_RETENTION_ATTR, audit_retention)
    setattr(app.state, NODE_REGISTRY_ATTR, node_registry)
    setattr(app.state, API_KEY_ADMIN_SERVICE_ATTR, api_key_admin)
    setattr(app.state, USER_ADMIN_SERVICE_ATTR, user_admin)
    setattr(app.state, SSO_SERVICE_ATTR, sso_service)
    setattr(app.state, SCIM_TOKEN_SERVICE_ATTR, scim_token_service)
    setattr(app.state, IDEMPOTENCY_SERVICE_ATTR, idempotency_service)
    setattr(app.state, ENGINE_ATTR, engine)
    setattr(app.state, SESSION_FACTORY_ATTR, session_factory)
    return engine
