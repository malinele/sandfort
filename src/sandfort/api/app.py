"""Router assembly, middleware and exception-handler registration.

Middleware order, outermost first: request id, then telemetry (span, HTTP metrics, access
log), the sign-on exchange limiter, the request body limit, then the routes; rate limiting
runs inside authentication. ``/metrics`` sits on this root application, open unless
``SANDFORT_METRICS_TOKEN`` is set (then a bearer token), and serves the Prometheus text exposition.
Before any worker starts, the lifespan runs the driver's isolation self-check: in prod a
missing capability refuses the start, in dev it is logged. On shutdown it stops the workers,
then closes the driver (when it has an ``aclose``), then disposes the engine.
"""

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Protocol, runtime_checkable

from fastapi import FastAPI, Request, Response
from fastapi.routing import APIRoute
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from sandfort import __version__
from sandfort.api.deps import DRIVER_ATTR
from sandfort.api.docs_pages import install_docs_pages
from sandfort.api.errors import register_exception_handlers
from sandfort.api.metrics_auth import require_metrics_token
from sandfort.api.middleware.body_limit import BodyLimitMiddleware
from sandfort.api.middleware.rate_limit import install_exchange_rate_limit
from sandfort.api.middleware.request_id import RequestIdMiddleware
from sandfort.api.routes import (
    api_keys,
    audit,
    console,
    egress_policy,
    health,
    image_builds,
    jobs,
    nodes,
    orgs,
    sandbox_logs,
    sandbox_preview,
    sandbox_resize,
    sandboxes,
    scim,
    scim_tokens,
    snapshots,
    sso,
    toolbox,
    usage,
    users,
    volumes,
    webhooks,
)
from sandfort.api.safe_json import SafeJSONResponse
from sandfort.api.security_headers import SecurityHeadersMiddleware
from sandfort.api.text_guard import TextGuardMiddleware
from sandfort.api.wiring import (
    AUDIT_RETENTION_ATTR,
    AUTOSTOP_SCANNER_ATTR,
    ENGINE_ATTR,
    GC_ATTR,
    JOB_RUNNER_ATTR,
    METERING_ATTR,
    NODE_REGISTRY_ATTR,
    RECONCILER_ATTR,
    SESSION_FACTORY_ATTR,
    TRACER_ATTR,
    VOLUME_TRANSFER_ATTR,
    WEBHOOK_DISPATCHER_ATTR,
    install_services,
)
from sandfort.config import PROD_ENVIRONMENT, Settings
from sandfort.db.models.jobs import JobRow, JobState
from sandfort.drivers.docker.capabilities import egress_findings
from sandfort.drivers.docker.egress_probe import (
    PROBE_FINDING_PREFIX,
    CanaryRunner,
    canary_runner_for,
    probe_findings,
)
from sandfort.observability.metrics import render_metrics, set_queue_depth
from sandfort.observability.tracing import TelemetryMiddleware
from sandfort.preflight import host_capacity_findings, prod_findings
from sandfort.routing.guard import RouteGuardMiddleware
from sandfort.routing.middleware import RouteForwardMiddleware
from sandfort.services.volume_transfer import VolumeTransfer

logger = logging.getLogger(__name__)

METRICS_PATH = "/metrics"
API_ROLE = "api"
DISK_QUOTA_GAP_PREFIX = "disk quota support"  # start of the docker capabilities disk quota gap
# operationIds are the route function names; where two functions share a name, the one listed
# here is prefixed with its module's last segment (``sessions_execute_command``).
PREFIXED_OPERATIONS = frozenset({("sandfort.api.routes.toolbox.sessions", "execute_command")})
_QUEUED_JOBS = select(func.count()).select_from(JobRow).where(JobRow.state == JobState.QUEUED.value)


EGRESS_PROBE_DEADLINE_S = 90.0  # the whole probe, pull included; past it the start is refused
EGRESS_PROBE_TIMEOUT = "{prefix} could not run: it did not finish within {deadline:g} s"
EGRESS_OVERRIDE_WARNING = (
    "egress probe findings tolerated: SANDFORT_EGRESS_ACKNOWLEDGED=true is an explicit"
    " override of the refusal, so startup continues; fix the host firewall and unset it: %s"
)
EGRESS_OVERRIDE_HINT = (
    " (SANDFORT_EGRESS_ACKNOWLEDGED=true turns egress probe findings into warnings)"
)
NON_DOCKER_DRIVER_MESSAGE = (
    "driver {driver} cannot run in prod: it has no isolation self-check, so the host"
    " isolation and egress gates cannot be verified; prod requires the docker driver"
)


class IsolationUnavailableError(RuntimeError):
    """A prod start was refused: the host lacks an isolation capability sandboxes rely on."""


def check_host_capacity(settings: Settings) -> None:
    """Refuse a prod start with no host capacity (zero means unguarded) unless allowed."""
    for finding in host_capacity_findings(settings):
        raise IsolationUnavailableError(finding)


def check_prod_configuration(settings: Settings) -> None:
    """Refuse a prod start whose configuration is unready, listing every finding at once.

    The serve lifespan runs this, so an application built directly (an embedder, the worker
    app) is covered like the ``sandfort.main`` entry point, which checks earlier to print
    without a traceback. Covers the host capacity and the webhook secret key.
    """
    findings = prod_findings(settings)
    if findings:
        raise _refuse(findings, "prod configuration is not ready")


@runtime_checkable
class _IsolationSelfCheck(Protocol):
    async def isolation_gaps(self) -> list[str]: ...


async def egress_gaps(
    driver: object, settings: Settings, canary: CanaryRunner | None = None
) -> list[str]:
    """The egress findings of this start: the probe's, or the acknowledgement in prod.

    With the probe on (``egress_probe_enabled``) a canary container on each managed network
    tries to get out and every reachable target is a finding; the probe replaces the
    acknowledgement. In prod ``egress_acknowledged`` is the explicit override that downgrades
    those findings to a warning. Without a probe (off, or a driver with no docker client) prod
    falls back to requiring the acknowledgement. A probe still running after
    ``EGRESS_PROBE_DEADLINE_S`` is cancelled and is one "could not run" finding.
    """
    prod = settings.environment == PROD_ENVIRONMENT
    runner = (canary or canary_runner_for(driver)) if settings.egress_probe_enabled() else None
    if runner is None:
        findings = egress_findings(settings.egress_acknowledged) if prod else []
    else:
        deadline = EGRESS_PROBE_DEADLINE_S
        try:
            findings = await asyncio.wait_for(
                probe_findings(runner, settings.egress_probe_image), deadline
            )
        except TimeoutError:
            findings = [EGRESS_PROBE_TIMEOUT.format(prefix=PROBE_FINDING_PREFIX, deadline=deadline)]
        if findings and prod and settings.egress_acknowledged:
            logger.warning(EGRESS_OVERRIDE_WARNING, "; ".join(findings))
            return []
    # The acknowledgement only has an effect in prod, so only prod is told about it.
    return [finding + EGRESS_OVERRIDE_HINT for finding in findings] if prod else findings


def _refuse(
    gaps: list[str], reason: str = "host lacks required isolation capabilities"
) -> IsolationUnavailableError:
    """Log one summary line and build the refusal that lists every finding.

    The findings are not logged separately: they are in the exception message, which is what a
    caller (the entry point, a test, an embedder) sees, so each finding appears once.
    """
    logger.error("%s: %d finding(s), listed in the startup error", reason, len(gaps))
    return IsolationUnavailableError(f"{reason}: {'; '.join(gaps)}")


async def check_isolation(
    driver: object, settings: Settings, *, canary: CanaryRunner | None = None
) -> None:
    """Refuse a prod start on a host missing an isolation capability; dev only logs it.

    Outside prod, ``enforce_disk_quota`` also refuses the start when the disk quota gap is
    reported: the deployment asked for per-sandbox disk size and every create would fail.
    A driver without a self-check (the in-memory fake) has nothing to verify, so prod refuses
    it: only the docker driver reports the gaps and takes the egress gate (``egress_gaps``),
    which runs after the capability check. ``canary`` replaces the docker canary runner.
    """
    if not isinstance(driver, _IsolationSelfCheck):
        if settings.environment == PROD_ENVIRONMENT:
            raise IsolationUnavailableError(
                NON_DOCKER_DRIVER_MESSAGE.format(driver=type(driver).__name__)
            )
        return
    gaps = await driver.isolation_gaps()
    gaps = [*gaps, *await egress_gaps(driver, settings, canary)]
    if not gaps:
        return
    if settings.environment == PROD_ENVIRONMENT:
        raise _refuse(gaps)
    if settings.enforce_disk_quota and any(gap.startswith(DISK_QUOTA_GAP_PREFIX) for gap in gaps):
        raise _refuse(gaps)
    logger.warning(
        "host lacks required isolation capabilities: %s (tolerated outside prod)", "; ".join(gaps)
    )


@runtime_checkable
class _Closable(Protocol):
    async def aclose(self) -> None: ...


async def _close_driver(driver: object) -> None:
    """Close a driver that offers ``aclose``; the fake driver and plugin drivers may not.

    A failed close is logged, never raised: the engine must still be disposed after it.
    """
    if not isinstance(driver, _Closable):
        return
    try:
        await driver.aclose()
    except Exception:
        logger.exception("driver close failed")


class _Worker(Protocol):
    def start(self) -> None: ...

    async def stop(self) -> None: ...


def _start_workers(app: FastAPI, settings: Settings) -> list[_Worker]:
    """Start each enabled background worker; return the started ones in start order."""
    state = app.state
    candidates: tuple[tuple[bool, str], ...] = (
        (settings.job_execution_enabled, JOB_RUNNER_ATTR),
        (settings.autostop_enabled, AUTOSTOP_SCANNER_ATTR),
        (settings.reconcile_enabled, RECONCILER_ATTR),
        (settings.gc_enabled, GC_ATTR),
        (settings.webhook_dispatcher_enabled, WEBHOOK_DISPATCHER_ATTR),
        (settings.metering_enabled, METERING_ATTR),
        (settings.audit_retention_days > 0, AUDIT_RETENTION_ATTR),
        (settings.node_heartbeat_enabled, NODE_REGISTRY_ATTR),
    )
    started: list[_Worker] = []
    for enabled, attr in candidates:
        if enabled:
            worker: _Worker = getattr(state, attr)
            worker.start()
            started.append(worker)
    return started


async def _stop_workers(started: list[_Worker]) -> None:
    """Stop only what was started, last started first."""
    for worker in reversed(started):
        await worker.stop()


async def _recover_restores(app: FastAPI) -> None:
    """Empty the volumes a crashed restore left marked; a failure is logged, not fatal."""
    transfer: VolumeTransfer = getattr(app.state, VOLUME_TRANSFER_ATTR)
    try:
        recovered = await transfer.recover_interrupted()
    except Exception:
        logger.exception("restore recovery could not run; marked volumes stay marked")
        return
    if recovered:
        logger.warning("restore recovery emptied %d volume(s) of interrupted restores", recovered)


@asynccontextmanager
async def _serve_lifespan(
    app: FastAPI, *, with_workers: bool, recover_restores: bool = False
) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    engine: AsyncEngine = getattr(app.state, ENGINE_ATTR)
    try:
        check_prod_configuration(settings)  # every configuration finding, capacity included
        await check_isolation(getattr(app.state, DRIVER_ATTR), settings)
    except BaseException:
        await engine.dispose()  # no worker has started yet: the engine is all there is
        raise
    if settings.fault_injection:
        logger.warning(
            "fault injection active: %s (SANDFORT_FAULT_INJECTION is a test hook, never for "
            "production)",
            ", ".join(settings.fault_injection),
        )
    if recover_restores:  # before the first request: a volume a crashed restore left partial
        await _recover_restores(app)
    started = _start_workers(app, settings) if with_workers else []
    try:
        yield
    finally:
        await _stop_workers(started)  # before the driver closes: a runner may be mid-call
        await _close_driver(getattr(app.state, DRIVER_ATTR))  # before the engine goes away
        await engine.dispose()


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Combined and api roles: the api role serves requests and starts no worker."""
    settings: Settings = app.state.settings
    async with _serve_lifespan(app, with_workers=settings.role != API_ROLE, recover_restores=True):
        yield


@asynccontextmanager
async def _worker_lifespan(app: FastAPI) -> AsyncIterator[None]:
    async with _serve_lifespan(app, with_workers=True):
        yield


async def _refresh_queue_depth(app: FastAPI) -> None:
    """Sample the queued-job count into the gauge; a failed read keeps the last sample."""
    session_factory: async_sessionmaker[AsyncSession] = getattr(app.state, SESSION_FACTORY_ATTR)
    try:
        async with session_factory() as session:
            depth = await session.scalar(_QUEUED_JOBS)
    except SQLAlchemyError as exc:
        logger.warning("job queue depth unavailable: %s", type(exc).__name__)
        return
    set_queue_depth(depth or 0)


async def metrics_endpoint(request: Request) -> Response:
    """Prometheus text exposition of the metric catalog (bearer token only when one is set)."""
    settings: Settings = request.app.state.settings
    require_metrics_token(settings, request.headers.get("authorization"))
    await _refresh_queue_depth(request.app)
    body, content_type = render_metrics()
    return Response(content=body, media_type=content_type)


def create_worker_app(settings: Settings | None = None) -> FastAPI:
    """The worker-role application: health probes only, background workers in the lifespan."""
    resolved = settings or Settings.from_env()
    app = FastAPI(title="Sandfort worker", version=__version__, lifespan=_worker_lifespan)
    install_services(app, resolved)
    app.include_router(health.router)
    return app


def _install_routing(app: FastAPI, settings: Settings) -> None:
    """Cross-node toolbox routing: the edge forwarder, then the owner guard around it.

    The guard is added last so it runs first and marks verified hops before the forwarder looks.
    """
    session_factory: async_sessionmaker[AsyncSession] = getattr(app.state, SESSION_FACTORY_ATTR)
    app.add_middleware(RouteForwardMiddleware, settings=settings, session_factory=session_factory)
    app.add_middleware(RouteGuardMiddleware, settings=settings, session_factory=session_factory)


def operation_id(route: APIRoute) -> str:
    """The route function's name; a pair in ``PREFIXED_OPERATIONS`` gets its module prefix."""
    module = route.endpoint.__module__
    if (module, route.name) in PREFIXED_OPERATIONS:
        return f"{module.rsplit('.', 1)[-1]}_{route.name}"
    return route.name


def _install_openapi(app: FastAPI) -> None:
    """Serve the exported document (``build_document``) on the live route, built once.

    ``build_document`` reads ``get_openapi`` directly, never ``app.openapi``, so there is no
    recursion. The import is deferred because the export module imports this one.
    """

    def openapi() -> dict[str, Any]:
        if app.openapi_schema is None:
            from sandfort.api.openapi import build_document

            app.openapi_schema = build_document(app)
        return app.openapi_schema

    app.openapi = openapi  # type: ignore[method-assign]


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or Settings.from_env()
    app = FastAPI(
        title="Sandfort",
        version=__version__,
        lifespan=_lifespan,
        generate_unique_id_function=operation_id,
        default_response_class=SafeJSONResponse,
        docs_url=None,
        redoc_url=None,
    )
    install_docs_pages(app)
    _install_openapi(app)
    install_services(app, resolved)
    register_exception_handlers(app)
    # add_middleware wraps outward: the last one added runs first. The two guards sit inside
    # request id and telemetry (their refusals carry the id and are logged), outside routing.
    if resolved.routing_secret:
        _install_routing(app, resolved)  # innermost: inside the body limit, around the routes
    # Inside the body limit (it reads a bounded body), outside the routing middlewares: text the
    # API can neither store nor encode is refused before any route, forward or audit sees it.
    app.add_middleware(TextGuardMiddleware)
    app.add_middleware(BodyLimitMiddleware, max_bytes=resolved.max_request_body_bytes)
    if resolved.rate_limit_enabled:
        install_exchange_rate_limit(app)  # pre-authentication, the sign-on exchange route only
    app.add_middleware(TelemetryMiddleware, tracer=getattr(app.state, TRACER_ATTR))
    app.add_middleware(RequestIdMiddleware)
    # Outermost user middleware, but an unhandled exception's 500 is built by Starlette's
    # ServerErrorMiddleware outside it: the error handlers set the header on their own responses.
    app.add_middleware(SecurityHeadersMiddleware)

    app.add_api_route(METRICS_PATH, metrics_endpoint, methods=["GET"], include_in_schema=False)
    app.include_router(health.router)
    app.include_router(console.router)  # the page carries no data: no authentication dependency
    app.include_router(sandboxes.router)
    app.include_router(sandbox_logs.router)
    app.include_router(sandbox_preview.router)
    app.include_router(sandbox_resize.router)
    # process, fs, sessions, git and pty (REST and the /pty/{id}/connect websocket), with the
    # shared activity-touch dependency attached once at the aggregate router.
    app.include_router(toolbox.router)
    app.include_router(audit.router)
    app.include_router(jobs.router)
    app.include_router(nodes.router)
    app.include_router(snapshots.router)
    app.include_router(image_builds.router)
    app.include_router(volumes.router)
    app.include_router(orgs.router)
    app.include_router(webhooks.router)
    app.include_router(usage.router)
    app.include_router(api_keys.router)
    app.include_router(users.router)
    app.include_router(sso.router)  # the login: no authentication dependency
    if resolved.egress_policy_route_enabled and resolved.egress_secret:
        app.include_router(egress_policy.router)  # internal, MAC-authenticated, out of the spec
    if resolved.scim_enabled:  # off by default: no SCIM or SCIM token route is mounted at all
        app.include_router(scim_tokens.router)
        app.include_router(scim.router)  # /scim/v2, SCIM bearer token only, out of the spec
    return app
