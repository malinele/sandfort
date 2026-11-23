"""OpenTelemetry tracing across the API, job and driver layers (WP 4.5).

Spans go to one process-wide SDK ``TracerProvider`` owned by this module; the global OTel
provider is left alone, so tests and embedders add exporters without fighting over it.
``build_tracer`` returns a no-op tracer when ``tracing_enabled`` is off. The ``none`` exporter
records spans without exporting them, ``console`` prints them, and ``install_span_exporter``
adds any other exporter (the tests install the in-memory one).

Three instrumentation points, each also feeding the metric catalog:

* ``TelemetryMiddleware``: one SERVER span per HTTP request, named ``<METHOD> <route>`` where
  the route is the matched template (path parameter values folded back to ``{name}``).
* ``TracedHandlerRegistry``: one CONSUMER span per job handler run, named ``job <kind>``. The
  enqueueing context travels in the job payload under ``TRACE_CONTEXT_KEY`` (W3C trace context
  injected by ``with_trace_propagation``), so a job joins the trace of the request that queued
  it. Handlers never see that key.
* ``instrument_driver``: one CLIENT span per awaited driver call, named ``driver.<operation>``.

Spans carry ``sandfort.org_id`` and ``sandfort.sandbox_id`` when known (from a ``SandboxSpec``
argument, a job payload or the enclosing job). Nothing else from arguments, payloads or paths
is recorded, so key material, env values and commands never reach a span.
"""

import asyncio
import dataclasses
import functools
import inspect
import logging
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Final, cast

from opentelemetry.context.context import Context
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
    SpanExporter,
)
from opentelemetry.trace import NoOpTracer, Span, SpanKind, Status, StatusCode, Tracer
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sandfort import __version__
from sandfort.config import Settings
from sandfort.db.repositories.ports import JobRecord, JobRepository, UnitOfWorkPort
from sandfort.drivers.base import SandboxDriver, SandboxSpec
from sandfort.observability import metrics
from sandfort.workers.handlers import HandlerRegistry, JobContext, JobHandler

TRACER_NAME: Final = "sandfort"
SERVICE_NAME: Final = "sandfort"
CONSOLE_EXPORTER: Final = "console"
TRACE_CONTEXT_KEY: Final = "trace_context"
ORG_ID_ATTR: Final = "sandfort.org_id"
SANDBOX_ID_ATTR: Final = "sandfort.sandbox_id"
JOB_KIND_ATTR: Final = "sandfort.job.kind"
DRIVER_OPERATION_ATTR: Final = "sandfort.driver.operation"
EXCEPTION_TYPE_ATTR: Final = "exception.type"
UNMATCHED_ROUTE: Final = "unmatched"
_ID_FIELDS: Final = (("org_id", ORG_ID_ATTR), ("sandbox_id", SANDBOX_ID_ATTR))
_PROXY_SLOTS: Final = frozenset({"_inner", "_tracer"})

_PROVIDER: Final = TracerProvider(resource=Resource.create({"service.name": SERVICE_NAME}))
_PROPAGATOR: Final = TraceContextTextMapPropagator()
_installed: Final[list[SpanExporter]] = []
# Org and sandbox ids of the job being run, inherited by the driver spans it opens.
_JOB_IDS: ContextVar[Mapping[str, str] | None] = ContextVar("sandfort_job_ids", default=None)
_access_log = logging.getLogger("sandfort.access")


# -- setup -------------------------------------------------------------------------------


def install_span_exporter(exporter: SpanExporter, *, batch: bool = False) -> None:
    """Send finished spans to ``exporter``; installing the same exporter again is a no-op."""
    if any(existing is exporter for existing in _installed):
        return
    processor = BatchSpanProcessor(exporter) if batch else SimpleSpanProcessor(exporter)
    _PROVIDER.add_span_processor(processor)
    _installed.append(exporter)


@functools.cache
def _console_exporter() -> ConsoleSpanExporter:
    return ConsoleSpanExporter()


def build_tracer(settings: Settings) -> Tracer:
    if not settings.tracing_enabled:
        return NoOpTracer()
    if settings.tracing_exporter == CONSOLE_EXPORTER:
        install_span_exporter(_console_exporter(), batch=True)
    return _PROVIDER.get_tracer(TRACER_NAME, __version__)


@contextmanager
def _span(
    tracer: Tracer,
    name: str,
    kind: SpanKind,
    *,
    attributes: Mapping[str, str] | None = None,
    context: Context | None = None,
) -> Iterator[Span]:
    """A current span that records a failure by exception class name only, never its text."""
    with tracer.start_as_current_span(
        name,
        context=context,
        kind=kind,
        attributes=attributes,
        record_exception=False,
        set_status_on_exception=False,
    ) as span:
        try:
            yield span
        except BaseException as exc:
            span.set_attribute(EXCEPTION_TYPE_ATTR, type(exc).__name__)
            span.set_status(Status(StatusCode.ERROR, type(exc).__name__))
            raise


def _ids_from(values: Mapping[str, Any]) -> dict[str, str]:
    ids: dict[str, str] = {}
    for field, attribute in _ID_FIELDS:
        value = values.get(field)
        if isinstance(value, str):
            ids[attribute] = value
    return ids


# -- api -----------------------------------------------------------------------------------


def route_template(scope: Scope) -> str:
    """The matched route with path parameter values folded back to ``{name}`` placeholders.

    Built from the full request path rather than the route object, so the prefixes of included
    routers and mounted sub-applications are always part of the label.
    """
    if scope.get("endpoint") is None and scope.get("route") is None:
        return UNMATCHED_ROUTE
    params: Mapping[str, Any] = scope.get("path_params") or {}
    names = {str(value): name for name, value in params.items() if str(value)}
    segments = str(scope.get("path", "")).split("/")
    return "/".join(f"{{{names[part]}}}" if part in names else part for part in segments)


def _finish_request_span(span: Span, method: str, route: str, status: int, scope: Scope) -> None:
    span.update_name(f"{method} {route}")
    span.set_attribute("http.request.method", method)
    span.set_attribute("http.route", route)
    span.set_attribute("http.response.status_code", status)
    params: Mapping[str, Any] = scope.get("path_params") or {}
    sandbox_id = params.get("sandbox_id")
    if isinstance(sandbox_id, str):
        span.set_attribute(SANDBOX_ID_ATTR, sandbox_id)
    if status >= 500:
        span.set_status(Status(StatusCode.ERROR))


class TelemetryMiddleware:
    """One SERVER span, the HTTP metrics and one access log line per HTTP request."""

    def __init__(self, app: ASGIApp, tracer: Tracer) -> None:
        self.app = app
        self._tracer = tracer

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method = str(scope.get("method", ""))
        status = 500  # what the client gets when the app fails before starting a response

        async def send_with_status(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
            await send(message)

        started = time.perf_counter()
        with _span(self._tracer, method, SpanKind.SERVER) as span:
            try:
                await self.app(scope, receive, send_with_status)
            finally:
                elapsed = time.perf_counter() - started
                route = route_template(scope)
                _finish_request_span(span, method, route, status, scope)
                metrics.record_http_request(method, route, status, elapsed)
                _access_log.info(
                    "request completed",
                    extra={
                        "method": method,
                        "route": route,
                        "status": status,
                        "duration_ms": round(elapsed * 1000, 3),
                    },
                )


# -- jobs ----------------------------------------------------------------------------------


class _PropagatingJobs:
    """Adds the enqueueing trace context to each job payload; other calls pass through."""

    def __init__(self, inner: JobRepository) -> None:
        self._inner = inner

    async def enqueue(self, job: JobRecord) -> None:
        carrier: dict[str, str] = {}
        _PROPAGATOR.inject(carrier)
        if not carrier:  # no active span: nothing to carry
            await self._inner.enqueue(job)
            return
        traced = dataclasses.replace(job, payload={**job.payload, TRACE_CONTEXT_KEY: carrier})
        await self._inner.enqueue(traced)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def with_trace_propagation(
    uow_factory: Callable[[], UnitOfWorkPort],
) -> Callable[[], UnitOfWorkPort]:
    """A unit-of-work factory whose job repository stamps the current trace on enqueued jobs."""

    def factory() -> UnitOfWorkPort:
        uow = uow_factory()
        uow.jobs = cast(JobRepository, _PropagatingJobs(uow.jobs))
        return uow

    return factory


def _enqueued_context(payload: Mapping[str, Any]) -> Context | None:
    carrier = payload.get(TRACE_CONTEXT_KEY)
    if not isinstance(carrier, Mapping):
        return None  # the current context, so the span starts a new trace
    return _PROPAGATOR.extract({str(key): str(value) for key, value in carrier.items()})


async def _run_job(
    tracer: Tracer,
    kind: str,
    handler: JobHandler,
    payload: Mapping[str, Any],
    context: JobContext,
) -> None:
    clean = {key: value for key, value in payload.items() if key != TRACE_CONTEXT_KEY}
    ids = _ids_from(clean)
    outcome = metrics.ERROR
    token = _JOB_IDS.set(ids)
    try:
        with _span(
            tracer,
            f"job {kind}",
            SpanKind.CONSUMER,
            attributes={**ids, JOB_KIND_ATTR: kind},
            context=_enqueued_context(payload),
        ):
            await handler(clean, context)
        outcome = metrics.OK
    except asyncio.CancelledError:  # the runner's timeout or shutdown
        outcome = metrics.CANCELLED
        raise
    finally:
        _JOB_IDS.reset(token)
        metrics.record_job(kind, outcome)


class TracedHandlerRegistry(HandlerRegistry):
    """Delegates to ``inner`` (registrations stay there) and traces each handler it hands out."""

    def __init__(self, inner: HandlerRegistry, tracer: Tracer) -> None:
        super().__init__()
        self._inner = inner
        self._tracer = tracer

    def register[H: JobHandler](self, kind: str) -> Callable[[H], H]:
        return self._inner.register(kind)

    def lookup(self, kind: str) -> JobHandler:
        handler = self._inner.lookup(kind)
        tracer = self._tracer

        async def traced(payload: Mapping[str, Any], context: JobContext) -> None:
            await _run_job(tracer, kind, handler, payload, context)

        return traced

    def kinds(self) -> frozenset[str]:
        return self._inner.kinds()


# -- driver --------------------------------------------------------------------------------


class _DriverProxy:
    """Base of the generated per-driver-class wrappers built by ``instrument_driver``."""

    __slots__ = ("_inner", "_tracer")

    def __init__(self, inner: object, tracer: Tracer) -> None:
        self._inner = inner
        self._tracer = tracer

    def __getattr__(self, name: str) -> Any:
        # Reached only for names the generated class lacks (instance data such as test hooks).
        if name in _PROXY_SLOTS:  # not set yet: never recurse into the wrapped driver
            raise AttributeError(name)
        return getattr(self._inner, name)

    def __repr__(self) -> str:
        return f"<instrumented {self._inner!r}>"


def _call_ids(args: tuple[Any, ...]) -> dict[str, str]:
    """Ids of the enclosing job, overridden by those of a ``SandboxSpec`` argument."""
    spec_ids = next(
        (
            {ORG_ID_ATTR: arg.org_id, SANDBOX_ID_ATTR: arg.sandbox_id}
            for arg in args
            if isinstance(arg, SandboxSpec)
        ),
        {},
    )
    return {**(_JOB_IDS.get() or {}), **spec_ids}


@contextmanager
def _driver_span(tracer: Tracer, operation: str, args: tuple[Any, ...]) -> Iterator[None]:
    attributes = {**_call_ids(args), DRIVER_OPERATION_ATTR: operation}
    outcome = metrics.ERROR
    started = time.perf_counter()
    try:
        with _span(tracer, f"driver.{operation}", SpanKind.CLIENT, attributes=attributes):
            yield
        outcome = metrics.OK
    finally:
        metrics.record_driver_call(operation, outcome, time.perf_counter() - started)


def _traced_call(operation: str) -> Callable[..., Any]:
    async def call(self: _DriverProxy, *args: Any, **kwargs: Any) -> Any:
        with _driver_span(self._tracer, operation, args):
            return await getattr(self._inner, operation)(*args, **kwargs)

    call.__name__ = operation
    return call


def _forwarded_call(name: str) -> Callable[..., Any]:
    def call(self: _DriverProxy, *args: Any, **kwargs: Any) -> Any:
        return getattr(self._inner, name)(*args, **kwargs)

    call.__name__ = name
    return call


def _forwarded_value(name: str) -> property:
    return property(lambda self: getattr(self._inner, name))


def _proxy_member(name: str, member: object) -> object:
    function = member.__func__ if isinstance(member, staticmethod | classmethod) else member
    if isinstance(function, property) or not callable(function):
        return _forwarded_value(name)
    if inspect.iscoroutinefunction(function):
        return _traced_call(name)
    return _forwarded_call(name)  # plain methods and streaming (async generator) members


@functools.cache
def _proxy_type(driver_type: type) -> type[_DriverProxy]:
    namespace: dict[str, object] = {"__slots__": ()}
    for name in dir(driver_type):
        if not name.startswith("_"):
            namespace[name] = _proxy_member(name, inspect.getattr_static(driver_type, name))
    created = type(f"Instrumented{driver_type.__name__}", (_DriverProxy,), namespace)
    return cast(type[_DriverProxy], created)


def instrument_driver(driver: SandboxDriver, tracer: Tracer) -> SandboxDriver:
    """Wrap ``driver`` so every awaited call gets a span and the driver metrics.

    The wrapper's class mirrors each public member of the driver's class, so the runtime
    capability checks (``isinstance`` against the ``runtime_checkable`` driver protocols) see
    exactly what the driver implements. Members are resolved on the wrapped driver at call
    time, so instance-level replacements still take effect. Streaming members (async
    generators) and plain methods are forwarded without a span.
    """
    return cast(SandboxDriver, _proxy_type(type(driver))(driver, tracer))
