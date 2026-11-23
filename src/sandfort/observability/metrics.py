"""The stable metric catalog and its Prometheus text exposition (WP 4.5).

Every metric name is declared once below and is part of the operator contract (dashboards and
alerts key on it): renaming one is a breaking change that the snapshot test catches. Metrics
live in a dedicated registry, so ``/metrics`` exposes exactly this catalog (no process or GC
collectors), and the ``*_created`` companion series are disabled for the same reason.

Hooks: the HTTP middleware, the job registry wrapper and the driver wrapper in
``observability.tracing`` call the ``record_*`` functions; ``with_delivery_metrics`` counts
webhook delivery outcomes as the dispatcher records them; the ``/metrics`` route refreshes the
queue-depth gauge before rendering. Label values are bounded: routes are templates, outcomes
are the constants below, kinds and operations are code-defined names.
"""

from collections.abc import Callable
from typing import Any, Final, cast

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    disable_created_metrics,
    generate_latest,
)

from sandfort.db.models.webhooks import DeliveryState
from sandfort.db.repositories.ports import (
    UnitOfWorkPort,
    WebhookDeliveryRecord,
    WebhookRepository,
)

HTTP_REQUESTS_TOTAL: Final = "sandfort_http_requests_total"
HTTP_REQUEST_SECONDS: Final = "sandfort_http_request_seconds"
SANDBOX_CREATES_TOTAL: Final = "sandfort_sandbox_creates_total"
JOBS_PROCESSED_TOTAL: Final = "sandfort_jobs_processed_total"
JOBS_QUEUE_DEPTH: Final = "sandfort_jobs_queue_depth"
DRIVER_CALLS_TOTAL: Final = "sandfort_driver_calls_total"
DRIVER_CALL_SECONDS: Final = "sandfort_driver_call_seconds"
WEBHOOK_DELIVERIES_TOTAL: Final = "sandfort_webhook_deliveries_total"
METRIC_NAMES: Final = frozenset(
    {
        HTTP_REQUESTS_TOTAL,
        HTTP_REQUEST_SECONDS,
        SANDBOX_CREATES_TOTAL,
        JOBS_PROCESSED_TOTAL,
        JOBS_QUEUE_DEPTH,
        DRIVER_CALLS_TOTAL,
        DRIVER_CALL_SECONDS,
        WEBHOOK_DELIVERIES_TOTAL,
    }
)

OK: Final = "ok"
ERROR: Final = "error"
CANCELLED: Final = "cancelled"
SANDBOX_CREATE_OPERATION: Final = "create"  # the driver call that provisions a sandbox
_DELIVERY_OUTCOMES: Final = {
    DeliveryState.DELIVERED.value: "delivered",
    DeliveryState.PENDING.value: "retrying",
    DeliveryState.FAILED.value: "failed",
    DeliveryState.DISABLED.value: "disabled",
}

# Keeps the exposition to exactly the catalog above (the library function is unannotated).
disable_created_metrics()  # type: ignore[no-untyped-call]
REGISTRY: Final = CollectorRegistry(auto_describe=True)

_http_requests = Counter(
    HTTP_REQUESTS_TOTAL,
    "HTTP requests served, by method, route template and status code.",
    labelnames=("method", "route", "status"),
    registry=REGISTRY,
)
_http_seconds = Histogram(
    HTTP_REQUEST_SECONDS,
    "HTTP request duration in seconds, by method and route template.",
    labelnames=("method", "route"),
    registry=REGISTRY,
)
_sandbox_creates = Counter(
    SANDBOX_CREATES_TOTAL,
    "Sandbox provisioning attempts (driver create calls), by outcome.",
    labelnames=("outcome",),
    registry=REGISTRY,
)
_jobs_processed = Counter(
    JOBS_PROCESSED_TOTAL,
    "Job handler executions, by job kind and outcome.",
    labelnames=("kind", "outcome"),
    registry=REGISTRY,
)
_jobs_queue_depth = Gauge(
    JOBS_QUEUE_DEPTH,
    "Jobs waiting in the queued state, sampled at scrape time.",
    registry=REGISTRY,
)
_driver_calls = Counter(
    DRIVER_CALLS_TOTAL,
    "Driver calls, by operation and outcome.",
    labelnames=("operation", "outcome"),
    registry=REGISTRY,
)
_driver_seconds = Histogram(
    DRIVER_CALL_SECONDS,
    "Driver call duration in seconds, by operation.",
    labelnames=("operation",),
    registry=REGISTRY,
)
_webhook_deliveries = Counter(
    WEBHOOK_DELIVERIES_TOTAL,
    "Webhook delivery attempts recorded by the dispatcher, by outcome.",
    labelnames=("outcome",),
    registry=REGISTRY,
)


def record_http_request(method: str, route: str, status: int, seconds: float) -> None:
    _http_requests.labels(method=method, route=route, status=str(status)).inc()
    _http_seconds.labels(method=method, route=route).observe(seconds)


def record_driver_call(operation: str, outcome: str, seconds: float) -> None:
    _driver_calls.labels(operation=operation, outcome=outcome).inc()
    _driver_seconds.labels(operation=operation).observe(seconds)
    if operation == SANDBOX_CREATE_OPERATION:
        _sandbox_creates.labels(outcome=outcome).inc()


def record_job(kind: str, outcome: str) -> None:
    _jobs_processed.labels(kind=kind, outcome=outcome).inc()


def set_queue_depth(depth: int) -> None:
    _jobs_queue_depth.set(depth)


def record_webhook_delivery(outcome: str) -> None:
    _webhook_deliveries.labels(outcome=outcome).inc()


def render_metrics() -> tuple[bytes, str]:
    """The Prometheus text exposition of the catalog and its content type."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


class _MeteredDeliveries:
    """Counts each delivery state the dispatcher writes; every other call passes through."""

    def __init__(self, inner: WebhookRepository) -> None:
        self._inner = inner

    @property
    def wrapped(self) -> WebhookRepository:
        """The repository this decorator counts for (read-only)."""
        return self._inner

    async def update_delivery_state(
        self, delivery: WebhookDeliveryRecord
    ) -> WebhookDeliveryRecord | None:
        saved = await self._inner.update_delivery_state(delivery)
        record_webhook_delivery(_DELIVERY_OUTCOMES.get(delivery.state, delivery.state))
        return saved

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def with_delivery_metrics(
    uow_factory: Callable[[], UnitOfWorkPort],
) -> Callable[[], UnitOfWorkPort]:
    """A unit-of-work factory whose webhook repository counts delivery outcomes."""

    def factory() -> UnitOfWorkPort:
        uow = uow_factory()
        uow.webhooks = cast(WebhookRepository, _MeteredDeliveries(uow.webhooks))
        return uow

    return factory
