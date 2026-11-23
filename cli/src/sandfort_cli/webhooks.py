"""The ``webhook`` command group; the signing secret prints only with --json --show-secret."""

import re
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any

import typer
from sandfort_sdk import DeliveryAttempt, WebhookDelivery, WebhookEndpoint
from sandfort_sdk.exceptions import ApiError
from sandfort_sdk.webhooks import MAX_LIMIT, MIN_LIMIT, DeliveryState

from sandfort_cli.audit import reject_unusable
from sandfort_cli.config import open_client
from sandfort_cli.output import (
    AppState,
    CliError,
    ErrorHint,
    app_state,
    clean_strings,
    cli_errors,
    print_fields,
    print_json,
    print_table,
    reject_empty_name,
    render_message,
    shown,
    utc_cell,
)
from sandfort_cli.sandboxes import JSON_ERROR_EPILOG, echo_value
from sandfort_cli.sanitise import caller_key

webhook_app = typer.Typer(
    name="webhook",
    help="Manage webhook endpoints and their deliveries.",
    epilog=JSON_ERROR_EPILOG,
    no_args_is_help=True,
)

ENDPOINT_METAVAR = "<endpoint-id>"
DELIVERY_METAVAR = "<delivery-id>"
URL_METAVAR = "<url>"
# The server's filter grammar (``api/schemas/webhooks.py``): ``*``, ``group.*``, ``group.name``.
EVENT_PATTERN = re.compile(r"\*|[a-z_]+\.(\*|[a-z_]+)")
MAX_EVENT_CHARS = 64
MAX_EVENTS = 32
DEFAULT_LIMIT = 50
NONE_CELL = "-"
ALL_EVENTS_CELL = "(all events)"
ENDPOINT_COLUMNS = ("ID", "URL", "ENABLED", "EVENTS", "FAILURES", "CREATED")
DELIVERY_FIELDS = (
    "id", "created_at", "event_type", "state", "attempts", "last_status", "last_error",
    "next_attempt_at",
)  # fmt: skip
DELIVERY_COLUMNS = (
    "ID", "CREATED", "EVENT TYPE", "STATE", "ATTEMPTS", "LAST STATUS", "LAST ERROR",
    "NEXT ATTEMPT",
)  # fmt: skip
# Free text, highest priority first; NEXT ATTEMPT, STATE and the numbers are never dropped.
DELIVERY_FREE = ("LAST ERROR",)
ATTEMPT_COLUMNS = ("KIND", "AT", "STATUS", "ERROR", "DURATION (ms)", "ACTOR")
SECRET_NOTE = (
    "note: the signing secret is returned only by this call and was not shown; "
    "pass --show-secret with the global --json to print it"
)
EVENT_HELP = "Event type filter: '*', 'group.*' or 'group.name' (repeatable)."
SHOW_SECRET_HELP = "Print the signing secret in the json object (needs the global --json)."
SHOW_SECRET_USAGE = "needs the global --json (sandfort --json webhook create ...)"
ENABLE_HELP = "Enable the endpoint (resets the failure count); not with --disable."
DISABLE_HELP = "Disable the endpoint; not with --enable."
HTTP_NOT_FOUND = 404
# A command that takes one id (an endpoint id) and one that takes both ids name different slips.
ONE_ID_HINT = (
    "endpoint ids and delivery ids share the whk_ prefix; check that you passed an endpoint id"
)
TWO_ID_HINT = (
    "webhook endpoint ids and delivery ids share the whk_ prefix; "
    "check the argument order (endpoint first, then delivery)"
)
STALE_AFTER = timedelta(minutes=5)
STALE_NOTE = (
    "deliveries have not been attempted for {minutes} min; the server's dispatcher may be "
    "disabled or failing, ask the operator"
)
ALL_HELP = "Page through every delivery (not with --cursor)."
DELIVERIES_EPILOG = (
    'With --json, one page prints {"deliveries": [...], "next_cursor": <cursor or null>} so a '
    "caller can continue with --cursor; with --all, a plain list of every delivery. --show "
    f"prints one delivery with its attempt history. {JSON_ERROR_EPILOG}"
)

EndpointId = Annotated[str, typer.Argument(metavar=ENDPOINT_METAVAR, help="Endpoint id.")]
DeliveryId = Annotated[str, typer.Argument(metavar=DELIVERY_METAVAR, help="Delivery id.")]


class StateChoice(StrEnum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    DISABLED = "disabled"


def reject_bad_events(events: Sequence[str], option: str = "--event") -> list[str]:
    """``events`` as a list; a blank or malformed filter, or too many, is a usage error."""
    if len(events) > MAX_EVENTS:
        raise typer.BadParameter(f"at most {MAX_EVENTS} filters", param_hint=option)
    for event in events:
        reject_empty_name(event, option)
        if len(event) > MAX_EVENT_CHARS or not EVENT_PATTERN.fullmatch(event):
            raise typer.BadParameter(
                f"invalid value {echo_value(event)}; expected '*', 'group.*' or 'group.name' "
                f"(lowercase letters and '_', at most {MAX_EVENT_CHARS} characters)",
                param_hint=option,
            )
    return list(events)


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _cell(value: object) -> str:
    """One server value for a table cell: sanitised; ``-`` when absent or empty."""
    return NONE_CELL if value is None else shown(value, caller_key()) or NONE_CELL


def _time(value: datetime | None) -> str:
    return utc_cell(value) or NONE_CELL


def printable_secret(endpoint: WebhookEndpoint) -> str:
    """The secret exactly as sent; refused (never printed) unless it is printable ascii."""
    secret = endpoint.secret or ""
    if not secret or not (secret.isascii() and secret.isprintable()) or " " in secret:
        raise CliError(
            f"endpoint {shown(endpoint.id, caller_key())} was created, but the server sent "
            "a signing secret that is not printable; it was not shown"
        )
    return secret


def _cleaned(payload: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = clean_strings(payload, caller_key())
    return cleaned


def endpoint_payload(endpoint: WebhookEndpoint) -> dict[str, Any]:
    """The endpoint object for ``--json``, sanitised, without the secret."""
    return _cleaned(
        {
            "id": endpoint.id,
            "url": endpoint.url,
            "enabled": endpoint.enabled,
            "event_types": list(endpoint.event_types),
            "failure_count": endpoint.failure_count,
            "created_at": _iso(endpoint.created_at),
        }
    )


def events_cell(endpoint: WebhookEndpoint) -> str:
    """The filters joined by commas; an empty filter admits every event."""
    key = caller_key()
    return ",".join(shown(event, key) for event in endpoint.event_types) or ALL_EVENTS_CELL


def endpoint_row(endpoint: WebhookEndpoint) -> tuple[str, ...]:
    """The cells of one endpoint under ``ENDPOINT_COLUMNS``, sanitised."""
    return (
        _cell(endpoint.id),
        _cell(endpoint.url),
        str(endpoint.enabled).lower(),
        events_cell(endpoint),
        str(endpoint.failure_count),
        _time(endpoint.created_at),
    )


def render_endpoint(state: AppState, endpoint: WebhookEndpoint) -> None:
    if state.json_output:
        print_json(endpoint_payload(endpoint))
        return
    names = ("id", "url", "enabled", "event_types", "failure_count", "created_at")
    print_fields("webhook endpoint", dict(zip(names, endpoint_row(endpoint), strict=True)))


def render_endpoints(state: AppState, endpoints: Sequence[WebhookEndpoint]) -> None:
    if state.json_output:
        print_json([endpoint_payload(endpoint) for endpoint in endpoints])
        return
    print_table("webhook endpoints", ENDPOINT_COLUMNS, [endpoint_row(e) for e in endpoints])


def attempt_payload(entry: DeliveryAttempt) -> dict[str, Any]:
    return {
        "kind": entry.kind,
        "attempted_at": _iso(entry.attempted_at),
        "status": entry.status,
        "error": entry.error,
        "duration_ms": entry.duration_ms,
        "actor_id": entry.actor_id,
    }


def delivery_payload(item: WebhookDelivery) -> dict[str, Any]:
    """The delivery object for ``--json``, sanitised, attempt history oldest first."""
    return _cleaned(
        {
            "id": item.id,
            "endpoint_id": item.endpoint_id,
            "event_id": item.event_id,
            "event_type": item.event_type,
            "state": item.state,
            "attempts": item.attempts,
            "last_status": item.last_status,
            "last_error": item.last_error,
            "next_attempt_at": _iso(item.next_attempt_at),
            "payload_sha256": item.payload_sha256,
            "attempt_history": [attempt_payload(entry) for entry in item.attempt_history],
            "created_at": _iso(item.created_at),
            "updated_at": _iso(item.updated_at),
        }
    )


def delivery_row(item: WebhookDelivery) -> tuple[str, ...]:
    """The cells of one delivery under ``DELIVERY_COLUMNS``, sanitised."""
    return (
        _cell(item.id),
        _time(item.created_at),
        _cell(item.event_type),
        _cell(item.state),
        str(item.attempts),
        _cell(item.last_status),
        _cell(item.last_error),
        _time(item.next_attempt_at),
    )


def render_deliveries(
    state: AppState, items: Sequence[WebhookDelivery], next_cursor: str | None, *, every: bool
) -> None:
    """A table (a next cursor on stderr). Json: every page is a plain list, one page is
    ``{"deliveries": [...], "next_cursor": ...}`` (the two shapes of ``audit list``)."""
    key = caller_key()
    if state.json_output:
        cursor = None if next_cursor is None else shown(next_cursor, key)
        listed = [delivery_payload(item) for item in items]
        print_json(listed if every else {"deliveries": listed, "next_cursor": cursor})
        return
    rows = [delivery_row(i) for i in items]
    print_table("webhook deliveries", DELIVERY_COLUMNS, rows, free=DELIVERY_FREE)
    if next_cursor is not None:
        typer.echo(f"next cursor: {shown(next_cursor, key)}", err=True)
    idle = idle_minutes(items)
    if idle is not None:
        typer.echo(STALE_NOTE.format(minutes=idle), err=True)


def idle_minutes(items: Sequence[WebhookDelivery], now: datetime | None = None) -> int | None:
    """Whole minutes since the oldest delivery was created, when every delivery is pending
    with no attempt and that age exceeds five minutes; otherwise ``None``."""
    if not items or any(i.state != "pending" or i.attempts != 0 for i in items):
        return None
    created = [i.created_at for i in items if i.created_at is not None]
    if not created:
        return None
    oldest = min(c if c.tzinfo is not None else c.replace(tzinfo=UTC) for c in created)
    age = (now or datetime.now(UTC)) - oldest
    return int(age.total_seconds() // 60) if age > STALE_AFTER else None


def hint_on_not_found(text: str) -> ErrorHint:
    """The ``cli_errors`` hint for a 404: ``text`` (the line that names the swapped-id mistake);
    any other failure has none."""

    def hint(exc: object) -> str | None:
        return text if isinstance(exc, ApiError) and exc.status_code == HTTP_NOT_FOUND else None

    return hint


HINT_ONE_ID = hint_on_not_found(ONE_ID_HINT)
HINT_TWO_IDS = hint_on_not_found(TWO_ID_HINT)


def attempt_row(entry: DeliveryAttempt) -> tuple[str, ...]:
    return (
        _cell(entry.kind),
        _time(entry.attempted_at),
        _cell(entry.status),
        _cell(entry.error),
        _cell(entry.duration_ms),
        _cell(entry.actor_id),
    )


def render_delivery(state: AppState, item: WebhookDelivery) -> None:
    """One delivery: its fields and its attempt history as a small table, or the json object."""
    if state.json_output:
        print_json(delivery_payload(item))
        return
    fields = dict(zip(DELIVERY_FIELDS, delivery_row(item), strict=True))
    fields.update(
        endpoint_id=_cell(item.endpoint_id),
        event_id=_cell(item.event_id),
        payload_sha256=_cell(item.payload_sha256),
        updated_at=_time(item.updated_at),
    )
    print_fields("webhook delivery", fields)
    print_table("attempts", ATTEMPT_COLUMNS, [attempt_row(e) for e in item.attempt_history])


@webhook_app.command("create")
def create(
    ctx: typer.Context,
    url: Annotated[str, typer.Argument(metavar=URL_METAVAR, help="Endpoint url.")],
    events: Annotated[list[str], typer.Option("--event", help=EVENT_HELP)],
    show_secret: Annotated[bool, typer.Option("--show-secret", help=SHOW_SECRET_HELP)] = False,
) -> None:
    """Register an endpoint; the server generates its signing secret (returned once)."""
    state = app_state(ctx)
    reject_empty_name(url, URL_METAVAR)
    filters = reject_bad_events(events)
    if show_secret and not state.json_output:
        raise typer.BadParameter(SHOW_SECRET_USAGE, param_hint="--show-secret")
    with cli_errors(), open_client() as client:
        endpoint = client.webhooks.create(url, filters)
        if show_secret:
            print_json({**endpoint_payload(endpoint), "secret": printable_secret(endpoint)})
            return
        render_endpoint(state, endpoint)
        if endpoint.secret is not None:
            typer.echo(SECRET_NOTE, err=True)


@webhook_app.command("list")
def list_endpoints(ctx: typer.Context) -> None:
    """List webhook endpoints."""
    with cli_errors(), open_client() as client:
        render_endpoints(app_state(ctx), client.webhooks.list())


@webhook_app.command("get")
def get(ctx: typer.Context, endpoint_id: EndpointId) -> None:
    """Show one webhook endpoint."""
    reject_empty_name(endpoint_id, ENDPOINT_METAVAR)
    app = app_state(ctx)
    with cli_errors(hint=HINT_ONE_ID), open_client() as client:
        render_endpoint(app, client.webhooks.get(endpoint_id))


@webhook_app.command("update")
def update(
    ctx: typer.Context,
    endpoint_id: EndpointId,
    url: Annotated[str | None, typer.Option("--url", help="New endpoint url.")] = None,
    events: Annotated[
        list[str] | None, typer.Option("--event", help=f"{EVENT_HELP} Replaces the filters.")
    ] = None,
    enable: Annotated[bool, typer.Option("--enable", help=ENABLE_HELP)] = False,
    disable: Annotated[bool, typer.Option("--disable", help=DISABLE_HELP)] = False,
) -> None:
    """Change the given fields of an endpoint only."""
    reject_empty_name(endpoint_id, ENDPOINT_METAVAR)
    if enable and disable:
        raise typer.BadParameter("cannot be combined with --enable", param_hint="--disable")
    if url is not None:
        reject_empty_name(url, "--url")
    filters = None if events is None else reject_bad_events(events)
    enabled = True if enable else (False if disable else None)
    if url is None and filters is None and enabled is None:
        raise typer.BadParameter("nothing to update: pass --url, --event, --enable or --disable")
    changes: dict[str, Any] = {"url": url, "events": filters, "enabled": enabled}
    given = {name: value for name, value in changes.items() if value is not None}
    app = app_state(ctx)
    with cli_errors(hint=HINT_ONE_ID), open_client() as client:
        render_endpoint(app, client.webhooks.update(endpoint_id, **given))


@webhook_app.command("rm")
def rm(ctx: typer.Context, endpoint_id: EndpointId) -> None:
    """Delete an endpoint (no prompt); prints its id (--json: the endpoint as it was)."""
    reject_empty_name(endpoint_id, ENDPOINT_METAVAR)
    app = app_state(ctx)
    with cli_errors(hint=HINT_ONE_ID), open_client() as client:
        payload = endpoint_payload(client.webhooks.delete(endpoint_id))
        render_message(app, str(payload["id"]), payload)


def _state(choice: StateChoice | None) -> DeliveryState | None:
    return None if choice is None else choice.value


def reject_show_combination(show: str, options: dict[str, object]) -> None:
    """A blank ``--show`` id, or ``--show`` next to a list option, is a usage error."""
    reject_empty_name(show, "--show")
    for option, value in options.items():
        if value is not None and value is not False:
            raise typer.BadParameter("cannot be combined with --show", param_hint=option)


@webhook_app.command("deliveries", epilog=DELIVERIES_EPILOG)
def deliveries(
    ctx: typer.Context,
    endpoint_id: EndpointId,
    event_type: Annotated[
        str | None, typer.Option("--event-type", help="Only this event type.")
    ] = None,
    state: Annotated[
        StateChoice | None, typer.Option("--state", help="Only deliveries in this state.")
    ] = None,
    limit: Annotated[
        int, typer.Option("--limit", min=MIN_LIMIT, max=MAX_LIMIT, help="Deliveries per page.")
    ] = DEFAULT_LIMIT,
    cursor: Annotated[str | None, typer.Option("--cursor", help="Continue after a cursor.")] = None,
    all_pages: Annotated[bool, typer.Option("--all", help=ALL_HELP)] = False,
    show: Annotated[
        str | None,
        typer.Option("--show", metavar=DELIVERY_METAVAR, help="Show one delivery and attempts."),
    ] = None,
) -> None:
    """List an endpoint's deliveries in id order, or show one with its attempts (--show)."""
    reject_empty_name(endpoint_id, ENDPOINT_METAVAR)
    app = app_state(ctx)
    if show is not None:
        options: dict[str, object] = {
            "--event-type": event_type, "--state": state, "--cursor": cursor, "--all": all_pages,
        }  # fmt: skip
        reject_show_combination(show, options)
        with cli_errors(hint=HINT_TWO_IDS), open_client() as client:
            render_delivery(app, client.webhooks.get_delivery(endpoint_id, show))
        return
    reject_unusable(event_type, "--event-type")
    reject_unusable(cursor, "--cursor")
    if all_pages and cursor is not None:
        raise typer.BadParameter("cannot be combined with --all", param_hint="--cursor")
    filters: dict[str, Any] = {"event_type": event_type, "state": _state(state), "limit": limit}
    with cli_errors(hint=HINT_ONE_ID), open_client() as client:
        hooks = client.webhooks
        if all_pages:
            items = list(hooks.iter_deliveries(endpoint_id, **filters))
            render_deliveries(app, items, None, every=True)
            return
        page = hooks.deliveries(endpoint_id, cursor=cursor, **filters)
        render_deliveries(app, page.deliveries, page.next_cursor, every=False)


@webhook_app.command("redeliver")
def redeliver(ctx: typer.Context, endpoint_id: EndpointId, delivery_id: DeliveryId) -> None:
    """Requeue a failed or disabled delivery (the server refuses any other state)."""
    reject_empty_name(endpoint_id, ENDPOINT_METAVAR)
    reject_empty_name(delivery_id, DELIVERY_METAVAR)
    app = app_state(ctx)
    with cli_errors(hint=HINT_TWO_IDS), open_client() as client:
        render_delivery(app, client.webhooks.redeliver(endpoint_id, delivery_id))
