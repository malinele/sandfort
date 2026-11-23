"""The ``audit`` command group (list, verify, verify-head, export) over ``client.audit``."""

import json
import sys
import unicodedata
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import typer
from sandfort_sdk import AuditEvent, AuditVerifyResult, SandfortSDKError
from sandfort_sdk.audit import MAX_LIMIT, MIN_LIMIT, AuditOrder

from sandfort_cli.atomic_write import plan_target, write_export
from sandfort_cli.audit_verify_cmd import (
    EXIT_BROKEN_CHAIN,
    SingleValueCommand,
    key_fingerprint,
    register_verify_head,
)
from sandfort_cli.audit_verify_cmd import (
    REASONS as REASONS,  # noqa: PLC0414  (re-exported: tests import it from here)
)
from sandfort_cli.audit_verify_cmd import cell as _cell
from sandfort_cli.config import open_client
from sandfort_cli.output import (
    EXIT_FAILURE,
    AppState,
    CliError,
    ErrorHint,
    app_state,
    clean_strings,
    cli_errors,
    error_payload,
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

audit_app = typer.Typer(
    name="audit",
    help="Query and verify the audit log.",
    epilog=JSON_ERROR_EPILOG,
    no_args_is_help=True,
)

HEAD_TYPE = "audit_head"
SUMMARY_TYPE = "export_summary"
TRAILER_TYPES = (HEAD_TYPE, SUMMARY_TYPE)
OUTCOMES = ("success", "denied", "error")  # AuditOutcome of the API
STDOUT_NAME = "-"
EXIT_NO_TRAILER = 3
NO_TRAILER_WARNING = "the export ended without a trailer line; it may be cut short"
CONTROL_CATEGORY = "Cc"
DEFAULT_LIMIT = 50
LIST_COLUMNS = (
    "OCCURRED", "ACTOR", "ACTION", "TARGET", "OUTCOME", "STATUS", "ERROR", "PATH", "REQUEST ID"
)  # fmt: skip
# Fixed column widths of ``list --all`` text output, which prints rows as they arrive and so
# cannot size columns from all rows: a UTC timestamp, ids, an action name, an outcome, an HTTP
# status, an error code, a route path.
STREAM_WIDTHS = (19, 30, 24, 30, 8, 6, 20, 30, 0)
# The columns of `list` that give way to a narrow terminal, highest priority first: the ids
# (ACTOR, REQUEST ID) are dropped whole rather than cut, the free text is cut or dropped. PATH
# goes before ERROR. OCCURRED, ACTION, OUTCOME and STATUS are never squeezed.
TABLE_FREE = ("TARGET", "ACTOR", "ERROR", "PATH", "REQUEST ID")
TABLE_UNCUT = ("ACTOR", "REQUEST ID")
TARGET_INDEX = LIST_COLUMNS.index("TARGET")
PATH_INDEX = LIST_COLUMNS.index("PATH")
NO_VALUE = "-"
DENIED_PREFIX = "request."
STATUS_DETAIL = "status"
ERROR_DETAIL = "error_code"
PATH_DETAIL = "path"
COLUMN_GAP = "  "
JSON_INDENT = 2
JSON_ITEM_INDENT = " " * JSON_INDENT
FINDING_COLUMNS = ("KIND", "EVENT ID", "DETAIL")
DATE_HELP = "ISO 8601; a date alone is midnight UTC, a value without an offset is UTC."
FROM_HELP = f"At or after this moment (inclusive). {DATE_HELP}"
TO_HELP = f"Before this moment (exclusive). {DATE_HELP}"
LIST_EPILOG = (
    'With --json, one page prints {"events": [...], "next_cursor": <cursor or null>} so a '
    "caller can continue with --cursor; with --all, a plain list of every event, printed once "
    "all pages arrived (when a page fails, the error is the only document, with the events "
    "fetched so far counted in error.details.partial_rows). --all prints text rows as each "
    "page arrives (fixed-width columns). "
    f"{JSON_ERROR_EPILOG}"
)


class OrderChoice(StrEnum):
    NEWEST = "newest"
    OLDEST = "oldest"


API_ORDER: dict[OrderChoice, AuditOrder] = {
    OrderChoice.NEWEST: "desc",
    OrderChoice.OLDEST: "asc",
}
# Older scripts pass the API's own words; they stay accepted (asc = oldest, desc = newest).
ORDER_ALIASES: dict[str, OrderChoice] = {"asc": OrderChoice.OLDEST, "desc": OrderChoice.NEWEST}
ORDER_METAVAR = "[newest|oldest]"


def parse_order(value: str) -> OrderChoice:
    """``newest`` or ``oldest`` (aliases ``desc`` and ``asc``); anything else is a usage error."""
    key = value.strip().lower()
    if key in ORDER_ALIASES:
        return ORDER_ALIASES[key]
    try:
        return OrderChoice(key)
    except ValueError:
        raise typer.BadParameter(
            f"{value!r} is not one of 'newest', 'oldest' (or the aliases 'desc', 'asc')."
        ) from None


def reject_unusable(value: str | None, option: str) -> None:
    """An empty value, or one holding a control character, is a usage error (exit 2)."""
    if value is None:
        return
    reject_empty_name(value, option)
    if any(unicodedata.category(char) == CONTROL_CATEGORY for char in value):
        raise typer.BadParameter("must not contain control characters", param_hint=option)


def check_outcome(value: str | None) -> None:
    """``--outcome`` must be one of the API's values; the server would answer 400 and keep a
    permanent ``request.denied`` row for it."""
    reject_unusable(value, "--outcome")
    if value is not None and value not in OUTCOMES:
        raise typer.BadParameter(
            f"{echo_value(value)} is not one of {', '.join(OUTCOMES)}", param_hint="--outcome"
        )


def check_period(since: datetime | None, until: datetime | None) -> None:
    """``--from`` must not be later than ``--to`` (the server would refuse, and audit it)."""
    if since is not None and until is not None and since > until:
        raise typer.BadParameter("must not be later than --to", param_hint="--from")


def parse_moment(value: str | None, option: str) -> datetime | None:
    """``value`` as a timezone-aware datetime (naive and date-only values are UTC)."""
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise typer.BadParameter(
            f"invalid value {echo_value(value)}; expected ISO 8601 (for example 2026-11-01 "
            "or 2026-11-01T08:30:00Z)",
            param_hint=option,
        ) from None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def event_payload(event: AuditEvent) -> dict[str, Any]:
    """The event object for ``--json``: server strings sanitised, ``occurred_at`` ISO 8601."""
    payload = {
        "id": event.id,
        "org_id": event.org_id,
        "actor_type": event.actor_type,
        "actor_id": event.actor_id,
        "action": event.action,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "outcome": event.outcome,
        "request_id": event.request_id,
        "ip": event.ip,
        "user_agent": event.user_agent,
        "occurred_at": event.occurred_at.isoformat(),
        "details": dict(event.details),
    }
    cleaned: dict[str, Any] = clean_strings(payload, caller_key())
    return cleaned


def detail_cell(event: AuditEvent, name: str) -> str:
    """One field of the event details as a sanitised cell (``-`` when absent or empty)."""
    return _cell(event.details.get(name))


def target_cell(event: AuditEvent) -> str:
    """The target id; a ``request.*`` row has none, so it shows the route path instead."""
    if event.target_id or not event.action.startswith(DENIED_PREFIX):
        return _cell(event.target_id)
    return detail_cell(event, PATH_DETAIL)


def event_row(event: AuditEvent) -> tuple[str, ...]:
    """The cells of one event under ``LIST_COLUMNS``, sanitised."""
    return (
        utc_cell(event.occurred_at),
        _cell(event.actor_id),
        _cell(event.action),
        target_cell(event),
        _cell(event.outcome),
        detail_cell(event, STATUS_DETAIL),
        detail_cell(event, ERROR_DETAIL),
        detail_cell(event, PATH_DETAIL),
        _cell(event.request_id),
    )


def _blank_repeated_path(row: tuple[str, ...]) -> tuple[str, ...]:
    """``row`` with its PATH cell blank when it repeats the TARGET cell."""
    target, path = row[TARGET_INDEX], row[PATH_INDEX]
    if path != target:
        return row
    return tuple(NO_VALUE if i == PATH_INDEX else cell for i, cell in enumerate(row))


def table_rows(events: list[AuditEvent]) -> tuple[tuple[str, ...], list[tuple[str, ...]]]:
    """The columns and rows of the list table. A PATH that repeats the TARGET (a denied request
    has no target, so TARGET shows the path) is blank; PATH is left out when nothing is left."""
    rows = [_blank_repeated_path(event_row(event)) for event in events]
    columns: tuple[str, ...] = LIST_COLUMNS
    if all(row[PATH_INDEX] == NO_VALUE for row in rows):
        columns = tuple(name for i, name in enumerate(columns) if i != PATH_INDEX)
        rows = [tuple(cell for i, cell in enumerate(row) if i != PATH_INDEX) for row in rows]
    return columns, rows


def _free_present(columns: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(name for name in TABLE_FREE if name in columns)


def render_page(state: AppState, events: list[AuditEvent], next_cursor: str | None) -> None:
    """One page: a table, or json with the events and the next cursor."""
    key = caller_key()
    if state.json_output:
        cursor = None if next_cursor is None else shown(next_cursor, key)
        print_json({"events": [event_payload(event) for event in events], "next_cursor": cursor})
        return
    columns, rows = table_rows(events)
    print_table("audit events", columns, rows, free=_free_present(columns), uncut=TABLE_UNCUT)
    if next_cursor is not None:
        typer.echo(f"next cursor: {shown(next_cursor, key)}", err=True)


def stream_line(cells: tuple[str, ...]) -> str:
    """Cells padded to ``STREAM_WIDTHS`` (a longer cell pushes the rest of its line right)."""
    padded = (cell.ljust(width) for cell, width in zip(cells, STREAM_WIDTHS, strict=True))
    return COLUMN_GAP.join(padded).rstrip()


def stream_rows(events: Iterable[AuditEvent]) -> None:
    """The header, then one line per event as it arrives (nothing is kept)."""
    started = False
    for event in events:
        if not started:
            typer.echo(stream_line(LIST_COLUMNS))
            started = True
        typer.echo(stream_line(event_row(event)))
    if not started:
        typer.echo(stream_line(LIST_COLUMNS))


def list_json(events: Iterable[AuditEvent]) -> None:
    """Every event as one json list. A page that fails prints the error as the only document,
    with the number of events fetched so far under ``details.partial_rows``."""
    payloads: list[dict[str, Any]] = []
    try:
        for event in events:
            payloads.append(event_payload(event))
    except (SandfortSDKError, CliError) as exc:
        document = error_payload(exc)
        error = document["error"]
        details = error.get("details")
        known = details if isinstance(details, dict) else {}
        error["details"] = {**known, "partial_rows": len(payloads)}
        print_json(document)
        raise typer.Exit(EXIT_FAILURE) from None
    print_json(payloads)


@audit_app.command("list", epilog=LIST_EPILOG, cls=SingleValueCommand)
def list_events(
    ctx: typer.Context,
    actor: Annotated[str | None, typer.Option("--actor", help="Actor id.")] = None,
    action: Annotated[str | None, typer.Option("--action", help="Action name.")] = None,
    target: Annotated[str | None, typer.Option("--target", help="Target id.")] = None,
    request_id: Annotated[str | None, typer.Option("--request-id", help="Request id.")] = None,
    outcome: Annotated[str | None, typer.Option("--outcome", help="Outcome.")] = None,
    from_: Annotated[str | None, typer.Option("--from", help=FROM_HELP)] = None,
    to: Annotated[str | None, typer.Option("--to", help=TO_HELP)] = None,
    order: Annotated[
        OrderChoice,
        typer.Option(
            "--order",
            parser=parse_order,
            metavar=ORDER_METAVAR,
            help="newest first (default) or oldest first; desc and asc are aliases.",
        ),
    ] = OrderChoice.NEWEST,
    limit: Annotated[
        int, typer.Option("--limit", min=MIN_LIMIT, max=MAX_LIMIT, help="Events per page.")
    ] = DEFAULT_LIMIT,
    cursor: Annotated[str | None, typer.Option("--cursor", help="Continue after a cursor.")] = None,
    all_pages: Annotated[
        bool, typer.Option("--all", help="Page through every event (not with --cursor).")
    ] = False,
) -> None:
    """List audit events (newest first by default).

    With --json, one page prints {"events": [...], "next_cursor": <cursor or null>}; with
    --all, a plain list of every event.
    """
    for value, option in (
        (actor, "--actor"),
        (action, "--action"),
        (target, "--target"),
        (request_id, "--request-id"),
        (cursor, "--cursor"),
    ):
        reject_unusable(value, option)
    check_outcome(outcome)
    if all_pages and cursor is not None:
        raise typer.BadParameter("cannot be combined with --all", param_hint="--cursor")
    since, until = parse_moment(from_, "--from"), parse_moment(to, "--to")
    check_period(since, until)
    sort = API_ORDER[order]
    filters: dict[str, Any] = {
        "actor_id": actor, "action": action, "target_id": target, "request_id": request_id,
        "outcome": outcome, "from_": since, "to": until, "order": sort, "limit": limit,
    }  # fmt: skip
    state = app_state(ctx)
    with cli_errors(), open_client() as client:
        if all_pages:
            events = client.audit.iter(**filters)
            (list_json if state.json_output else stream_rows)(events)
            return
        page = client.audit.list(cursor=cursor, **filters)
        render_page(state, list(page.events), page.next_cursor)


def verify_payload(result: AuditVerifyResult) -> dict[str, Any]:
    """The verify result for ``--json`` (``reanchor.occurred_at`` as ISO 8601)."""
    payload: dict[str, Any] = {
        "ok": result.ok,
        "checked": result.checked,
        "first_id": result.first_id,
        "last_id": result.last_id,
        "last_hash": result.last_hash,
        "findings": [
            {"kind": f.kind, "event_id": f.event_id, "detail": f.detail} for f in result.findings
        ],
        "findings_truncated": result.findings_truncated,
        "anchor_id": result.anchor_id,
        "acknowledged_findings": result.acknowledged_findings,
        "reanchored_by": result.reanchored_by,
        "reanchor": None,
    }
    anchor = result.reanchor
    if anchor is not None:
        payload["reanchor"] = {
            "event_id": anchor.event_id,
            "acknowledged_through": anchor.acknowledged_through,
            "occurred_at": anchor.occurred_at.isoformat(),
            "operator": anchor.operator,
            "reason_code": anchor.reason_code,
            "note": anchor.note,
            "findings": anchor.findings,
        }
    cleaned: dict[str, Any] = clean_strings(payload, caller_key())
    return cleaned


def render_verify(state: AppState, result: AuditVerifyResult) -> None:
    if state.json_output:
        print_json(verify_payload(result))
        return
    fields = {
        "ok": str(result.ok).lower(),
        "checked": str(result.checked),
        "first_id": _cell(result.first_id),
        "last_id": _cell(result.last_id),
        "last_hash": _cell(result.last_hash),
        "findings": str(len(result.findings)),
        "findings_truncated": str(result.findings_truncated).lower(),
        "anchor_id": _cell(result.anchor_id),
        "acknowledged_findings": str(result.acknowledged_findings),
        "reanchored_by": _cell(result.reanchored_by),
    }
    print_fields("audit chain", fields)
    if result.findings:
        rows = [(_cell(f.kind), _cell(f.event_id), _cell(f.detail)) for f in result.findings]
        print_table("findings", FINDING_COLUMNS, rows)


@audit_app.command("verify", cls=SingleValueCommand)
def verify(
    ctx: typer.Context,
    from_id: Annotated[
        str | None, typer.Option("--from-id", help="Start the walk at this event id.")
    ] = None,
) -> None:
    """Verify the audit hash chain (exit 3 when the chain is broken)."""
    reject_unusable(from_id, "--from-id")
    with cli_errors(), open_client() as client:
        result = client.audit.verify(from_id)
        render_verify(app_state(ctx), result)
    if not result.ok:
        raise typer.Exit(EXIT_BROKEN_CHAIN)


def head_record(line: str) -> dict[str, Any] | None:
    """The fields of ``line`` when it is an ``audit_head`` JSON object; else ``None``."""
    try:
        record = json.loads(line)
    except (ValueError, RecursionError):
        return None
    return record if isinstance(record, dict) and record.get("type") == HEAD_TYPE else None


register_verify_head(audit_app)


class TrailerWatch:
    """Passes export lines through and keeps the last non-blank one (the trailer)."""

    def __init__(self) -> None:
        self.last = ""

    def watch(self, lines: Iterable[str]) -> Iterator[str]:
        for line in lines:
            if line.strip():
                self.last = line
            yield line

    def has_trailer(self) -> bool:
        """Whether the last non-blank line is an ``audit_head`` or ``export_summary`` object."""
        try:
            record = json.loads(self.last)
        except (ValueError, RecursionError):
            return False
        return isinstance(record, dict) and record.get("type") in TRAILER_TYPES

    def check(self) -> None:
        """An export that ended without a trailer may be cut short: warn and exit 3."""
        if not self.has_trailer():
            typer.echo(f"warning: {NO_TRAILER_WARNING}", err=True)
            raise typer.Exit(EXIT_NO_TRAILER)

    def note(self) -> None:
        """One stderr line naming the signing key when the trailer is a signed head."""
        record = head_record(self.last)
        if record is None or not record.get("signature"):
            return
        key = record.get("public_key")
        fingerprint = key_fingerprint(key) if isinstance(key, str) else None
        if fingerprint is not None:
            typer.echo(
                f"audit head signed with Ed25519 key fingerprint {fingerprint} "
                "(check it with: sandfort audit verify-head <file>)",
                err=True,
            )


def tilde_hint(output: str | None) -> ErrorHint:
    """The hint for a failed write to a quoted ``~`` path (the shell did not expand it)."""

    def hint(exc: SandfortSDKError | CliError) -> str | None:
        if output is None or not (output == "~" or output.startswith("~/")):
            return None
        if not isinstance(exc, CliError) or not str(exc).startswith("cannot write"):
            return None
        rest = output[2:] if output.startswith("~/") else ""
        home = f"$HOME/{rest}" if rest else "$HOME"
        return f"hint: the shell did not expand ~; use {home} or an unquoted ~"

    return hint


def output_target(output: str | None, force: bool) -> str | None:
    """``--output`` as a file name; ``None`` for standard output (no option, or ``-``)."""
    if output is not None and not output.strip():
        raise typer.BadParameter("--output needs a file name")
    if output is None or output == STDOUT_NAME:
        if force:
            raise typer.BadParameter("--force needs --output with a file name")
        return None
    reject_unusable(output, "--output")
    return output


@audit_app.command("export", cls=SingleValueCommand)
def export(
    ctx: typer.Context,
    from_: Annotated[str | None, typer.Option("--from", help=FROM_HELP)] = None,
    to: Annotated[str | None, typer.Option("--to", help=TO_HELP)] = None,
    request_id: Annotated[str | None, typer.Option("--request-id", help="Request id.")] = None,
    outcome: Annotated[str | None, typer.Option("--outcome", help="Outcome.")] = None,
    output: Annotated[
        str | None,
        typer.Option("--output", help="Write to this file (mode 600); - or no --output is stdout."),
    ] = None,
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing --output.")] = False,
) -> None:
    """Export events as newline-delimited JSON, exactly as the server sends them.

    Lines are written as they arrive to a temporary file that replaces --output only when the
    export is complete; a failed or interrupted export leaves an existing --output untouched.
    A symlink is followed (its target is replaced, the link kept); a device or fifo is
    written directly. When the trailer is a signed audit_head, one stderr note names the
    signing key's fingerprint (first 16 hex characters of sha256 over the raw public key).
    An export that ends without a trailer line (audit_head or export_summary) may be cut
    short: a warning on stderr and exit 3 (the lines received are still written).
    """
    reject_unusable(request_id, "--request-id")
    check_outcome(outcome)
    name = output_target(output, force)
    since, until = parse_moment(from_, "--from"), parse_moment(to, "--to")
    check_period(since, until)
    trailer = TrailerWatch()
    with cli_errors(hint=tilde_hint(name)):
        target = None if name is None else plan_target(Path(name), force=force)
        with open_client() as client:
            lines = trailer.watch(
                client.audit.export_lines(
                    request_id=request_id, outcome=outcome, from_=since, to=until
                )
            )
            if target is None:
                for line in lines:
                    sys.stdout.write(line)
                trailer.note()
                trailer.check()
                return
            size = write_export(target, lines, force=force)
        trailer.note()
        shown_name = shown(str(target.path), caller_key())
        message = f"wrote {size} bytes to {shown_name}"
        render_message(app_state(ctx), message, {"output": shown_name, "bytes": size})
        trailer.check()
