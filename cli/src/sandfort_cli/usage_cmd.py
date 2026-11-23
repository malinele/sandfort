"""The ``usage`` command: the org usage report over ``client.usage``."""

import math
import shlex
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Annotated, Any

import typer
from sandfort_sdk.audit import MAX_LIMIT, MIN_LIMIT
from sandfort_sdk.usage import (
    GROUP_BY_HELP,
    GROUP_BY_LABEL_PREFIX,
    GROUP_BY_SANDBOX,
    UsageGroup,
    UsageTotal,
)

from sandfort_cli.audit import DATE_HELP, parse_moment, reject_unusable
from sandfort_cli.config import open_client
from sandfort_cli.output import (
    AppState,
    app_state,
    clean_strings,
    cli_errors,
    labels_cell,
    print_json,
    print_table,
    shown,
)
from sandfort_cli.sandboxes import JSON_ERROR_EPILOG, echo_value
from sandfort_cli.sanitise import caller_key

NONE_CELL = "-"
UNLABELED_CELL = "(unlabeled)"
TOTAL_COLUMNS = ("DIMENSION", "UNIT", "TOTAL")
SANDBOX_COLUMNS = ("SANDBOX", "NAME", "LABELS")
LABEL_COLUMNS = ("LABEL", "VALUE")
AMOUNT_DECIMALS = 2
NEXT_PAGE_PREFIX = "sandfort usage"
USAGE_EPILOG = (
    "Without --group-by the report is the org totals. With --json both forms print "
    '{"from", "to", "group_by", "groups", "totals", "next_cursor"}; without --group-by '
    '"groups": [] and "next_cursor": null. On a grouped page "totals" sums the groups printed '
    f"(every group with --all), rounded to {AMOUNT_DECIMALS} decimals. A cursor belongs to "
    "its period: --cursor needs explicit --from and --to, and a page with more groups prints "
    "the command for the next page on stderr. Amounts are allocated resource time per "
    f"dimension, not a bill. {JSON_ERROR_EPILOG}"
)


def utc_now() -> datetime:
    return datetime.now(UTC)


def month_start(moment: datetime) -> datetime:
    """Midnight UTC of the first day of the month that holds ``moment``."""
    return moment.astimezone(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def resolve_period(from_: str | None, to: str | None) -> tuple[datetime, datetime]:
    """The report period: ``--to`` defaults to now, ``--from`` to the start of its UTC month."""
    until = parse_moment(to, "--to") or utc_now()
    since = parse_moment(from_, "--from") or month_start(until)
    if since > until:
        raise typer.BadParameter("must not be later than --to", param_hint="--from")
    return since, until


def parse_group_by(value: str | None) -> str | None:
    """``sandbox`` or ``label:<key>``; anything else is a usage error (exit 2)."""
    if value is None:
        return None
    reject_unusable(value, "--group-by")
    key = value[len(GROUP_BY_LABEL_PREFIX) :]
    if value == GROUP_BY_SANDBOX or (value.startswith(GROUP_BY_LABEL_PREFIX) and key.strip()):
        return value
    raise typer.BadParameter(
        f"expected {GROUP_BY_HELP}; got {echo_value(value)}", param_hint="--group-by"
    )


def check_paging(
    group_by: str | None, cursor: str | None, limit: int | None, all_pages: bool
) -> None:
    """Paging options need ``--group-by``; ``--all`` and ``--cursor`` exclude each other."""
    reject_unusable(cursor, "--cursor")
    if group_by is None:
        for used, option in ((all_pages, "--all"), (cursor, "--cursor"), (limit, "--limit")):
            if used not in (None, False):
                raise typer.BadParameter("needs --group-by", param_hint=option)
    if all_pages and cursor is not None:
        raise typer.BadParameter("cannot be combined with --all", param_hint="--cursor")


def check_cursor_period(cursor: str | None, from_: str | None, to: str | None) -> None:
    """A cursor is bound to its period, so ``--cursor`` needs ``--from`` and ``--to`` given
    (``--to`` would otherwise default to a new "now" and the server refuses the cursor)."""
    if cursor is not None and (from_ is None or to is None):
        raise typer.BadParameter(
            "needs explicit --from and --to (the period of the page the cursor came from)",
            param_hint="--cursor",
        )


def next_page_command(
    period: tuple[datetime, datetime], group_by: str, cursor: str, limit: int | None
) -> str:
    """The shell command that fetches the page after this one, with the period pinned."""
    words = [
        "--from", period[0].isoformat(), "--to", period[1].isoformat(),
        "--group-by", group_by, "--cursor", shown(cursor, caller_key()),
    ]  # fmt: skip
    if limit is not None:
        words += ["--limit", str(limit)]
    return " ".join([NEXT_PAGE_PREFIX, *(shlex.quote(word) for word in words)])


def cell(value: object) -> str:
    """One server value for a table cell: sanitised; ``-`` when absent or empty."""
    return NONE_CELL if value is None else shown(value, caller_key()) or NONE_CELL


def amount(value: float) -> str:
    """A total with at most two decimals and no trailing zeros; never ``-0``."""
    text = f"{value:.{AMOUNT_DECIMALS}f}".rstrip("0").rstrip(".")
    return "0" if text in ("", "-0") else text


def rounded(value: float) -> float:
    """``value`` at the precision the table shows; ``0.0`` rather than ``-0.0``."""
    return round(value, AMOUNT_DECIMALS) or 0.0


def sum_totals(groups: Sequence[UsageGroup]) -> list[UsageTotal]:
    """The groups' totals added per (dimension, unit) with ``math.fsum``, rounded to the shown
    precision, in order of first appearance."""
    parts: dict[tuple[str, str], list[float]] = {}
    for group in groups:
        for item in group.totals:
            parts.setdefault((item.dimension, item.unit), []).append(item.total)
    return [
        UsageTotal(dimension, unit, rounded(math.fsum(values)))
        for (dimension, unit), values in parts.items()
    ]


def dimensions(groups: Sequence[UsageGroup]) -> list[tuple[str, str]]:
    """The (dimension, unit) pairs of the groups, in order of first appearance."""
    seen: dict[tuple[str, str], None] = {}
    for group in groups:
        for item in group.totals:
            seen.setdefault((item.dimension, item.unit), None)
    return list(seen)


def total_payload(item: UsageTotal) -> dict[str, Any]:
    return {"dimension": item.dimension, "unit": item.unit, "total": item.total}


def group_payload(group: UsageGroup) -> dict[str, Any]:
    return {
        "group_key": group.group_key,
        "group_value": group.group_value,
        "name": group.name,
        "labels": group.labels,
        "totals": [total_payload(item) for item in group.totals],
    }


def totals_table(title: str, totals: Sequence[UsageTotal]) -> None:
    rows = [(cell(t.dimension), cell(t.unit), amount(t.total)) for t in totals]
    print_table(title, TOTAL_COLUMNS, rows, free=())


def group_cells(group: UsageGroup, by_label: bool) -> tuple[str, ...]:
    """The leading cells of a group row: key and value, or sandbox id, name and labels."""
    if by_label:
        value = UNLABELED_CELL if group.group_value is None else cell(group.group_value)
        return (cell(group.group_key), value)
    labels = labels_cell(group.labels) if group.labels else NONE_CELL
    return (cell(group.group_value), cell(group.name), labels)


def groups_table(group_by: str, groups: Sequence[UsageGroup]) -> None:
    by_label = group_by != GROUP_BY_SANDBOX
    pairs = dimensions(groups)
    heads = tuple(shown(f"{dim.upper()} ({unit})", caller_key()) for dim, unit in pairs)
    rows = []
    for group in groups:
        found = {(t.dimension, t.unit): amount(t.total) for t in group.totals}
        rows.append((*group_cells(group, by_label), *(found.get(p, NONE_CELL) for p in pairs)))
    columns = (LABEL_COLUMNS if by_label else SANDBOX_COLUMNS) + heads
    free = ("VALUE",) if by_label else ("LABELS", "NAME")
    print_table(f"usage by {shown(group_by, caller_key())}", columns, rows, free=free)


def render_totals(
    state: AppState, period: tuple[datetime, datetime], totals: Sequence[UsageTotal]
) -> None:
    if state.json_output:
        payload = {
            "from": period[0].isoformat(), "to": period[1].isoformat(), "group_by": None,
            "groups": [],
            "totals": [total_payload(item) for item in totals],
            "next_cursor": None,
        }  # fmt: skip
        print_json(clean_strings(payload, caller_key()))
        return
    totals_table("usage totals", totals)


def render_groups(
    state: AppState,
    period: tuple[datetime, datetime],
    group_by: str,
    groups: Sequence[UsageGroup],
    next_cursor: str | None,
    limit: int | None = None,
    note: str | None = None,
) -> None:
    summed = sum_totals(groups)
    if state.json_output:
        payload = {
            "from": period[0].isoformat(), "to": period[1].isoformat(), "group_by": group_by,
            "groups": [group_payload(group) for group in groups],
            "totals": [total_payload(item) for item in summed],
            "next_cursor": next_cursor,
        }  # fmt: skip
        if note is not None:  # additive: the key exists only when the server sent a note
            payload["note"] = note
        print_json(clean_strings(payload, caller_key()))
        return
    groups_table(group_by, groups)
    if summed:
        totals_table("totals (groups shown)", summed)
    if next_cursor is not None:
        typer.echo(f"next cursor: {shown(next_cursor, caller_key())}", err=True)
        command = next_page_command(period, group_by, next_cursor, limit)
        typer.echo(f"next page: {command}", err=True)
    if note is not None:
        typer.echo(f"note: {shown(note, caller_key())}", err=True)


def collect_pages(
    client: Any, period: tuple[datetime, datetime], group_by: str, limit: int | None
) -> tuple[list[UsageGroup], str | None]:
    """Every group of the report page by page, and the first server note (``--all``)."""
    groups: list[UsageGroup] = []
    note: str | None = None
    cursor: str | None = None
    while True:
        page = client.usage.get(
            from_=period[0], to=period[1], group_by=group_by, cursor=cursor, limit=limit
        )
        groups.extend(page.groups)
        note = note or page.note
        if page.next_cursor is None or page.next_cursor == cursor:
            return groups, note
        cursor = page.next_cursor


def usage_command(
    ctx: typer.Context,
    from_: Annotated[
        str | None, typer.Option("--from", help=f"Period start. {DATE_HELP}")
    ] = None,
    to: Annotated[str | None, typer.Option("--to", help=f"Period end. {DATE_HELP}")] = None,
    group_by: Annotated[
        str | None, typer.Option("--group-by", help=f"Group by {GROUP_BY_HELP}.")
    ] = None,
    limit: Annotated[
        int | None, typer.Option("--limit", min=MIN_LIMIT, max=MAX_LIMIT, help="Groups per page.")
    ] = None,
    cursor: Annotated[
        str | None,
        typer.Option("--cursor", help="Continue after a cursor (needs --from and --to)."),
    ] = None,
    all_pages: Annotated[
        bool, typer.Option("--all", help="Page through every group (needs --group-by).")
    ] = False,
) -> None:
    """Show the org usage report for a period.

    The period defaults to the current UTC month so far. Without --group-by the report is
    the org totals; with it, one row per sandbox or per label value, plus their sum.
    """
    grouping = parse_group_by(group_by)
    check_paging(grouping, cursor, limit, all_pages)
    check_cursor_period(cursor, from_, to)
    since, until = resolve_period(from_, to)
    period = (since, until)
    state = app_state(ctx)
    with cli_errors(), open_client() as client:
        if grouping is None:
            render_totals(state, period, client.usage.get(from_=since, to=until).totals)
        elif all_pages:
            groups, note = collect_pages(client, period, grouping, limit)
            render_groups(state, period, grouping, groups, None, note=note)
        else:
            page = client.usage.get(
                from_=since, to=until, group_by=grouping, cursor=cursor, limit=limit
            )
            render_groups(
                state, period, grouping, page.groups, page.next_cursor, limit, page.note
            )
