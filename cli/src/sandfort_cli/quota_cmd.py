"""The ``quota`` command: the caller's own quota view over ``client.quota``.

An org-wide key sees the org's limits next to what is reserved. A key limited to labelled
sandboxes sees the org's limits, the reservation of its own sandboxes only, and a second table
with its own cap, the live sandboxes of its scope and how many it may still create.
"""

from dataclasses import asdict

import typer
from sandfort_sdk.quota import QuotaSnapshot

from sandfort_cli.config import open_client
from sandfort_cli.output import (
    AppState,
    app_state,
    clean_strings,
    cli_errors,
    labels_cell,
    print_json,
    print_table,
)
from sandfort_cli.sandboxes import JSON_ERROR_EPILOG
from sandfort_cli.sanitise import caller_key

UNLIMITED_CELL = "unlimited"
NO_CAP_CELL = "no cap"
RESOURCE_COLUMNS = ("RESOURCE", "LIMIT", "RESERVED")
SCOPE_COLUMNS = ("LABELS", "CAP", "IN SCOPE", "REMAINING")
QUOTA_EPILOG = (
    'With --json it prints {"limits", "reserved", "scope"}: "scope" is null for an org-wide key. '
    'For a key limited to labelled sandboxes, "reserved" covers only the sandboxes of its '
    'scope and "scope" holds {"labels", "max_sandboxes", "sandboxes", "remaining"}. '
    f"{JSON_ERROR_EPILOG}"
)


def amount(value: float | int | None) -> str:
    """A limit or total without a trailing ``.0``; ``unlimited`` when there is no limit."""
    if value is None:
        return UNLIMITED_CELL
    return str(int(value)) if float(value).is_integer() else f"{value:g}"


def snapshot_payload(snapshot: QuotaSnapshot) -> dict[str, object]:
    return asdict(snapshot)


def resource_rows(snapshot: QuotaSnapshot) -> list[tuple[str, str, str]]:
    limits, held = snapshot.limits, snapshot.reserved
    return [
        ("vcpus", amount(limits.max_vcpus), amount(held.vcpus)),
        ("memory_mib", amount(limits.max_memory_mib), amount(held.memory_mib)),
        ("disk_gib", amount(limits.max_disk_gib), amount(held.disk_gib)),
        ("sandboxes", amount(limits.max_sandboxes), amount(held.sandboxes)),
    ]


def render(state: AppState, snapshot: QuotaSnapshot) -> None:
    if state.json_output:
        print_json(clean_strings(snapshot_payload(snapshot), caller_key()))
        return
    scoped = snapshot.scope is not None
    title = "quota (org limits, your scope's reservation)" if scoped else "quota"
    print_table(title, RESOURCE_COLUMNS, resource_rows(snapshot), free=())
    scope = snapshot.scope
    if scope is None:
        return
    cap = NO_CAP_CELL if scope.max_sandboxes is None else str(scope.max_sandboxes)
    remaining = "-" if scope.remaining is None else str(scope.remaining)
    row = (labels_cell(scope.labels), cap, str(scope.sandboxes), remaining)
    print_table("your key", SCOPE_COLUMNS, [row], free=("LABELS",))


def quota_command(ctx: typer.Context) -> None:
    """Show the quota view of the API key in use.

    An org-wide key sees the org limits and what is reserved. A key limited to labelled
    sandboxes sees the org limits, its own reservation, its sandbox cap and its live count.
    """
    state = app_state(ctx)
    with cli_errors(), open_client() as client:
        render(state, client.quota.get())
