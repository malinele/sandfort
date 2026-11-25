"""``sandbox egress``: replace or show the egress allowlist of a sandbox.

Importing this module registers the ``egress`` group on the ``sandbox`` group (``main`` imports
it once, before the application is built).
"""

from typing import Annotated, Any

import typer
from sandfort_sdk import SandboxInfo

from sandfort_cli.config import open_client
from sandfort_cli.output import (
    AppState,
    app_state,
    clean_strings,
    print_fields,
    print_json,
    reject_empty_name,
    reject_empty_options,
    shown,
)
from sandfort_cli.refs import resolve_sandbox_id
from sandfort_cli.sandboxes import (
    JSON_ERROR_EPILOG,
    SANDBOX_METAVAR,
    SandboxId,
    ref_errors,
    sandbox_app,
)
from sandfort_cli.sanitise import caller_key

EXACTLY_ONE = "pass exactly one of --allow and --deny-all"
NO_ALLOWLIST = "no allowlist"
BLOCKED = "empty, all connections blocked"

egress_app = typer.Typer(
    name="egress",
    help="Manage the egress allowlist.",
    epilog=JSON_ERROR_EPILOG,
    no_args_is_help=True,
)
sandbox_app.add_typer(egress_app)


def egress_payload(info: SandboxInfo) -> dict[str, Any]:
    """The ``--json`` view: id, allowlist (null when the sandbox has none) and generation."""
    allowlist = None if info.egress_allowlist is None else list(info.egress_allowlist)
    payload = {
        "id": info.id,
        "egress_allowlist": allowlist,
        "egress_policy_generation": info.egress_policy_generation,
    }
    cleaned: dict[str, Any] = clean_strings(payload, caller_key())
    return cleaned


def render_egress(state: AppState, info: SandboxInfo) -> None:
    """The allowlist and its generation, as a table or as one json object."""
    if state.json_output:
        print_json(egress_payload(info))
        return
    key = caller_key()
    if info.egress_allowlist is None:
        allowlist = NO_ALLOWLIST
    elif not info.egress_allowlist:
        allowlist = BLOCKED
    else:
        allowlist = "\n".join(shown(entry, key) for entry in info.egress_allowlist)
    fields = {
        "id": info.id,
        "egress_allowlist": allowlist,
        "egress_policy_generation": str(info.egress_policy_generation),
    }
    print_fields("egress", fields, folded=("egress_allowlist",))


@egress_app.command("set")
def egress_set(
    ctx: typer.Context,
    sandbox_id: SandboxId,
    allow: Annotated[
        list[str] | None,
        typer.Option("--allow", metavar="ENTRY", help="Allow this host or CIDR (repeatable)."),
    ] = None,
    deny_all: Annotated[
        bool, typer.Option("--deny-all", help="Block every outbound connection.")
    ] = False,
) -> None:
    """Replace the egress allowlist.

    The server stores the list at once and the egress proxy applies it within its cache window.
    """
    reject_empty_name(sandbox_id, SANDBOX_METAVAR)
    reject_empty_options(allow, "--allow")
    if bool(allow) == deny_all:
        raise typer.BadParameter(EXACTLY_ONE)
    entries = [] if deny_all else list(allow or ())
    with ref_errors(), open_client() as client:
        updated = client.set_egress_allowlist(resolve_sandbox_id(client, sandbox_id), entries)
        render_egress(app_state(ctx), updated.info)


@egress_app.command("show")
def egress_show(ctx: typer.Context, sandbox_id: SandboxId) -> None:
    """Show the egress allowlist."""
    reject_empty_name(sandbox_id, SANDBOX_METAVAR)
    with ref_errors(), open_client() as client:
        sandbox = client.get(resolve_sandbox_id(client, sandbox_id))
        render_egress(app_state(ctx), sandbox.info)
