"""``sandbox resize``: change the CPU, memory or disk of a stopped sandbox.

Importing this module registers the command on the ``sandbox`` group (``main`` imports it once,
before the application is built).
"""

from typing import Annotated

import typer

from sandfort_cli.config import open_client
from sandfort_cli.output import app_state, reject_empty_name
from sandfort_cli.refs import resolve_sandbox_id
from sandfort_cli.sandboxes import (
    INTEGER_METAVAR,
    SANDBOX_METAVAR,
    SandboxId,
    parse_optional_whole_number,
    ref_errors,
    render_sandbox,
    sandbox_app,
)

NOTHING_TO_RESIZE = "nothing to resize: pass --cpu-millicores, --memory-mib or --disk-gib"


@sandbox_app.command("resize")
def resize(
    ctx: typer.Context,
    sandbox_id: SandboxId,
    cpu_text: Annotated[
        str | None,
        typer.Option("--cpu-millicores", metavar=INTEGER_METAVAR, help="CPU in millicores."),
    ] = None,
    memory_text: Annotated[
        str | None, typer.Option("--memory-mib", metavar=INTEGER_METAVAR, help="Memory in MiB.")
    ] = None,
    disk_text: Annotated[
        str | None, typer.Option("--disk-gib", metavar=INTEGER_METAVAR, help="Disk in GiB.")
    ] = None,
) -> None:
    """Change the resources of a stopped sandbox (fields left out keep their value)."""
    reject_empty_name(sandbox_id, SANDBOX_METAVAR)
    cpu_millicores = parse_optional_whole_number(cpu_text, "--cpu-millicores")
    memory_mib = parse_optional_whole_number(memory_text, "--memory-mib")
    disk_gib = parse_optional_whole_number(disk_text, "--disk-gib")
    if cpu_millicores is None and memory_mib is None and disk_gib is None:
        raise typer.BadParameter(NOTHING_TO_RESIZE)
    with ref_errors(), open_client() as client:
        sandbox = client.get(resolve_sandbox_id(client, sandbox_id))
        resized = sandbox.resize(
            cpu_millicores=cpu_millicores, memory_mib=memory_mib, disk_gib=disk_gib
        )
        render_sandbox(app_state(ctx), resized.info)
