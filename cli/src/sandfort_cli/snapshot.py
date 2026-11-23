"""The ``snapshot`` command group (register, create, list, get, rm, export, build)."""

import json
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any

import typer
from sandfort_sdk import BuildLogEvent, Client, SnapshotInfo

from sandfort_cli.config import open_client
from sandfort_cli.output import (
    LABELS_FIELD,
    AppState,
    CliError,
    app_state,
    clean_strings,
    cli_errors,
    exact_labels,
    labels_cell,
    labels_lines,
    print_fields,
    print_json,
    print_table,
    reject_empty_name,
    reject_empty_option,
    scalar_text,
    shown,
    strip_dangerous_terminal,
)
from sandfort_cli.refs import resolve_sandbox_id
from sandfort_cli.sandboxes import JSON_ERROR_EPILOG, SANDBOX_METAVAR, parse_pairs, ref_errors
from sandfort_cli.sanitise import caller_key

PENDING = "pending"
READY = "ready"
FINAL_EVENT = "state"
# Shown for a hidden image_ref or digest (the server answers null to a label-scoped key).
NULL_CELL = "-"

snapshot_app = typer.Typer(
    name="snapshot",
    help="Manage snapshots and image builds.",
    epilog=JSON_ERROR_EPILOG,
    no_args_is_help=True,
)

SNAPSHOT_ID_METAVAR = "<snapshot-id>"
NAME_METAVAR = "<name>"
IMAGE_METAVAR = "<image>"
NAME_OPTION = "--name"
OUTPUT_OPTION = "--output"
SnapshotId = Annotated[str, typer.Argument(metavar=SNAPSHOT_ID_METAVAR, help="Snapshot id.")]
LABEL_OPTION = "--label"
SnapshotName = Annotated[str | None, typer.Option(NAME_OPTION, "-n", help="Snapshot name.")]
CreateLabels = Annotated[
    list[str] | None,
    typer.Option(LABEL_OPTION, "-l", help="Label as KEY=VALUE (repeatable)."),
]
FilterLabels = Annotated[
    list[str] | None,
    typer.Option(LABEL_OPTION, "-l", help="Only snapshots with label KEY=VALUE (repeatable)."),
]


def snapshot_payload(info: SnapshotInfo) -> dict[str, Any]:
    """The snapshot object for ``--json``: server strings sanitised like the sandbox views."""
    payload = {**asdict(info), "created_at": info.created_at.isoformat()}
    cleaned: dict[str, Any] = clean_strings(payload, caller_key())
    cleaned["labels"] = exact_labels(cleaned.get("labels"), info.labels)
    return cleaned


def snapshot_fields(info: SnapshotInfo) -> dict[str, str]:
    key = caller_key()
    fields = {
        "id": shown(info.id, key),
        "name": shown(info.name, key),
        "state": shown(info.state, key),
        "image_ref": shown(info.image_ref, key) if info.image_ref else NULL_CELL,
        "digest": shown(info.digest, key) if info.digest else NULL_CELL,
        "layer_count": scalar_text(info.layer_count, key),
        LABELS_FIELD: labels_lines(info.labels),
        "created_at": info.created_at.isoformat(),
    }
    if info.source_sandbox_id:
        fields["source_sandbox_id"] = shown(info.source_sandbox_id, key)
    if info.spec_hash:
        fields["spec_hash"] = shown(info.spec_hash, key)
    return fields


def render_snapshot(state: AppState, info: SnapshotInfo) -> None:
    if state.json_output:
        print_json(snapshot_payload(info))
    else:
        print_fields("snapshot", snapshot_fields(info), folded=(LABELS_FIELD,))


def render_snapshots(state: AppState, infos: Sequence[SnapshotInfo]) -> None:
    if state.json_output:
        print_json([snapshot_payload(info) for info in infos])
        return
    key = caller_key()
    rows = [
        (
            shown(info.id, key),
            shown(info.name, key),
            shown(info.state, key),
            shown(info.image_ref, key) if info.image_ref else NULL_CELL,
            labels_cell(info.labels),
        )
        for info in infos
    ]
    print_table("snapshots", ("ID", "NAME", "STATE", "IMAGE", "LABELS"), rows)


def read_spec(path: Path) -> dict[str, Any]:
    """The image spec json object in ``path`` (the server validates its content).

    Read before the build request, so every failure here is a client error.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        message = f"cannot read spec file {path}: {exc.strerror or exc}"
        raise CliError(message, client=True) from None
    except ValueError:
        raise CliError(f"spec file {path} is not valid json", client=True) from None
    if not isinstance(raw, dict):
        raise CliError(f"spec file {path} must hold a json object", client=True)
    return raw


def follow_build(client: Client, info: SnapshotInfo, *, echo_lines: bool) -> BuildLogEvent:
    """Stream the build log until the final ``state`` event and return that event.

    Log lines are program output: only dangerous terminal sequences are removed (the same strip
    the exec relay uses); nothing is masked, reshaped or cut. A stream that ends early raises
    ``TransportError``, which ``cli_errors`` reports.
    """
    with client.snapshots.follow_build_logs(info.id) as stream:
        for event in stream:
            if event.is_final:
                return event
            if echo_lines:
                typer.echo(strip_dangerous_terminal(event.line))
    raise CliError(f"build log of {info.id} ended without a final state")


def final_payload(final: BuildLogEvent) -> dict[str, Any]:
    return {"state": final.state, "digest": final.digest, "reason": final.reason}


def report_build(state: AppState, info: SnapshotInfo, final: BuildLogEvent) -> None:
    """Print the outcome; a build that did not end ready is a failure (exit status 1)."""
    key = caller_key()
    if state.json_output:
        combined = {**snapshot_payload(info), **clean_strings(final_payload(final), key)}
        print_json(combined)
    elif final.state == READY:
        reused = " (reused)" if info.reused else ""
        target = final.digest or info.image_ref or info.id
        typer.echo(f"build {shown(info.id, key)} ready{reused}: {shown(target, key)}")
    if final.state != READY:
        reason = f": {final.reason}" if final.reason else ""
        raise CliError(f"build {info.id} ended {final.state}{reason}")


@snapshot_app.command("register")
def register(
    ctx: typer.Context,
    image: Annotated[
        str, typer.Argument(metavar=IMAGE_METAVAR, help="Image reference, e.g. python:3.12-slim.")
    ],
    name: SnapshotName = None,
    label: CreateLabels = None,
) -> None:
    """Register an existing registry image as a snapshot."""
    reject_empty_name(image, IMAGE_METAVAR)
    if name is not None:
        reject_empty_name(name, NAME_OPTION)
    labels = parse_pairs(label, "label")
    with cli_errors(), open_client() as client:
        try:
            info = client.snapshots.register(image, name=name, labels=labels)
        except ValueError as exc:  # the SDK checks the labels before sending anything
            raise typer.BadParameter(str(exc), param_hint=LABEL_OPTION) from None
        render_snapshot(app_state(ctx), info)


@snapshot_app.command("create")
def create(
    ctx: typer.Context,
    sandbox_id: Annotated[
        str, typer.Argument(metavar=SANDBOX_METAVAR, help="Sandbox id or name to snapshot.")
    ],
    name: Annotated[str, typer.Argument(metavar=NAME_METAVAR, help="Snapshot name.")],
    wait: Annotated[
        bool, typer.Option("--wait", help="Block until the snapshot is ready.")
    ] = False,
    label: CreateLabels = None,
) -> None:
    """Create a snapshot from a sandbox (pending until the commit finishes)."""
    reject_empty_name(sandbox_id, SANDBOX_METAVAR)
    reject_empty_name(name, NAME_METAVAR)
    labels = parse_pairs(label, "label")
    with ref_errors(), open_client() as client:
        resolved_id = resolve_sandbox_id(client, sandbox_id)
        try:
            info = client.snapshots.create_from_sandbox(
                resolved_id, name, labels=labels, wait=wait
            )
        except ValueError as exc:  # the SDK checks the labels before sending anything
            raise typer.BadParameter(str(exc), param_hint=LABEL_OPTION) from None
        render_snapshot(app_state(ctx), info)


@snapshot_app.command("list")
def list_snapshots(ctx: typer.Context, label: FilterLabels = None) -> None:
    """List snapshots."""
    labels = parse_pairs(label, "label")
    with cli_errors(), open_client() as client:
        try:
            snapshots = list(client.snapshots.iter(labels=labels))
        except ValueError as exc:  # the SDK checks the labels before sending anything
            raise typer.BadParameter(str(exc), param_hint=LABEL_OPTION) from None
        render_snapshots(app_state(ctx), snapshots)


# `snapshot ls`: the same command as `list`, hidden from --help.
snapshot_app.command("ls", hidden=True)(list_snapshots)


@snapshot_app.command("get")
def get(ctx: typer.Context, snapshot_id: SnapshotId) -> None:
    """Show one snapshot."""
    reject_empty_name(snapshot_id, SNAPSHOT_ID_METAVAR)
    with cli_errors(), open_client() as client:
        render_snapshot(app_state(ctx), client.snapshots.get(snapshot_id))


@snapshot_app.command("rm")
def rm(ctx: typer.Context, snapshot_id: SnapshotId) -> None:
    """Delete a snapshot."""
    reject_empty_name(snapshot_id, SNAPSHOT_ID_METAVAR)
    with cli_errors(), open_client() as client:
        render_snapshot(app_state(ctx), client.snapshots.delete(snapshot_id))


# `snapshot delete`: the same command as `rm`, hidden from --help.
snapshot_app.command("delete", hidden=True)(rm)


@snapshot_app.command("export")
def export(
    ctx: typer.Context,
    snapshot_id: SnapshotId,
    output_text: Annotated[
        str,
        typer.Option(OUTPUT_OPTION, "-o", metavar="PATH", help="File to write the image tar to."),
    ],
) -> None:
    """Download a ready snapshot as an image tar (load it with: docker load -i FILE)."""
    reject_empty_name(snapshot_id, SNAPSHOT_ID_METAVAR)
    # Taken as text: typer would turn an empty path into ".", which is never a file to write.
    reject_empty_name(output_text, OUTPUT_OPTION)
    output = Path(output_text)
    state = app_state(ctx)
    with cli_errors(), open_client() as client:
        try:
            written = client.snapshots.export(snapshot_id, output)
        except OSError as exc:
            raise CliError(f"cannot write {output}: {exc.strerror or exc}") from None
        if state.json_output:
            print_json({"id": snapshot_id, "path": str(output), "bytes": written})
        else:
            typer.echo(f"exported {snapshot_id} to {output}: {written} bytes")


@snapshot_app.command("build")
def build(
    ctx: typer.Context,
    spec_file: Annotated[
        Path, typer.Argument(metavar="<spec-file>", help="Path to an image spec json file.")
    ],
    name: SnapshotName = None,
) -> None:
    """Build an image from a json spec, following the build log to its final state."""
    reject_empty_option(name, NAME_OPTION)
    state = app_state(ctx)
    with cli_errors(), open_client() as client:
        info = client.snapshots.build(read_spec(spec_file), name=name)
        if info.state == PENDING:
            final = follow_build(client, info, echo_lines=not state.json_output)
        else:  # reused: the identical spec was built before, nothing to follow
            final = BuildLogEvent(FINAL_EVENT, state=info.state, digest=info.digest)
        report_build(state, info, final)
