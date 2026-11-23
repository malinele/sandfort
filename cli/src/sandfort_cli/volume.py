"""The ``volume`` command group (create, list, get, rm, export, restore)."""

from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any

import typer
from sandfort_sdk import VolumeInfo

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
    scalar_text,
    shown,
)
from sandfort_cli.sandboxes import JSON_ERROR_EPILOG, parse_pairs
from sandfort_cli.sanitise import MAX_RAW_CHARS, caller_key
from sandfort_cli.volume_refs import volume_id_for_ref

volume_app = typer.Typer(
    name="volume",
    help="Manage persistent volumes.",
    epilog=JSON_ERROR_EPILOG,
    no_args_is_help=True,
)

VOLUME_ID_METAVAR = "<volume-id>"
NAME_METAVAR = "<name>"
LABEL_OPTION = "--label"
OUTPUT_OPTION = "--output"
VolumeRef = Annotated[
    str, typer.Argument(metavar=VOLUME_ID_METAVAR, help="Volume id (vol_...) or volume name.")
]


NO_LIMIT_TEXT = "none"
OVER_MARKER = "over"
BYTES_PER_UNIT = 1024
SIZE_UNITS = ("KiB", "MiB", "GiB", "TiB", "PiB", "EiB")


def volume_payload(info: VolumeInfo) -> dict[str, Any]:
    """The volume object for ``--json``: server strings sanitised like the sandbox views."""
    payload = {**asdict(info), "created_at": info.created_at.isoformat()}
    cleaned: dict[str, Any] = clean_strings(payload, caller_key())
    cleaned["labels"] = exact_labels(cleaned.get("labels"), info.labels)
    return cleaned


def human_size(count: int) -> str:
    """``count`` bytes in binary units: ``512 B``, ``1.5 KiB``, ``1.0 GiB``.

    The value is rounded to one decimal first and the unit picked from the rounded figure, so
    1048575 is ``1.0 MiB``, never ``1024.0 KiB``. EiB is the last unit: larger counts stay in
    EiB with thousands separators. Integer arithmetic only, so any size is exact.
    """
    if abs(count) < BYTES_PER_UNIT:
        return f"{count} B"
    sign = "-" if count < 0 else ""
    magnitude = abs(count)
    last = len(SIZE_UNITS)
    for index, unit in enumerate(SIZE_UNITS, start=1):
        scale = BYTES_PER_UNIT**index
        tenths = (magnitude * 20 + scale) // (2 * scale)  # round half up
        if tenths < BYTES_PER_UNIT * 10 or index == last:
            whole = f"{tenths // 10:,}" if index == last else str(tenths // 10)
            return f"{sign}{whole}.{tenths % 10} {unit}"
    raise AssertionError("unreachable: the last unit always returns")  # pragma: no cover


def raw_limit_text(info: VolumeInfo, key: str) -> str:
    """``max_bytes`` as ``--json`` shows it (raw bytes); the no-limit text only when null."""
    if info.max_bytes is None:
        return NO_LIMIT_TEXT
    return scalar_text(info.max_bytes, key)


def size_text(info: VolumeInfo, key: str) -> str:
    """The last sampled size exactly as ``--json`` shows it (blank until first sampled)."""
    return scalar_text(info.size_bytes, key)


def limit_text(info: VolumeInfo, key: str) -> str:
    """``max_bytes`` as a human size with the exact byte count; the no-limit text only when it
    is null (a zero limit is ``0 B (0 bytes)``, not "none")."""
    limit = info.max_bytes
    if limit is None:
        return NO_LIMIT_TEXT
    if isinstance(limit, bool) or not isinstance(limit, int):
        return scalar_text(limit, key)
    noun = "byte" if limit == 1 else "bytes"
    return f"{human_size(limit)} ({limit} {noun})"


def render_volume(state: AppState, info: VolumeInfo) -> None:
    if state.json_output:
        print_json(volume_payload(info))
        return
    key = caller_key()
    fields = {
        "id": shown(info.id, key),
        "name": shown(info.name, key),
        "state": shown(info.state, key),
        "size_bytes": size_text(info, key),
        "limit": limit_text(info, key),
        "over_limit": str(info.over_limit).lower(),
        LABELS_FIELD: labels_lines(info.labels),
        "created_at": info.created_at.isoformat(),
    }
    print_fields("volume", fields, folded=(LABELS_FIELD,))


def render_volumes(state: AppState, infos: Sequence[VolumeInfo]) -> None:
    if state.json_output:
        print_json([volume_payload(info) for info in infos])
        return
    key = caller_key()
    rows = [
        (
            shown(info.id, key),
            shown(info.name, key),
            shown(info.state, key),
            size_text(info, key),
            raw_limit_text(info, key),
            OVER_MARKER if info.over_limit else "",
            labels_cell(info.labels, MAX_RAW_CHARS),  # the layout cuts to the free width
        )
        for info in infos
    ]
    columns = ("ID", "NAME", "STATE", "SIZE (B)", "LIMIT (B)", "OVER", "LABELS")
    print_table("volumes", columns, rows)


@volume_app.command("create")
def create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(metavar=NAME_METAVAR, help="Volume name.")],
    label: Annotated[
        list[str] | None,
        typer.Option("--label", "-l", help="Label as KEY=VALUE (repeatable)."),
    ] = None,
) -> None:
    """Create a volume."""
    reject_empty_name(name, NAME_METAVAR)
    labels = parse_pairs(label, "label")
    with cli_errors(), open_client() as client:
        try:
            created = client.volumes.create(name, labels=labels)
        except ValueError as exc:  # the SDK checks the labels before sending anything
            raise typer.BadParameter(str(exc), param_hint=LABEL_OPTION) from None
        render_volume(app_state(ctx), created)


@volume_app.command("list")
def list_volumes(
    ctx: typer.Context,
    label: Annotated[
        list[str] | None,
        typer.Option("--label", "-l", help="Only volumes with label KEY=VALUE (repeatable)."),
    ] = None,
) -> None:
    """List volumes."""
    labels = parse_pairs(label, "label")
    with cli_errors(), open_client() as client:
        try:
            volumes = list(client.volumes.iter(labels=labels))
        except ValueError as exc:  # the SDK checks the labels before sending anything
            raise typer.BadParameter(str(exc), param_hint=LABEL_OPTION) from None
        render_volumes(app_state(ctx), volumes)


# `volume ls`: the same command as `list`, hidden from --help.
volume_app.command("ls", hidden=True)(list_volumes)


@volume_app.command("get")
def get(ctx: typer.Context, volume_id: VolumeRef) -> None:
    """Show one volume by id or name."""
    reject_empty_name(volume_id, VOLUME_ID_METAVAR)
    with cli_errors(), open_client() as client:
        resolved = volume_id_for_ref(client, volume_id, VOLUME_ID_METAVAR)
        render_volume(app_state(ctx), client.volumes.get(resolved))


@volume_app.command("rm")
def rm(ctx: typer.Context, volume_id: VolumeRef) -> None:
    """Delete a volume by id or name (refused while a sandbox mounts it); prints the id.

    With --json: the volume object.
    """
    reject_empty_name(volume_id, VOLUME_ID_METAVAR)
    with cli_errors(), open_client() as client:
        resolved = volume_id_for_ref(client, volume_id, VOLUME_ID_METAVAR)
        info = client.volumes.delete(resolved)
        if app_state(ctx).json_output:
            print_json(volume_payload(info))
        else:
            typer.echo(shown(info.id, caller_key()))


# `volume delete`: the same command as `rm`, hidden from --help.
volume_app.command("delete", hidden=True)(rm)


@volume_app.command("export")
def export(
    ctx: typer.Context,
    volume_id: VolumeRef,
    output_text: Annotated[
        str,
        typer.Option(OUTPUT_OPTION, "-o", metavar="PATH", help="File to write the .tar.gz to."),
    ],
) -> None:
    """Download a volume's files as a gzipped tar.

    A volume a running sandbox mounts can be exported, but the archive is then not a
    point-in-time copy. With --json: id, path and bytes written.
    """
    reject_empty_name(volume_id, VOLUME_ID_METAVAR)
    # Taken as text: typer would turn an empty path into ".", which is never a file to write.
    reject_empty_name(output_text, OUTPUT_OPTION)
    output = Path(output_text)
    state = app_state(ctx)
    with cli_errors(), open_client() as client:
        resolved = volume_id_for_ref(client, volume_id, VOLUME_ID_METAVAR)
        try:
            written = client.volumes.export(resolved, output)
        except OSError as exc:
            raise CliError(f"cannot write {output}: {exc.strerror or exc}") from None
        if state.json_output:
            print_json({"id": resolved, "path": str(output), "bytes": written})
        else:
            typer.echo(f"exported {shown(resolved, caller_key())} to {output}: {written} bytes")


@volume_app.command("restore")
def restore(
    ctx: typer.Context,
    volume_id: VolumeRef,
    archive: Annotated[
        Path,
        typer.Argument(
            metavar="<archive>",
            help="Gzipped tar to restore from (at most 256 MiB).",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ],
) -> None:
    """Replace a volume's contents from a gzipped tar.

    The volume is emptied first: a restore that fails after it began leaves the volume empty
    and the error says so. Refused while a sandbox mounts the volume. With --json: volume_id,
    name and restored_bytes.
    """
    reject_empty_name(volume_id, VOLUME_ID_METAVAR)
    state = app_state(ctx)
    with cli_errors(), open_client() as client:
        resolved = volume_id_for_ref(client, volume_id, VOLUME_ID_METAVAR)
        try:
            result = client.volumes.restore(resolved, archive)
        except OSError as exc:
            raise CliError(f"cannot read {archive}: {exc.strerror or exc}") from None
        if state.json_output:
            print_json(clean_strings(asdict(result), caller_key()))
        else:
            typer.echo(
                f"restored {shown(resolved, caller_key())} from {archive}: "
                f"{result.restored_bytes} bytes"
            )
