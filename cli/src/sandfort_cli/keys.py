"""The ``key`` command group (create, list, revoke) over the SDK API key methods."""

from collections.abc import Sequence
from dataclasses import asdict
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any

import typer
from sandfort_sdk import ApiKeyInfo, Client, CreatedApiKey, NotFound
from sandfort_sdk.api_keys import RevokedApiKey

from sandfort_cli.config import open_client
from sandfort_cli.output import (
    CliError,
    app_state,
    clean_strings,
    cli_errors,
    exact_labels,
    flatten_text,
    is_blank,
    labels_cell,
    print_json,
    print_table,
    reject_empty_name,
    reject_empty_options,
    shown,
)
from sandfort_cli.sandboxes import (
    JSON_ERROR_EPILOG,
    echo_value,
    parse_pairs,
    parse_whole_number,
)
from sandfort_cli.sanitise import caller_key

NAME_METAVAR = "<name>"
KEY_ID_METAVAR = "<key-id>"
SECRET_WARNING = "warning: this key is shown only once; store it now, it cannot be read back"
TIMESTAMP_FIELDS = ("created_at", "last_used_at", "expires_at", "revoked_at")
# The one-time plaintext secret in the json of a created key.
SECRET_FIELD = "key"
UNNAMED_LABEL = "(unnamed)"
STATUS_ACTIVE = "active"
STATUS_EXPIRED = "expired"
STATUS_REVOKED = "revoked"
EXPIRES_FORMAT = "%Y-%m-%d %H:%M"
EXPIRES_NEVER = "-"
# Scope names shown in a `key list` cell before the rest are counted as "+N more".
SCOPES_SHOWN = 2
# The free-text columns of `key list`, highest priority first; the rest stay whole.
KEY_LIST_FREE = ("NAME", "SCOPES", "LABELS")
# The scope names the server grants, in its order. The CLI does not depend on the server
# package, so this mirrors ``sandfort.domain.org.Scope``; a test checks that the two agree.
KNOWN_SCOPES = (
    "org:read",
    "sandboxes:read",
    "sandboxes:write",
    "toolbox:use",
    "snapshots:read",
    "snapshots:write",
    "volumes:read",
    "volumes:write",
    "api_keys:admin",
    "webhooks:write",
    "usage:read",
    "audit:read",
)
SCOPE_HELP = f"Scope to grant (repeatable, at least one). Known scopes: {', '.join(KNOWN_SCOPES)}."


class KeyStatusFilter(StrEnum):
    """The values ``key list --status`` accepts (the server's key status filter)."""

    ACTIVE = "active"
    REVOKED = "revoked"


key_app = typer.Typer(
    name="key", help="Manage API keys.", epilog=JSON_ERROR_EPILOG, no_args_is_help=True
)


def key_payload(info: ApiKeyInfo, now: datetime | None = None) -> dict[str, Any]:
    """The key object for ``--json``: timestamps as ISO 8601, ``key`` only on a created key.

    ``status`` is the value the ``key list`` table shows (:func:`key_status`). Every server
    string is sanitised like the sandbox views, except the one-time plaintext ``key`` of a
    created key: it is a credential and stays exactly as the server returned it.
    """
    payload = asdict(info)
    secret = payload.pop(SECRET_FIELD, None)
    # A revoke answer's descendants are added by the revoke command, not by every view.
    payload.pop("cascade", None)
    payload.pop("dependants", None)
    payload["status"] = key_status(info, now or datetime.now(UTC))
    payload["scopes"] = list(info.scopes)
    for name in TIMESTAMP_FIELDS:
        value = payload[name]
        payload[name] = None if value is None else value.isoformat()
    cleaned: dict[str, Any] = clean_strings(payload, caller_key())
    cleaned["sandbox_labels"] = exact_labels(cleaned.get("sandbox_labels"), info.sandbox_labels)
    cleaned["shared_volume_labels"] = exact_labels(
        cleaned.get("shared_volume_labels"), info.shared_volume_labels
    )
    if isinstance(info, CreatedApiKey):
        cleaned[SECRET_FIELD] = secret
    return cleaned


def parse_expires_at(value: str | None) -> datetime | None:
    """``value`` as a timezone-aware datetime; ``None`` when not given.

    A value that is not ISO 8601, or has no timezone, is a usage error (exit 2).
    """
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise typer.BadParameter(
            f"invalid value {echo_value(value)}; expected ISO 8601", param_hint="--expires-at"
        ) from None
    if parsed.tzinfo is None:
        hint = "needs a timezone, e.g. 2027-01-01T00:00:00Z"
        raise typer.BadParameter(f"{echo_value(value)} {hint}", param_hint="--expires-at")
    return parsed


def _cell(value: object) -> str:
    """One server value for a table cell or a text line: sanitised like the sandbox views."""
    return "" if value is None else shown(value, caller_key())


def name_cell(name: object) -> str:
    """A key name for text output: sanitised, ``(unnamed)`` when nothing visible is left."""
    if name is None or is_blank(str(name)):
        return UNNAMED_LABEL
    return _cell(name).strip() or UNNAMED_LABEL


def key_status(info: ApiKeyInfo, now: datetime) -> str:
    """``revoked`` once revoked, else ``expired`` once past ``expires_at``, else ``active``."""
    if info.revoked_at is not None:
        return STATUS_REVOKED
    expires_at = info.expires_at
    if expires_at is not None:
        aware = expires_at if expires_at.tzinfo is not None else expires_at.replace(tzinfo=UTC)
        if aware <= now:
            return STATUS_EXPIRED
    return STATUS_ACTIVE


def expires_cell(expires_at: datetime | None) -> str:
    """The expiry as a short UTC ``YYYY-MM-DD HH:MM``; ``-`` when the key never expires."""
    if expires_at is None:
        return EXPIRES_NEVER
    aware = expires_at if expires_at.tzinfo is not None else expires_at.replace(tzinfo=UTC)
    return aware.astimezone(UTC).strftime(EXPIRES_FORMAT)


def scopes_cell(scopes: Sequence[str]) -> str:
    """The first :data:`SCOPES_SHOWN` scope names, then ``+N more`` for the rest."""
    shown = ",".join(scopes[:SCOPES_SHOWN])
    hidden = len(scopes) - SCOPES_SHOWN
    return _cell(f"{shown} +{hidden} more" if hidden > 0 else shown)


def _key_row(info: ApiKeyInfo, now: datetime) -> tuple[str, ...]:
    return (
        _cell(info.id),
        name_cell(info.name),
        key_status(info, now),
        expires_cell(info.expires_at),
        scopes_cell(info.scopes),
        labels_cell(info.sandbox_labels or {}),
        _cell(info.max_sandboxes),
    )


@key_app.command("create")
def create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(metavar=NAME_METAVAR, help="Key name.")],
    scope: Annotated[
        list[str],
        typer.Option("--scope", "-s", help=SCOPE_HELP),
    ],
    label: Annotated[
        list[str] | None,
        typer.Option(
            "--label", "-l", help="Restrict to sandboxes with label KEY=VALUE (repeatable)."
        ),
    ] = None,
    shared_volume_label: Annotated[
        list[str] | None,
        typer.Option(
            "--shared-volume-label",
            help="Also let the key list, get and mount read-only volumes labelled KEY=VALUE "
            "(repeatable; needs --label).",
        ),
    ] = None,
    max_sandboxes_text: Annotated[
        str | None,
        typer.Option(
            "--max-sandboxes", metavar="INTEGER", help="Cap on live sandboxes (needs --label)."
        ),
    ] = None,
    expires_at: Annotated[
        str | None,
        typer.Option("--expires-at", help="Expiry as ISO 8601 with a timezone."),
    ] = None,
) -> None:
    """Create an API key; the secret is printed once and cannot be read back later."""
    json_output = app_state(ctx).json_output
    reject_empty_name(name, NAME_METAVAR)
    reject_empty_options(scope, "--scope")
    # Local input is checked first: a bad value is a usage error even without a login.
    max_sandboxes = (
        None
        if max_sandboxes_text is None
        else parse_whole_number(max_sandboxes_text, "--max-sandboxes")
    )
    sandbox_labels = parse_pairs(label, "label")
    if max_sandboxes is not None and not sandbox_labels:
        raise typer.BadParameter(
            "at least one KEY=VALUE is required with --max-sandboxes "
            "(the cap counts the sandboxes the key's labels select)",
            param_hint="--label",
        )
    shared_labels = parse_pairs(shared_volume_label, "shared-volume-label")
    if shared_labels and not sandbox_labels:
        raise typer.BadParameter(
            "at least one KEY=VALUE is required with --shared-volume-label "
            "(the shared volumes extend the key's label scope)",
            param_hint="--label",
        )
    expiry = parse_expires_at(expires_at)
    with cli_errors(), open_client() as client:
        try:
            created: CreatedApiKey = client.create_api_key(
                name,
                scope,
                sandbox_labels=sandbox_labels,
                max_sandboxes=max_sandboxes,
                expires_at=expiry,
                shared_volume_labels=shared_labels,
            )
        except ValueError as exc:  # the SDK checks its arguments before sending
            raise CliError(str(exc), client=True) from None
        if json_output:
            print_json(key_payload(created))
        else:
            typer.echo(created.key)
            typer.echo(SECRET_WARNING, err=True)


@key_app.command("list")
def list_keys(
    ctx: typer.Context,
    show_all: Annotated[
        bool, typer.Option("--all", "-a", help="Include revoked keys (hidden by default).")
    ] = False,
    status: Annotated[
        KeyStatusFilter | None,
        typer.Option(
            "--status",
            help="Ask the server for only active or only revoked keys "
            "(overrides the default hiding of revoked keys).",
        ),
    ] = None,
) -> None:
    """List API keys (metadata only, revoked ones hidden); secrets are never printed.

    Ids always print in full so they can be copied into `key revoke`.
    """
    with cli_errors(), open_client() as client:
        try:
            keys = client.list_api_keys(status=None if status is None else status.value)
        except ValueError as exc:  # the SDK checks its arguments before sending
            raise CliError(str(exc), client=True) from None
        hide_revoked = status is None and not show_all
        infos = [info for info in keys if not (hide_revoked and info.revoked_at is not None)]
    now = datetime.now(UTC)
    if app_state(ctx).json_output:
        print_json([key_payload(info, now) for info in infos])
        return
    columns = ("ID", "NAME", "STATUS", "EXPIRES", "SCOPES", "LABELS", "MAX SANDBOXES")
    rows = [_key_row(info, now) for info in infos]
    # Free text, highest priority first; the id is never cut (it goes into `key revoke`),
    # the status, the dates and the numbers are never squeezed.
    print_table("api keys", columns, rows, free=KEY_LIST_FREE)


def _revoke_one(
    client: Client, key_id: str, if_exists: bool, cascade: bool
) -> RevokedApiKey | None:
    """Revoke ``key_id``; ``None`` when ``if_exists`` and the key does not exist."""
    try:
        return client.revoke_api_key(key_id, cascade=cascade)
    except NotFound:
        if not if_exists:
            raise
        typer.echo(f"{flatten_text(key_id)}: not found, skipped", err=True)
        return None


def _dependants_hint(info: RevokedApiKey) -> None:
    """On stderr: the live dependants a plain revoke left alive, and how to revoke them."""
    if info.cascade or not info.dependants:
        return
    count = len(info.dependants)
    head = f"note: {count} live dependant key(s) of {_cell(info.id)} were not revoked:"
    typer.echo(head, err=True)
    for dependant in info.dependants:
        typer.echo(f"  {_cell(dependant.id)}  {name_cell(dependant.name)}", err=True)
    ids = " ".join(_cell(dependant.id) for dependant in info.dependants)
    typer.echo(f"revoke them with: sandfort key revoke {ids}", err=True)


def _revoke_payload(info: RevokedApiKey) -> dict[str, Any]:
    """The key object for ``--json``, plus ``cascade`` and ``dependants`` when there are any."""
    payload = key_payload(info)
    payload["revoked"] = True
    if info.cascade or info.dependants:
        payload["cascade"] = info.cascade
        payload["dependants"] = [key_payload(dependant) for dependant in info.dependants]
    return payload


@key_app.command("revoke")
def revoke(
    ctx: typer.Context,
    key_ids: Annotated[
        list[str], typer.Argument(metavar=f"{KEY_ID_METAVAR}...", help="Key ids, revoked in order.")
    ],
    if_exists: Annotated[
        bool,
        typer.Option(
            "--if-exists",
            help="Skip a key that does not exist (note on stderr, exit code unchanged). "
            "Other errors still fail.",
        ),
    ] = False,
    cascade: Annotated[
        bool,
        typer.Option(
            "--cascade",
            help="Also revoke the live keys created by the revoked key (descendants). "
            "Without it they stay alive and a hint lists them.",
        ),
    ] = False,
) -> None:
    """Revoke API keys; prints "revoked <id> (<name>)" per key (--json: key object or list).

    With --json every processed id is reported, also when a later id fails: a skipped id is
    {"id": ..., "skipped": "not_found"}. The live dependants are listed in "dependants".
    """
    json_output = app_state(ctx).json_output
    for key_id in key_ids:
        reject_empty_name(key_id, KEY_ID_METAVAR)
    payloads: list[dict[str, Any]] = []
    with cli_errors(), open_client() as client:
        try:
            for key_id in key_ids:
                info = _revoke_one(client, key_id, if_exists, cascade)
                if info is None:
                    payloads.append({"id": key_id, "skipped": "not_found"})
                    continue
                payloads.append(_revoke_payload(info))
                if not json_output:
                    typer.echo(f"revoked {_cell(info.id)} ({name_cell(info.name)})")
                    _dependants_hint(info)
        finally:
            if json_output and payloads:
                print_json(payloads[0] if len(key_ids) == 1 else payloads)
