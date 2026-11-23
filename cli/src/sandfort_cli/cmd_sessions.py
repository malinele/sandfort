"""``sandfort cmd sessions`` and ``sandfort cmd rm-session``, and the session clean-up that
``cmd start --close`` runs once a followed command has ended."""

from collections.abc import Sequence
from typing import Annotated, Any

import typer
from sandfort_sdk import NotFound, Sandbox, SandfortSDKError
from sandfort_sdk.models import SessionInfo

from sandfort_cli.config import open_client
from sandfort_cli.output import (
    EXIT_FAILURE,
    PLATFORM_ERROR_EXIT_CODE,
    app_state,
    clean_strings,
    cli_errors,
    describe_error,
    print_json,
    print_table,
    reject_empty_name,
    render_message,
    shown,
    utc_cell,
)
from sandfort_cli.refs import resolve_sandbox_id
from sandfort_cli.sandboxes import SANDBOX_METAVAR, ref_errors
from sandfort_cli.sanitise import caller_key

SESSION_METAVAR = "<session-id>"

SandboxRef = Annotated[str, typer.Argument(metavar=SANDBOX_METAVAR, help="Sandbox id or name.")]
SessionRef = Annotated[
    str, typer.Argument(metavar=SESSION_METAVAR, help="Session id printed by 'cmd start'.")
]


def session_payload(info: SessionInfo, key: str) -> dict[str, Any]:
    """The json shape of a session. Its environment is left out (it may hold secrets)."""
    payload: dict[str, Any] = clean_strings(
        {
            "id": info.id,
            "sandbox_id": info.sandbox_id,
            "state": info.state,
            "cwd": info.cwd,
            "created_at": info.created_at.isoformat(),
        },
        key,
    )
    return payload


def render_sessions(json_output: bool, infos: Sequence[SessionInfo]) -> None:
    key = caller_key()
    if json_output:
        print_json([session_payload(info, key) for info in infos])
        return
    rows = [
        (
            shown(info.id, key),
            shown(info.state, key),
            shown(info.cwd, key) if info.cwd else "",
            utc_cell(info.created_at),
        )
        for info in infos
    ]
    print_table("sessions", ("ID", "STATE", "CWD", "CREATED"), rows, free=("CWD",))


def sessions_command(ctx: typer.Context, sandbox_id: SandboxRef) -> None:
    """List the sessions of a sandbox (each 'cmd start' without --session opens a new one)."""
    reject_empty_name(sandbox_id, SANDBOX_METAVAR)
    with ref_errors(PLATFORM_ERROR_EXIT_CODE, sandbox_id), open_client() as client:
        sandbox = client.get(resolve_sandbox_id(client, sandbox_id))
        infos = sandbox.process.list_sessions()
    render_sessions(app_state(ctx).json_output, infos)


SANDBOX_MISSING_PREFIX = "sandbox "


def delete_session_or_missing(sandbox: Sandbox, session_id: str, *, if_exists: bool) -> Any:
    """Delete the session; ``None`` when ``if_exists`` and it was already gone.

    A missing session is reported like a missing sandbox (exit 1, ``NOT_FOUND``), apart from
    the platform errors, which keep exit 125. A not-found answer about the sandbox itself is
    such a platform error.
    """
    try:
        return sandbox.process.delete_session(session_id)
    except NotFound as exc:
        if exc.message.startswith(SANDBOX_MISSING_PREFIX):
            raise
        if if_exists:
            typer.echo(f"{shown(session_id, caller_key())}: not found, skipped", err=True)
            return None
        with cli_errors(EXIT_FAILURE):
            raise


def rm_session_command(
    ctx: typer.Context,
    sandbox_id: SandboxRef,
    session_id: SessionRef,
    if_exists: Annotated[
        bool,
        typer.Option(
            "--if-exists",
            help="Skip a session that does not exist (note on stderr, exit code 0). "
            "Other errors still fail.",
        ),
    ] = False,
) -> None:
    """Delete a session; the commands still running in it are killed.

    A session that does not exist exits 1 (a platform error exits 125).
    """
    reject_empty_name(sandbox_id, SANDBOX_METAVAR)
    reject_empty_name(session_id, SESSION_METAVAR)
    with ref_errors(PLATFORM_ERROR_EXIT_CODE, sandbox_id), open_client() as client:
        sandbox = client.get(resolve_sandbox_id(client, sandbox_id))
        info = delete_session_or_missing(sandbox, session_id, if_exists=if_exists)
    key = caller_key()
    if info is None:
        skipped = clean_strings(
            {"sandbox_id": sandbox.id, "session_id": session_id, "skipped": "not_found"}, key
        )
        if app_state(ctx).json_output:
            print_json(skipped)
        return
    payload = clean_strings(
        {"sandbox_id": sandbox.id, "session_id": session_id, "state": info.state}, key
    )
    message = f"session {shown(session_id, key)}: {shown(info.state, key)}"
    render_message(app_state(ctx), message, payload)


def close_session(sandbox: Sandbox, session_id: str) -> None:
    """Delete ``session_id`` after its command ended. A failure is a warning on stderr: it must
    not replace the command's own exit status."""
    try:
        sandbox.process.delete_session(session_id)
    except SandfortSDKError as exc:
        key = caller_key()
        problem = describe_error(exc)
        typer.echo(
            f"sandfort: could not delete session {shown(session_id, key)}: {problem}", err=True
        )
