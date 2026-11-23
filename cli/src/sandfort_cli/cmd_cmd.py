"""``sandfort cmd`` (background commands, logs, kill) and ``sandfort preview``.

A background command lives in an exec session: ``cmd start`` runs it asynchronously and returns
at once with the session and command ids, ``cmd logs`` reads or follows its output and ``cmd
kill`` stops it. ``preview`` mints a preview token and prints the URL that reaches a sandbox port.
"""

import shlex
from collections.abc import Callable
from typing import Annotated, Any

import typer
from sandfort_sdk import NotFound, Sandbox
from sandfort_sdk.models import SessionInfo

from sandfort_cli.cmd_sessions import (
    SESSION_METAVAR,
    SandboxRef,
    SessionRef,
    close_session,
    rm_session_command,
    sessions_command,
)
from sandfort_cli.config import open_client
from sandfort_cli.exec_cmd import (
    NOT_OK_EXIT_CODE,
    TIMED_OUT_EXIT_CODE,
    command_argv,
    exit_hint,
    not_ok_sentence,
)
from sandfort_cli.output import (
    PLATFORM_ERROR_EXIT_CODE,
    CliError,
    accepts_negative_numbers,
    app_state,
    clean_strings,
    print_json,
    reject_empty_name,
    reject_empty_option,
    render_message,
    shown,
    strip_dangerous_terminal,
)
from sandfort_cli.refs import resolve_sandbox_id
from sandfort_cli.sandboxes import (
    INTEGER_METAVAR,
    JSON_ERROR_EPILOG,
    SANDBOX_METAVAR,
    parse_whole_number,
    ref_errors,
)
from sandfort_cli.sanitise import MASK, caller_key

cmd_app = typer.Typer(
    name="cmd",
    help="Run background commands in a sandbox.",
    epilog=JSON_ERROR_EPILOG,
    no_args_is_help=True,
)

# The server's ceiling for one command (an async command is killed when it runs longer).
MAX_COMMAND_TIMEOUT_S = 3600
MIN_PREVIEW_TTL_S = 60
MAX_PREVIEW_TTL_S = 7 * 24 * 3600
# The server's preview port range (``MintPreviewTokenRequest.port`` in the OpenAPI spec).
MIN_PREVIEW_PORT = 1024
MAX_PORT = 65535
# The query parameter the preview proxy reads the token from (``TOKEN_PARAM`` in the server's
# proxy module; repeated because the CLI must not import it).
TOKEN_PARAM = "sandfort_preview_token"
PORT_METAVAR = "<port>"
# Same convention as a shell: 128 + SIGKILL for a command that was killed.
KILLED_EXIT_CODE = 137
KILLED_STATE = "killed"
STARTED_STATE = "started"
KILLED_MESSAGE = "sandfort: the command was killed"
TIMED_OUT_MESSAGE = "sandfort: the command timed out"

COMMAND_METAVAR = "<command-id>"

CommandRef = Annotated[
    str, typer.Argument(metavar=COMMAND_METAVAR, help="Command id printed by 'cmd start'.")
]


def reject_empty_ids(sandbox_id: str, session_id: str, command_id: str) -> None:
    """Blank sandbox, session or command ids are usage errors, found before any request."""
    reject_empty_name(sandbox_id, SANDBOX_METAVAR)
    reject_empty_name(session_id, SESSION_METAVAR)
    reject_empty_name(command_id, COMMAND_METAVAR)


def ensure_session(sandbox: Sandbox, name: str | None) -> SessionInfo:
    """The session named ``name`` when it exists, else a new session (an unknown name is an error).

    The platform assigns session ids, so a session cannot be created under a chosen name.
    """
    if name is None:
        return sandbox.process.create_session()
    try:
        return sandbox.process.get_session(name)
    except NotFound:
        raise CliError(
            f"no session '{name}' in this sandbox; omit --session to create one "
            "(session ids are assigned by the platform)"
        ) from None


cmd_app.command("sessions")(sessions_command)
cmd_app.command("rm-session")(rm_session_command)


@cmd_app.command("start")
def start_command(
    ctx: typer.Context,
    sandbox_id: SandboxRef,
    argv: Annotated[
        list[str], typer.Argument(metavar="<argv>...", help="Command and arguments, after '--'.")
    ],
    session: Annotated[
        str | None,
        typer.Option("--session", help="Run in this existing session; default: a new session."),
    ] = None,
    timeout_text: Annotated[
        str | None,
        typer.Option(
            "--timeout", "-t", metavar=INTEGER_METAVAR, help="Seconds before it is killed."
        ),
    ] = None,
    follow: Annotated[
        bool,
        typer.Option(
            "--follow",
            "-f",
            help="Wait for the command, stream its output and exit with its status.",
        ),
    ] = False,
    close: Annotated[
        bool,
        typer.Option(
            "--close",
            help="With --follow: delete the new session once the command has ended.",
        ),
    ] = False,
) -> None:
    """Start a command in the background and print its session and command ids.

    The command runs through the session shell. Every start without --session opens a new
    session; list them with 'cmd sessions' and delete one with 'cmd rm-session'.

    With --follow the ids go to stderr and the command's output to stdout. Add --close to
    delete the session afterwards (not with --session, which names a session to keep).
    The exit status is the command's own. A command that exits 0 but was stopped or had its
    output truncated exits 120 with a sentence on stderr.

    It is killed after --timeout seconds (default and maximum: 3600).
    """
    reject_empty_name(sandbox_id, SANDBOX_METAVAR)
    reject_empty_option(session, "--session")
    check_close_options(follow=follow, close=close, session=session)
    timeout = (
        MAX_COMMAND_TIMEOUT_S
        if timeout_text is None
        else parse_whole_number(timeout_text, "--timeout", high=MAX_COMMAND_TIMEOUT_S)
    )
    command = shlex.join(command_argv(argv))
    with ref_errors(PLATFORM_ERROR_EXIT_CODE, sandbox_id), open_client() as client:
        sandbox = client.get(resolve_sandbox_id(client, sandbox_id))
        target = ensure_session(sandbox, session)
        outcome = sandbox.process.execute_session_command(
            target.id, command, run_async=True, timeout_s=timeout
        )
        if outcome.command is None:
            raise CliError("the platform did not report a command for the async execution")
        key = caller_key()
        payload = clean_strings(
            {
                "sandbox_id": sandbox.id,
                "session_id": target.id,
                "command_id": outcome.command.id,
            },
            key,
        )
        message = f"session: {shown(target.id, key)}\ncommand: {shown(outcome.command.id, key)}"
        if not follow:
            render_message(app_state(ctx), message, payload)
            return
        typer.echo(message.replace("\n", ", "), err=True)
        # The command runs through the session shell, so a missing program is the shell's report.
        hint_command = ["sh", "-c", command]

        def hint_for(exit_code: int, stderr: str) -> str | None:
            return exit_hint(
                ctx, sandbox_id, hint_command, exit_code, cwd_given=True, stderr=stderr
            )

        exit_code = follow_and_close(
            sandbox, target.id, outcome.command.id, close=close, hint_for=hint_for
        )
    raise typer.Exit(exit_code)


# Called with the exit code and the stderr seen so far; returns a hint line or ``None``.
HintFor = Callable[[int, str], str | None]
# Stderr kept for the 127 hint: the runner or shell reports a missing command first.
HINT_STDERR_LINES = 50


def check_close_options(*, follow: bool, close: bool, session: str | None) -> None:
    """``--close`` needs ``--follow`` (the session is deleted when the command has ended) and
    must not delete a session the caller named; both are usage errors found before any request."""
    if close and not follow:
        raise typer.BadParameter(
            "it needs --follow, to know when the command ends", param_hint="--close"
        )
    if close and session is not None:
        raise typer.BadParameter(
            "it deletes the session, so it cannot be used with --session; "
            "use 'cmd rm-session' for a session you named",
            param_hint="--close",
        )


def follow_and_close(
    sandbox: Sandbox,
    session_id: str,
    command_id: str,
    *,
    close: bool,
    hint_for: HintFor | None = None,
) -> int:
    """Follow the command to its exit status; with ``close`` delete the session afterwards,
    also when following fails."""
    try:
        return follow_to_exit_code(sandbox, session_id, command_id, hint_for=hint_for)
    finally:
        if close:
            close_session(sandbox, session_id)


@cmd_app.command("logs")
def logs_command(
    sandbox_id: SandboxRef,
    session_id: SessionRef,
    command_id: CommandRef,
    follow: Annotated[
        bool,
        typer.Option("--follow", "-f", help="Stream output until the command exits."),
    ] = False,
) -> None:
    """Print a command's output; with --follow stream it and exit with the command's status.

    A killed command exits 137 and a timed-out command exits 124, each with a message on stderr.
    Exit status 125 means the platform or CLI failed. Without --follow the status is 0.
    """
    reject_empty_ids(sandbox_id, session_id, command_id)
    exit_code = 0
    with ref_errors(PLATFORM_ERROR_EXIT_CODE, sandbox_id), open_client() as client:
        sandbox = client.get(resolve_sandbox_id(client, sandbox_id))
        if follow:
            exit_code = follow_to_exit_code(sandbox, session_id, command_id)
        else:
            print_logs(sandbox, session_id, command_id)
    raise typer.Exit(exit_code)


def echo_event(stream: str, text: str) -> None:
    """Relay one line of program output (followed or paged) with the same filter as ``exec``:
    OSC (the clipboard write included), DCS, SOS, PM and APC sequences are removed, the rest is
    kept as the program wrote it."""
    typer.echo(strip_dangerous_terminal(text), nl=False, err=stream == "stderr")


def follow_to_exit_code(
    sandbox: Sandbox, session_id: str, command_id: str, *, hint_for: HintFor | None = None
) -> int:
    """Echo events as they arrive; return the command's exit code from the exit event.

    A killed command (state ``killed`` or no exit code) gives 137 and a timed-out one gives 124,
    each with a message on stderr. A command that exited 0 but whose output was truncated or
    that a sandbox stop ended gives ``NOT_OK_EXIT_CODE`` with a message. ``hint_for`` may add a
    hint line (the exit 127 hint). Every sentence of ours starts on its own line, also when the
    command's stderr did not end with a newline. A stream that ends without an exit event gives 0.
    """
    final = None
    stderr_lines: list[str] = []
    line_open = False  # the last stderr text relayed did not end with a newline
    with sandbox.process.follow_logs(session_id, command_id) as stream:
        for event in stream:
            if event.is_exit:
                final = event
                continue
            echo_event(event.stream, event.line)
            if event.stream == "stderr":
                line_open = bool(event.line) and not event.line.endswith("\n")
                if len(stderr_lines) < HINT_STDERR_LINES:
                    stderr_lines.append(event.line)

    def say(text: str) -> None:
        nonlocal line_open
        if line_open:
            typer.echo(err=True)
            line_open = False
        typer.echo(text, err=True)

    if final is None:
        return 0
    if final.state == KILLED_STATE or final.exit_code is None:
        say(KILLED_MESSAGE)
        return KILLED_EXIT_CODE
    exit_code = final.exit_code
    if exit_code == TIMED_OUT_EXIT_CODE:
        say(TIMED_OUT_MESSAGE)
    hint = None if hint_for is None else hint_for(exit_code, "".join(stderr_lines))
    if hint is not None:
        say(hint)
    if exit_code == 0 and (final.truncated or final.stop_cause is not None):
        say(not_ok_sentence(final.stop_cause, truncated=final.truncated))
        return NOT_OK_EXIT_CODE
    return exit_code


def print_logs(sandbox: Sandbox, session_id: str, command_id: str) -> None:
    """Echo everything logged so far, page by page, until the log is complete or has no more."""
    offset = 0
    while True:
        page = sandbox.process.get_command_logs(session_id, command_id, offset=offset)
        for event in page.events:
            echo_event(event.stream, event.line)
        if page.complete or page.next_offset <= offset:
            return
        offset = page.next_offset


@cmd_app.command("kill")
def kill_command(
    ctx: typer.Context, sandbox_id: SandboxRef, session_id: SessionRef, command_id: CommandRef
) -> None:
    """Kill a background command."""
    reject_empty_ids(sandbox_id, session_id, command_id)
    with ref_errors(PLATFORM_ERROR_EXIT_CODE, sandbox_id), open_client() as client:
        sandbox = client.get(resolve_sandbox_id(client, sandbox_id))
        info = sandbox.process.kill_command(session_id, command_id)
    key = caller_key()
    payload: dict[str, Any] = clean_strings(
        {
            "sandbox_id": sandbox.id,
            "session_id": session_id,
            "command_id": info.id,
            "state": info.state,
            "exit_code": info.exit_code,
        },
        key,
    )
    message = f"command {shown(info.id, key)}: {shown(info.state, key)}"
    render_message(app_state(ctx), message, payload)


def preview_view(url: str, token: str, api_key: str) -> tuple[str, bool]:
    """``url`` sanitised like any server text, except that the preview token stays usable, and
    whether the returned url carries the token verbatim.

    The sanitiser masks every query value, which would turn ``?<TOKEN_PARAM>=<token>`` into
    ``?<TOKEN_PARAM>=***``. The token is found by its parameter name, never by comparing values:
    when the token is ordinary text (the sanitiser would leave it unchanged), the values of the
    pairs named ``TOKEN_PARAM`` that equal it are put back as returned; every other part of the
    url, other query values included, stays sanitised. A token the sanitiser would alter is
    never spliced in (it could hold terminal sequences): the masked url is returned and the flag
    is False.
    """
    cleaned = shown(url, api_key)
    if not token or shown(token, api_key) != token:
        return cleaned, False
    raw_pairs = url.partition("?")[2].partition("#")[0].split("&")
    indexes = [
        i
        for i, pair in enumerate(raw_pairs)
        if pair.partition("=")[0] == TOKEN_PARAM and pair.partition("=")[2] == token
    ]
    head, question, rest = cleaned.partition("?")
    query, hash_mark, fragment = rest.partition("#")
    pairs = query.split("&")
    if not indexes or not question or len(pairs) != len(raw_pairs):
        return cleaned, False
    masked = "=" + MASK
    if not all(pairs[i].startswith(TOKEN_PARAM) and pairs[i].endswith(masked) for i in indexes):
        return cleaned, False
    for i in indexes:
        pairs[i] = pairs[i][: -len(MASK)] + token
    return f"{head}?{'&'.join(pairs)}{hash_mark}{fragment}", True


def preview_url(url: str, token: str, api_key: str) -> str:
    """The sanitised preview url with the token put back (see :func:`preview_view`)."""
    return preview_view(url, token, api_key)[0]


def has_control_chars(text: str) -> bool:
    return any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in text)


def echo_token_line(token: str) -> None:
    """Text mode only: the exact token on its own line, for a url that could not carry it.

    A token holding control characters is never printed raw (it could drive the terminal); it
    is not an ordinary token, and ``--json`` has it exactly.
    """
    if not token:
        return
    if has_control_chars(token):
        typer.echo("sandfort: the token holds control characters; use --json to read it", err=True)
        return
    typer.echo(f"token: {token}")


@accepts_negative_numbers
def preview_command(
    ctx: typer.Context,
    sandbox_id: SandboxRef,
    port_text: Annotated[
        str,
        typer.Argument(
            metavar=PORT_METAVAR,
            help=f"Port in the sandbox, from {MIN_PREVIEW_PORT} to {MAX_PORT}.",
        ),
    ],
    ttl_text: Annotated[
        str | None,
        typer.Option(
            "--ttl",
            metavar=INTEGER_METAVAR,
            help="Token lifetime in seconds (default: the server's).",
        ),
    ] = None,
) -> None:
    """Print the preview URL for a port of a sandbox (with --json: also token and expiry).

    A sandbox that is not started still gets a URL, with a warning on stderr.
    """
    reject_empty_name(sandbox_id, SANDBOX_METAVAR)
    port = parse_whole_number(port_text, PORT_METAVAR, low=MIN_PREVIEW_PORT, high=MAX_PORT)
    ttl = (
        None
        if ttl_text is None
        else parse_whole_number(ttl_text, "--ttl", low=MIN_PREVIEW_TTL_S, high=MAX_PREVIEW_TTL_S)
    )
    with ref_errors(PLATFORM_ERROR_EXIT_CODE, sandbox_id), open_client() as client:
        sandbox = client.get(resolve_sandbox_id(client, sandbox_id))
        info = sandbox.preview(port, ttl_seconds=ttl)
        state = sandbox.state
    key = caller_key()
    if state != STARTED_STATE:
        note = f"sandfort: the sandbox is {shown(state, key)}; the URL works after it is started"
        typer.echo(note, err=True)
    url, token_in_url = preview_view(info.url, info.token, key)
    if app_state(ctx).json_output:
        # The token is a credential: printed exactly as the server returned it, and the url
        # (already sanitised, token put back) must not be cleaned a second time.
        others = clean_strings({"port": info.port, "expires_at": info.expires_at.isoformat()}, key)
        print_json({**others, "url": url, "token": info.token})
    else:
        typer.echo(url)
        if not token_in_url:
            echo_token_line(info.token)
