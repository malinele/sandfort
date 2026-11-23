"""``sandfort exec``: run an argv in a sandbox and exit with the remote exit code."""

import os
import shlex
import stat
import sys
from dataclasses import asdict
from pathlib import PurePosixPath
from typing import Annotated

import typer

from sandfort_cli.config import open_client
from sandfort_cli.output import (
    PLATFORM_ERROR_EXIT_CODE,
    CliError,
    app_state,
    clean_hint,
    print_json,
    reject_empty_name,
    reject_empty_option,
    strip_dangerous_terminal,
)
from sandfort_cli.refs import resolve_sandbox_id
from sandfort_cli.sandboxes import SANDBOX_METAVAR, echo_value, parse_whole_number, ref_errors
from sandfort_cli.sanitise import USAGE_MESSAGE_CHARS

# Same convention as timeout(1): a command killed for exceeding its budget exits 124.
TIMED_OUT_EXIT_CODE = 124
# The command exited 0 but the server had stopped it or cut its output (SDK ``ExecResult.ok`` is
# false): not 1, 2, 3 or 124 to 127, so a script can tell it from the command's own failures.
NOT_OK_EXIT_CODE = 120
OUTPUT_TRUNCATED_REASON = "output truncated"


def not_ok_sentence(stop_reason: str | None, *, truncated: bool) -> str:
    """The stderr sentence (no newline) for a command that exited 0 but was stopped or cut."""
    reasons = [] if stop_reason is None else [stop_reason]
    if truncated:
        reasons.append(OUTPUT_TRUNCATED_REASON)
    return f"sandfort: the command was stopped: {'; '.join(reasons)}"


# Options must precede the sandbox id; everything after it belongs to the remote command.
EXEC_CONTEXT_SETTINGS = {"allow_interspersed_args": False}

END_OF_OPTIONS = "--"
STDIN_NOT_FORWARDED = "sandfort: stdin is not forwarded to the command; pass -i to send it"


# The server's exec timeout when the request carries none, and the largest it accepts
# (``timeout_s`` in the process execute schema); repeated because the CLI must not import it.
DEFAULT_TIMEOUT_S = 60
MAX_TIMEOUT_S = 3600
TIMEOUT_TOO_LARGE = f"timeout is too large; pass -t/--timeout from 1 to {MAX_TIMEOUT_S}"


def suggested_timeout(timeout_s: int | None) -> int:
    """A -t value above the one in effect: twice the default or twice ``timeout_s``, capped."""
    in_effect = DEFAULT_TIMEOUT_S if timeout_s is None else timeout_s
    return min(in_effect * 2, MAX_TIMEOUT_S)


def timeout_message(sandbox_ref: str, timeout_s: int | None) -> str:
    """The timeout line for the -t that was in effect; typer.echo adds the trailing newline."""
    ref = shlex.quote(sandbox_ref)
    if timeout_s is not None and timeout_s >= MAX_TIMEOUT_S:
        return (
            f"error: command did not finish within the maximum of {MAX_TIMEOUT_S} s; run "
            f"long-running work in the background in a session: sandfort cmd start {ref} "
            "-- <command>"
        )
    return (
        "error: command timed out; allow more time with -t/--timeout SECONDS, which goes "
        f"before the sandbox reference: sandfort exec -t {suggested_timeout(timeout_s)} {ref} "
        "-- <command>"
    )


REPLAYED_NOTE = "sandfort: replayed the stored result of this idempotency key; nothing ran again"
KEY_MAX_LENGTH = 255
PRINTABLE_FIRST, PRINTABLE_LAST = 0x20, 0x7E  # space to tilde


def check_idempotency_key(key: str | None) -> None:
    """Nothing for ``None`` or a valid ``--idempotency-key``.

    A usage error (exit 2) when the key is empty, over 255 characters, not printable ASCII, or
    starts or ends with a space (HTTP would drop it).
    """
    if key is None:
        return
    problem = None
    if not 1 <= len(key) <= KEY_MAX_LENGTH:
        problem = f"must be 1 to {KEY_MAX_LENGTH} characters"
    elif not all(PRINTABLE_FIRST <= ord(ch) <= PRINTABLE_LAST for ch in key):
        problem = "must be printable ASCII"
    elif key != key.strip(" "):
        problem = "must not start or end with a space"
    if problem is not None:
        raise typer.BadParameter(problem, param_hint="--idempotency-key")


COMMAND_NOT_FOUND_EXIT_CODE = 127
NOT_EXECUTABLE_EXIT_CODE = 126
NOT_EXECUTABLE_HINT = (
    "hint: exit 126: the file exists but cannot be executed (permissions, or not a binary/script)"
)
# Shell builtins whose effect cannot outlive the one call that ran them.
SHELL_BUILTINS = frozenset({"cd", "export", "alias", "source", "set", "ulimit", "umask"})
# Characters a shell would act on: & | ; < > $ ` * ? and both kinds of quote.
# Characters that make a word two words or change its meaning once a shell reads it again.
QUOTING_CHARS = frozenset(" \t\n'\"\\")
SHELL_METACHARACTERS = frozenset("&|;<>$`*?'\"")
# Programs that are themselves a shell: a 127 from them is the shell's own "not found".
SHELL_PROGRAMS = frozenset({"sh", "bash", "dash", "zsh", "ash", "ksh", "mksh"})
DEFAULT_CWD_OPTION = "--cwd"
# Room kept below the sanitiser's cut for what sanitising may change (masked values).
HINT_MARGIN_CHARS = 40
TRUNCATED_MARKER = "..."
PLACEHOLDER_COMMAND = "'<command>'"
# What the sandbox runner writes for a program it cannot find (``COMMAND_NOT_FOUND_MESSAGE`` in
# the docker driver, repeated because the CLI must not import the server).
RUNNER_NOT_FOUND_PREFIX = "command not found: "
SHELL_NOT_FOUND_MARKERS = ("not found", "No such file")
HINT_HEAD = "hint: exit 127 means command not found"
NO_SHELL_PART = "; the argv ran without a shell"
SHELL_PART = (
    "; the shell reported a missing command (check the command name and that the sandbox "
    "image provides it)"
)


def builtin_note(command: list[str]) -> str | None:
    """The stderr note for a command that is a shell builtin, or ``None``."""
    word = command[0]
    if word not in SHELL_BUILTINS:
        return None
    return (
        f"'{word}' only changes this one call; use --cwd, a session (sandfort shell), "
        "or chain with sh -c"
    )


def reports_missing_command(command: list[str], stderr: str) -> bool:
    """True when ``stderr`` says a command was not found, as opposed to a program that exits
    127 on purpose.

    The runner writes ``command not found: WORD`` before it runs anything. A shell writes a line
    with ``not found`` or ``No such file`` (``sh: 1: tool: not found``); when the program is not
    itself a shell, that line must also name the first word of the argv.
    """
    shell = runs_a_shell(command)
    first = PurePosixPath(command[0]).name if command else ""
    for line in stderr.splitlines():
        if line.startswith(RUNNER_NOT_FOUND_PREFIX):
            return True
        if not any(marker in line for marker in SHELL_NOT_FOUND_MARKERS):
            continue
        if shell or (command and (command[0] in line or first in line)):
            return True
    return False


def exit_hint(
    ctx: typer.Context,
    sandbox_ref: str,
    command: list[str],
    exit_code: int,
    *,
    cwd_given: bool,
    stderr: str = "",
) -> str | None:
    """The cleaned hint line for exit 127 or 126, or ``None`` for any other exit code.

    Exit 127 gets its hint only when ``stderr`` reports a missing command
    (:func:`reports_missing_command`)."""
    if exit_code == COMMAND_NOT_FOUND_EXIT_CODE:
        if not reports_missing_command(command, stderr):
            return None
        return clean_hint(not_found_hint(ctx, sandbox_ref, command, cwd_given=cwd_given))
    if exit_code == NOT_EXECUTABLE_EXIT_CODE:
        return clean_hint(NOT_EXECUTABLE_HINT)
    return None


def needs_shell(command: list[str]) -> bool:
    """True when the argv looks like shell syntax: an element with an operator or
    metacharacter, or a single element holding a space (a whole command line in one word)."""
    if any(SHELL_METACHARACTERS.intersection(word) for word in command):
        return True
    return len(command) == 1 and " " in command[0]


def runs_a_shell(command: list[str]) -> bool:
    """True when the program is a shell (``sh``, ``/bin/bash``, ...), with or without ``-c``."""
    return bool(command) and PurePosixPath(command[0]).name in SHELL_PROGRAMS


def shell_line(command: list[str]) -> str:
    """The argv as one shell command line for ``sh -c``, keeping the quoting it was typed with.

    A single word is taken as a whole command line already. In a longer argv a word that holds
    whitespace, a quote or a backslash is quoted with :func:`shlex.quote`, so the shell sees
    the same word; a word of shell syntax (``|``, ``&&``, ``>``, ``*.txt``, ``$HOME``) stays as
    it is for the shell to act on.
    """
    if len(command) == 1:
        return command[0]
    return " ".join(
        shlex.quote(word) if QUOTING_CHARS.intersection(word) or word == "" else word
        for word in command
    )


def fitted_quote(line: str, budget: int) -> str:
    """``line`` shell-quoted in at most ``budget`` characters: cut with ``...`` when longer,
    the placeholder when not even a cut fits."""
    quoted = shlex.quote(line)
    if len(quoted) <= budget:
        return quoted
    keep = budget - len(TRUNCATED_MARKER)
    while keep > 0:
        candidate = shlex.quote(line[:keep] + TRUNCATED_MARKER)
        if len(candidate) <= budget:
            return candidate
        keep -= max(1, len(candidate) - budget)
    return PLACEHOLDER_COMMAND


def cwd_option_name(ctx: typer.Context) -> str:
    """The long name of exec's working-directory option, read from the command itself."""
    for param in ctx.command.params:
        if param.name == "cwd":
            opts: list[str] = list(getattr(param, "opts", ()))
            names = [name for name in opts if name.startswith("--")]
            if names:
                return names[0]
    return DEFAULT_CWD_OPTION


def not_found_hint(
    ctx: typer.Context, sandbox_ref: str, command: list[str], *, cwd_given: bool = False
) -> str:
    """One line for exit 127.

    When the program is a shell, the shell itself reported the missing command. Otherwise the
    argv ran without a shell, with the ``sh -c`` fix when it looks like shell syntax (the
    echoed command is cut so the line stays under the sanitiser's limit). Unless ``--cwd`` was
    given, the line ends by naming the default working directory and how to change it.
    """
    cwd_part = (
        ""
        if cwd_given
        else ". The default working directory is the root directory (/); change it with "
        f"{cwd_option_name(ctx)} DIR, which goes before the sandbox reference"
    )
    if runs_a_shell(command):
        return f"{HINT_HEAD}{SHELL_PART}{cwd_part}"
    if not needs_shell(command):
        return f"{HINT_HEAD}{NO_SHELL_PART}{cwd_part}"
    lead = (
        "; to use shell syntax run it through sh -c with the whole command as one quoted "
        f"argument: sandfort exec {shlex.quote(sandbox_ref)} -- sh -c "
    )
    fixed = len(HINT_HEAD) + len(NO_SHELL_PART) + len(lead) + len(cwd_part)
    quoted = fitted_quote(shell_line(command), USAGE_MESSAGE_CHARS - HINT_MARGIN_CHARS - fixed)
    return f"{HINT_HEAD}{NO_SHELL_PART}{lead}{quoted}{cwd_part}"


def stdin_fileno() -> int | None:
    """The file descriptor behind stdin, or ``None`` when it has none (a replaced stream)."""
    try:
        return sys.stdin.fileno()
    except (AttributeError, ValueError, OSError):
        return None


def stdin_is_pipe_or_file() -> bool:
    """True for a pipe or a regular file; never for a TTY or a character device (/dev/null)."""
    fileno = stdin_fileno()
    if fileno is None:
        return False
    try:
        mode = os.fstat(fileno).st_mode
    except OSError:
        return False
    return stat.S_ISFIFO(mode) or stat.S_ISREG(mode)


def read_stdin_text() -> str:
    """All of stdin as strict UTF-8 text."""
    try:
        return sys.stdin.buffer.read().decode("utf-8")
    except UnicodeDecodeError:
        raise CliError("stdin is not valid UTF-8 text", client=True) from None


def command_argv(argv: list[str]) -> list[str]:
    """``argv`` without a leading ``--``; a usage error when no command is left."""
    command = argv[1:] if argv and argv[0] == END_OF_OPTIONS else argv
    if not command:
        raise typer.BadParameter("no command given")
    return command


SHORT_OPTION_CHARS = 2
LONG_OPTION_PREFIX = "--"


def exec_option_names(ctx: typer.Context) -> tuple[str, ...]:
    """Every option name of this command (``--cwd``, ``-t``, ...), help excluded."""
    return tuple(
        name
        for param in ctx.command.params
        for name in (*getattr(param, "opts", ()), *getattr(param, "secondary_opts", ()))
        if name.startswith("-")
    )


def matched_option(word: str, names: tuple[str, ...]) -> str | None:
    """The option of ``names`` that ``word`` spells: the name itself, a long name with
    ``=VALUE`` attached, or a short name followed only by digits (``-t5``).

    Any other dash-prefixed word (``-tool``, ``-input``) is a program name, not an option.
    """
    for name in names:
        if word == name:
            return name
        if name.startswith(LONG_OPTION_PREFIX) and word.startswith(f"{name}="):
            return name
        is_short = len(name) == SHORT_OPTION_CHARS and not name.startswith(LONG_OPTION_PREFIX)
        rest = word[len(name) :]
        if is_short and word.startswith(name) and rest.isascii() and rest.isdigit():
            return name
    return None


def reject_misplaced_option(ctx: typer.Context, argv: list[str]) -> None:
    """A usage error when the first command word is one of exec's own options.

    exec reads its options only before the sandbox reference, so ``exec sbx -t 5 ls`` would run
    ``-t`` as the command. A dash-prefixed program after ``--`` is a command and is left alone.
    """
    if not argv or argv[0] == END_OF_OPTIONS or not argv[0].startswith("-"):
        return
    option = matched_option(argv[0], exec_option_names(ctx))
    if option is None:
        return
    raise typer.BadParameter(
        f"{echo_value(argv[0])} came after the sandbox name; exec options go before it: "
        f"sandfort exec {option} ... {SANDBOX_METAVAR} -- <command> (to run a command that "
        "starts with a dash, put it after --)",
        param_hint=option,
    )


def exec_command(
    ctx: typer.Context,
    sandbox_id: Annotated[str, typer.Argument(metavar=SANDBOX_METAVAR, help="Sandbox id or name.")],
    argv: Annotated[
        list[str], typer.Argument(metavar="<argv>...", help="Command and arguments to run.")
    ],
    cwd: Annotated[str | None, typer.Option("--cwd", help="Working directory.")] = None,
    timeout_text: Annotated[
        str | None,
        typer.Option("--timeout", "-t", metavar="INTEGER", help="Timeout in seconds."),
    ] = None,
    stdin: Annotated[
        bool, typer.Option("--stdin", "-i", help="Send this command's stdin to the command.")
    ] = False,
    idempotency_key: Annotated[
        str | None,
        typer.Option(
            "--idempotency-key",
            metavar="KEY",
            help="Make the exec safe to retry: the same key and command return the first "
            "result without running again (1 to 255 printable ASCII characters).",
        ),
    ] = None,
) -> None:
    """Run a command in a sandbox; stdout/stderr are replayed and the exit code is kept.

    Exit status 125 means the platform or CLI failed before the command's own status was known.
    Exit status 120 means the command exited 0 but the server had stopped it or cut its output
    (stop_reason set, or truncated output); a sentence on stderr names the reason. --json adds
    "ok": the same test as ExecResult.ok in the SDK.
    Pass -i to forward stdin (UTF-8 text); without it stdin is never read.

    On exit status 127 (command not found) or 126 (found but not executable) a hint line
    follows on stderr; with --json the result object carries it instead as a "hint" string,
    a key present only for those two. A shell builtin such as cd gets a one-line note on stderr.

    With --idempotency-key KEY a repeat of the same command returns the first result and does
    not run it again; a note on stderr says so, and --json carries "replayed": true.
    """
    reject_empty_name(sandbox_id, SANDBOX_METAVAR)
    reject_misplaced_option(ctx, argv)
    reject_empty_option(cwd, "--cwd")
    timeout = (
        None
        if timeout_text is None
        else parse_whole_number(timeout_text, "--timeout", high=MAX_TIMEOUT_S)
    )
    command = command_argv(argv)
    check_idempotency_key(idempotency_key)
    if not stdin and stdin_is_pipe_or_file():
        typer.echo(STDIN_NOT_FORWARDED, err=True)
    with ref_errors(PLATFORM_ERROR_EXIT_CODE, sandbox_id), open_client() as client:
        stdin_text = read_stdin_text() if stdin else None
        sandbox = client.get(resolve_sandbox_id(client, sandbox_id))
        try:
            if timeout is None:
                result = sandbox.process_exec(
                    argv=command, cwd=cwd, stdin=stdin_text, idempotency_key=idempotency_key
                )
            else:
                result = sandbox.process_exec(
                    argv=command,
                    cwd=cwd,
                    stdin=stdin_text,
                    timeout_s=timeout,
                    idempotency_key=idempotency_key,
                )
        except OverflowError:  # the socket timeout cannot hold the value (capped above anyway)
            raise CliError(TIMEOUT_TOO_LARGE) from None
    json_output = app_state(ctx).json_output
    stderr_line_open = not json_output and bool(result.stderr) and not result.stderr.endswith("\n")
    not_found = exit_hint(
        ctx,
        sandbox_id,
        command,
        result.exit_code,
        cwd_given=cwd is not None,
        stderr=result.stderr,
    )
    note = builtin_note(command)
    if json_output:
        print_json(
            {
                **asdict(result),
                "ok": result.ok,
                **({} if not_found is None else {"hint": not_found}),
            }
        )
    else:
        # Program output is relayed as it is (never masked); only the string sequences a
        # terminal acts on (OSC, DCS, SOS, PM, APC) are dropped.
        typer.echo(strip_dangerous_terminal(result.stdout), nl=False)
        typer.echo(strip_dangerous_terminal(result.stderr), nl=False, err=True)
        if result.timed_out:
            if stderr_line_open:
                typer.echo(err=True)
                stderr_line_open = False
            typer.echo(timeout_message(sandbox_id, timeout), err=True)
        if not_found is not None:
            if stderr_line_open:
                typer.echo(err=True)
                stderr_line_open = False
            typer.echo(not_found, err=True)
    if note is not None:
        if stderr_line_open:
            typer.echo(err=True)
            stderr_line_open = False
        typer.echo(note, err=True)
    if result.replayed:
        if not json_output and stderr_line_open:
            typer.echo(err=True)
            stderr_line_open = False
        typer.echo(REPLAYED_NOTE, err=True)
    if result.sandbox_stopped:
        if not json_output and stderr_line_open:
            typer.echo(err=True)
            stderr_line_open = False
        typer.echo(
            "sandfort: the sandbox has stopped; start it again with: "
            f"sandfort sandbox start {sandbox_id}",
            err=True,
        )
    exit_code = result.exit_code
    if result.timed_out and exit_code == 0:
        exit_code = TIMED_OUT_EXIT_CODE
    elif exit_code == 0 and not result.ok:
        if not json_output and stderr_line_open:
            typer.echo(err=True)
            stderr_line_open = False
        typer.echo(not_ok_sentence(result.stop_reason, truncated=result.truncated), err=True)
        exit_code = NOT_OK_EXIT_CODE
    if stderr_line_open and (result.stop_reason is not None or result.truncated):
        # The server's own stop sentence ends the stderr text without a newline.
        typer.echo(err=True)
    raise typer.Exit(exit_code)
