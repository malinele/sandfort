"""Where ``sandfort login`` gets the api key from, before it ever prompts.

The order is ``--api-key``, then ``--key-file PATH``, then ``SANDFORT_API_KEY``, then the file
named by ``SANDFORT_API_KEY_FILE``. ``--key-stdin`` reads the key from one line of stdin instead
of all of them. When none is given the key is prompted for on a terminal, and read from one line
of stdin when stdin is not a terminal (``printf '%s\\n' "$KEY" | sandfort login``), which keeps
the key out of argv. Empty stdin is a usage error naming the sources instead of a silent wait.
"""

import sys

import typer

from sandfort_cli.config import (
    API_KEY_ENV,
    API_KEY_FILE_ENV,
    KEY_FILE_MAX_LINES,
    KEY_FILE_READ_LIMIT,
    MALFORMED_KEY_MESSAGE,
    check_configured_key,
    key_from_file_variable,
    read_key_file,
)

KEY_FILE_OPTION = "--key-file"
KEY_STDIN_OPTION = "--key-stdin"
STDIN_LABEL = "stdin"
# Where a key came from, as the subject of a full sentence ("<subject> is malformed ...").
STDIN_SUBJECT = "the api key read from stdin"
KEY_FILE_SUBJECT = f"the api key in the {KEY_FILE_OPTION} file"
ENV_SUBJECT = f"the api key in {API_KEY_ENV}"
ENV_FILE_SUBJECT = f"the api key in the file named by {API_KEY_FILE_ENV}"
KEY_PROMPT_HINT = "Paste the API key and press Enter; the input is hidden."
KEY_FROM_STDIN_NOTE = "Api key: read from stdin"
NO_KEY_SOURCE_MESSAGE = (
    f"no api key given; pass {KEY_FILE_OPTION} PATH, set {API_KEY_ENV} or "
    f"{API_KEY_FILE_ENV}, or pipe the key on stdin (one line, see {KEY_STDIN_OPTION})"
)
BOTH_KEY_OPTIONS_MESSAGE = f"give either --api-key or {KEY_FILE_OPTION}, not both"
STDIN_ONE_LINE_MESSAGE = "stdin must hold exactly one key line"
KEY_STDIN_EMPTY_MESSAGE = (
    f"{KEY_STDIN_OPTION} was given but stdin holds no api key; pipe the key as one line "
    f"(printf '%s\\n' \"$KEY\" | sandfort login {KEY_STDIN_OPTION})"
)
KEY_STDIN_CONFLICT_MESSAGE = (
    f"{KEY_STDIN_OPTION} cannot be combined with --api-key or {KEY_FILE_OPTION}"
)


def stdin_is_tty() -> bool:
    """Whether stdin is a terminal a person can type a hidden key into."""
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):  # no stdin, or a closed one
        return False


def key_from_option_file(raw_path: str) -> str:
    """The checked key from ``--key-file``; the errors are those of ``SANDFORT_API_KEY_FILE``."""
    try:
        key = read_key_file(raw_path, KEY_FILE_OPTION)
    except typer.BadParameter as exc:
        raise typer.BadParameter(exc.message, param_hint=KEY_FILE_OPTION) from None
    check_configured_key(key, KEY_FILE_OPTION, KEY_FILE_SUBJECT)
    return key


def key_without_prompt(
    api_key: str | None, key_file: str | None, *, api_key_from_flag: bool
) -> str | None:
    """The key from the first non-interactive source that has one; ``None`` when none has.

    ``api_key`` is what typer resolved for ``--api-key`` (the option or ``SANDFORT_API_KEY``);
    ``api_key_from_flag`` says it came from the command line, which wins over a key file. A key
    file wins over the environment.
    """
    if api_key_from_flag and api_key is not None:
        if key_file is not None:
            raise typer.BadParameter(BOTH_KEY_OPTIONS_MESSAGE, param_hint=KEY_FILE_OPTION)
        return api_key
    if key_file is not None:
        return key_from_option_file(key_file)
    if api_key is not None:
        check_configured_key(api_key, API_KEY_ENV, ENV_SUBJECT)
        return api_key
    return key_from_file_variable(ENV_FILE_SUBJECT)


def reject_key_stdin_conflict(
    api_key: str | None, key_file: str | None, *, api_key_from_flag: bool
) -> None:
    """``--key-stdin`` names the source; ``--api-key`` or ``--key-file`` would name another."""
    if key_file is not None or (api_key_from_flag and api_key is not None):
        raise typer.BadParameter(KEY_STDIN_CONFLICT_MESSAGE, param_hint=KEY_STDIN_OPTION)


def malformed_stdin_key(hint: str) -> typer.BadParameter:
    """The usage error for stdin input that cannot be a key: a full sentence naming stdin."""
    return typer.BadParameter(f"{STDIN_SUBJECT} {MALFORMED_KEY_MESSAGE}", param_hint=hint)


def stdin_key_lines(hint: str = STDIN_LABEL) -> list[str]:
    """The non-blank lines of stdin, at most two (a second one is already too many).

    Stdin is read as text through ``sys.stdin`` itself, so a base url prompted for first has
    already taken its line. A line longer than ``KEY_FILE_READ_LIMIT`` or input that is not
    UTF-8 is a malformed key (nothing of it is echoed); a byte order mark is ignored.
    """
    lines: list[str] = []
    try:
        for _ in range(KEY_FILE_MAX_LINES):
            raw = sys.stdin.readline(KEY_FILE_READ_LIMIT)
            if not raw:
                break
            if len(raw) >= KEY_FILE_READ_LIMIT and not raw.endswith("\n"):
                raise malformed_stdin_key(hint)
            text = raw.lstrip("\ufeff").strip()
            if text:
                lines.append(text)
                if len(lines) > 1:
                    break
    except UnicodeError:  # stdin is not valid text: the same usage error as a malformed key
        raise malformed_stdin_key(hint) from None
    return lines


def key_from_stdin(explicit: bool = False) -> str | None:
    """The one key line on stdin, stripped and checked; ``None`` when stdin holds no key.

    ``explicit`` says ``--key-stdin`` was given, which names the option in the errors (else the
    errors name ``stdin``). More than one non-blank line, or a key that cannot go into the
    Authorization header, is a usage error naming stdin as the source; the key is never echoed.
    """
    hint = KEY_STDIN_OPTION if explicit else STDIN_LABEL
    try:
        lines = stdin_key_lines(hint)
    except (AttributeError, OSError, ValueError):  # no stdin, or a closed one: no key
        return None
    if len(lines) > 1:
        raise typer.BadParameter(STDIN_ONE_LINE_MESSAGE, param_hint=hint)
    if not lines:
        return None
    check_configured_key(lines[0], hint, STDIN_SUBJECT)
    return lines[0]


def reads_key_from_stdin(key_stdin: bool) -> bool:
    """Whether the key comes from a stdin line: asked for, or no terminal to prompt on."""
    return key_stdin or not stdin_is_tty()


def no_key_message(explicit_stdin: bool = False) -> str:
    """Why a login has no key: with ``--key-stdin`` stdin is the only source asked for, so the
    message says it held nothing; else all the sources are named."""
    return KEY_STDIN_EMPTY_MESSAGE if explicit_stdin else NO_KEY_SOURCE_MESSAGE


def no_key_source_error(explicit_stdin: bool = False) -> typer.BadParameter:
    """The usage error (exit 2) for a login that was given no key and has none on stdin."""
    hint = KEY_STDIN_OPTION if explicit_stdin else KEY_FILE_OPTION
    return typer.BadParameter(no_key_message(explicit_stdin), param_hint=hint)


def stdin_not_text_error() -> typer.BadParameter:
    """The usage error for a key prompt whose stdin is not valid text."""
    return malformed_stdin_key(STDIN_LABEL)
