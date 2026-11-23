"""Rendering helpers: rich tables for humans, raw json for scripts, and error reporting."""

import ast
import json
import os
import re
import unicodedata
from collections.abc import Callable, Container, Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, NamedTuple

import httpx
import typer
from rich.console import Console
from rich.text import Text
from sandfort_sdk import (
    ApiError,
    InvalidResponseError,
    IsolationInfo,
    RequestTimedOut,
    SandboxFailedError,
    SandboxInfo,
    SandboxTimeoutError,
    SandfortSDKError,
    TransportError,
)
from sandfort_sdk.exceptions import request_id_tail
from typer import main as typer_main
from typer.core import TyperArgument, TyperCommand

from sandfort_cli.error_hints import hint_for, plain_error_names
from sandfort_cli.escapes import (
    CSI_SEQUENCE_RE,
    DANGEROUS_SEQUENCE_RE,
    without_escape_sequences,
)
from sandfort_cli.name_rules import plain_name_rule, plain_name_rules
from sandfort_cli.sanitise import (
    ELLIPSIS,
    MAX_ECHOED_VALUE_CHARS,
    MAX_RAW_CHARS,
    MAX_RELAYED_CHARS,
    MAX_RELAYED_CODE_CHARS,
    MAX_RELAYED_DEPTH,
    MAX_RELAYED_ENTRIES,
    MAX_RELAYED_ID_CHARS,
    USAGE_MESSAGE_CHARS,
    caller_key,
    clean_value,
    flatten_text,
    is_invisible,
    sanitise_text,
    scrub_local,
)
from sandfort_cli.table_layout import (
    default_free_columns,
    hidden_columns,
    layout_table,
    whole_column_table,
)

# The text helpers moved to sanitise.py and the escape patterns to escapes.py; these names keep
# their import path from here.
__all__ = [
    "CSI_SEQUENCE_RE",
    "DANGEROUS_SEQUENCE_RE",
    "ELLIPSIS",
    "flatten_text",
    "without_escape_sequences",
]

# Width used when stdout is not a terminal and COLUMNS is unset: in effect unbounded, since a
# pipe takes long lines. Decision: a piped table is never cut and never loses a column, because
# scripts parse it (a cut cell or a dropped column would be silent data loss). Rich sizes a
# table to its content, so nothing is padded to this width and the layout (``plan_layout``)
# finds everything fitting. Only a terminal, or an explicit COLUMNS, makes a table narrow.
PIPED_TABLE_WIDTH = 1_000_000
COLUMNS_ENV = "COLUMNS"
# Longest LABELS / REASON cell in the sandbox table; longer values end in an ellipsis.
TABLE_CELL_MAX = 32
# The field-view row that lists every label whole (one ``key=value`` per line).
LABELS_FIELD = "labels"
ID_FIELD_RE = re.compile(r"(?:^|[ _])id$", re.IGNORECASE)
HIDDEN_COLUMNS_NOTE = "(hidden at this width: {}; widen the terminal or use --json)"
EXIT_FAILURE = 1
# Same convention as docker run: the platform or CLI failed, not the remote command.
PLATFORM_ERROR_EXIT_CODE = 125
HTTP_CONFLICT = 409
# Phrases of the platform's 409 answers for a call on a sandbox that is not running: the toolbox
# guard ("... require a started sandbox") and the driver ("instance ... is not running").
NOT_RUNNING_PHRASES = ("not started", "not running", "require a started", "requires a started")
CLI_ERROR_CODE = "CLI_ERROR"
# How the SDK's create-timeout message says its cleanup removed the sandbox.
DELETED_PHRASE = "was deleted"
TABLE_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
SANDBOX_FAILED_CODE = "SANDBOX_FAILED"
# ``error.source`` of a json error for which no request reached the server (``never_sent``).
CLIENT_SOURCE = "client"

# Deepest json level of a success payload that is walked string by string; a deeper level
# becomes the ellipsis (a hostile reply cannot make the walk recurse without bound).
MAX_PAYLOAD_DEPTH = 32
# A python string literal as ``repr`` writes it: single or double quoted, backslash escapes.
REPR_LITERAL_RE = re.compile(r"""'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*\"""")

# Set by the main callback from the global ``--json`` flag; read by ``cli_errors``.
_json_errors: ContextVar[bool] = ContextVar("sandfort_cli_json_errors", default=False)

# Positional placeholders are written in angle brackets; curly braces are for REST routes.
ANGLE_METAVAR_PREFIX = "<"


class AngleArgument(TyperArgument):
    """A typer argument whose explicit ``<...>`` metavar is shown on the usage line as written
    (in ``[]`` when optional) instead of typer's curly braces. Any other argument, and every
    non-usage use of the metavar, is exactly typer's."""

    def make_metavar(self, ctx: Any, *, usage: bool = False) -> str:
        metavar = self.metavar
        if usage and metavar is not None and metavar.startswith(ANGLE_METAVAR_PREFIX):
            return metavar if self.required else f"[{metavar}]"
        return super().make_metavar(ctx, usage=usage)


# Set on a command function by :func:`accepts_negative_numbers`; read by ``AngleCommand``.
NEGATIVE_NUMBER_ATTR = "sandfort_negative_numbers"
NEGATIVE_INT_RE = re.compile(r"-\d+")
OPTIONS_END = "--"


def accepts_negative_numbers[CommandFunction: Callable[..., Any]](
    function: CommandFunction,
) -> CommandFunction:
    """Mark a command function whose positional arguments may be negative whole numbers, so
    ``cmd sbx -5`` reaches the argument check instead of failing as an unknown option."""
    setattr(function, NEGATIVE_NUMBER_ATTR, True)
    return function


def hoist_negative_numbers(args: list[str], value_options: frozenset[str]) -> list[str]:
    """``args`` with every lone negative whole number that is not an option's value moved behind
    ``--`` (the other tokens keep their order), so the parser reads it as a positional value.

    Unchanged when there is none, or when the caller already used ``--``.
    """
    if OPTIONS_END in args:
        return args
    kept: list[str] = []
    hoisted: list[str] = []
    takes_value = False
    for arg in args:
        if takes_value:
            kept.append(arg)
            takes_value = False
        elif arg in value_options:
            kept.append(arg)
            takes_value = True
        elif NEGATIVE_INT_RE.fullmatch(arg):
            hoisted.append(arg)
        else:
            kept.append(arg)
    return [*kept, OPTIONS_END, *hoisted] if hoisted else args


class AngleCommand(TyperCommand):
    """A typer command that, when its function is marked with
    :func:`accepts_negative_numbers`, reads a lone negative number as a positional value."""

    def parse_args(self, ctx: Any, args: list[str]) -> list[str]:
        if getattr(self.callback, NEGATIVE_NUMBER_ATTR, False):
            value_options = frozenset(
                name
                for param in self.params
                if getattr(param, "is_flag", True) is False
                for name in (*getattr(param, "opts", ()), *getattr(param, "secondary_opts", ()))
            )
            args = hoist_negative_numbers(list(args), value_options)
        return super().parse_args(ctx, args)


def install_angle_arguments() -> None:
    """Make typer build :class:`AngleArgument` and :class:`AngleCommand` for every argument and
    command.

    typer's own classes are left untouched (the old fix replaced a method for the whole
    process). typer looks the classes up by name in ``typer.main`` when it builds a command, so
    rebinding those names is enough; it is idempotent. This module is imported by every command
    module, so the result does not depend on which of them is imported first. The sanitiser is
    not touched here: its url fragment mask keeps a closing parenthesis on its own.
    """
    if vars(typer_main).get("TyperArgument") is not AngleArgument:
        vars(typer_main)["TyperArgument"] = AngleArgument
    if vars(typer_main).get("TyperCommand") is not AngleCommand:
        vars(typer_main)["TyperCommand"] = AngleCommand


install_angle_arguments()


class CliError(Exception):
    """``error: <message>``, exit status 1; ``client=True`` only for bad local input found
    before any request of the step was sent (json ``"source": "client"``)."""

    def __init__(self, *args: object, client: bool = False) -> None:
        super().__init__(*args)
        self.client = client


@dataclass(frozen=True)
class AppState:
    """Global options shared with every subcommand through ``ctx.obj``."""

    json_output: bool = False


CONTROL_CATEGORY = "Cc"
EMPTY_MESSAGE = "must not be empty"
# Added when the name held something, but only terminal sequences or control characters.
AFTER_SEQUENCES_NOTE = " (after removing terminal control sequences)"
# The printed name of a label key that sanitising changed and left empty or whitespace only (a key
# made of invisible characters would print as '').
INVISIBLE_KEY_NAME = "(invisible)"
SPACE = " "


def is_blank_char(char: str) -> bool:
    """True for a character that shows nothing: whitespace, an invisible character (zero-width
    space, joiners, bidi marks and the other default-ignorable code points) or a control
    character (C0, DEL, C1, the single-byte CSI introducer among them)."""
    return char.isspace() or is_invisible(char) or unicodedata.category(char) == CONTROL_CATEGORY


def is_blank(text: str) -> bool:
    """True when ``text`` is empty or made only of :func:`is_blank_char` characters once its
    terminal escape sequences are removed (so ``ESC [ 0 m`` alone is blank). A text that mixes
    such characters with visible ones is not blank (the sanitiser cleans it on output)."""
    return all(is_blank_char(char) for char in without_escape_sequences(text))


def reject_empty_name(name: str, param_hint: str = "<name>") -> None:
    """An empty or blank name (:func:`is_blank`) is a usage error (exit 2), found before any
    request is sent: nothing of it is visible. A name that held terminal escape sequences or
    control characters says they were removed (it was not typed empty)."""
    if is_blank(name):
        raise typer.BadParameter(EMPTY_MESSAGE + empty_note(name), param_hint=param_hint)


def empty_note(name: str) -> str:
    """:data:`AFTER_SEQUENCES_NOTE` when the blank ``name`` held an escape sequence or a control
    character, else nothing (an empty or whitespace-only name is plainly empty)."""
    has_sequence = without_escape_sequences(name) != name
    has_control = any(unicodedata.category(char) == CONTROL_CATEGORY for char in name)
    return AFTER_SEQUENCES_NOTE if has_sequence or has_control else ""


def reject_empty_option(value: str | None, option: str) -> None:
    """:func:`reject_empty_name` for an optional option value; ``None`` (not given) passes."""
    if value is not None:
        reject_empty_name(value, option)


def reject_empty_options(values: Sequence[str] | None, option: str) -> None:
    """:func:`reject_empty_name` for every value of a repeatable option."""
    for value in values or ():
        reject_empty_name(value, option)


def app_state(ctx: typer.Context) -> AppState:
    obj = ctx.obj
    return obj if isinstance(obj, AppState) else AppState()


def writes_to_terminal(console: Console) -> bool:
    """True when the console's file is a tty. Rich's ``is_terminal`` is not used: FORCE_COLOR
    makes it true for a pipe, and the width then falls back to 80 columns."""
    isatty = getattr(console.file, "isatty", None)
    if isatty is None:
        return False
    try:
        return bool(isatty())
    except ValueError:  # a closed stream
        return False


def _console() -> Console:
    """A terminal (or a set COLUMNS) keeps Rich's width; a pipe without COLUMNS is not cut."""
    # Built per call so it binds to whatever stdout is current (tests swap it).
    probe = Console()
    if writes_to_terminal(probe) or (os.environ.get(COLUMNS_ENV) or "").isdigit():
        return probe
    return Console(width=PIPED_TABLE_WIDTH)


def _json_default(value: object) -> str:
    """json fallback: a datetime as ISO 8601; anything else is still a programming error."""
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def print_json(payload: Any) -> None:
    typer.echo(json.dumps(payload, indent=2, sort_keys=True, default=_json_default))


def print_table(
    title: str,
    columns: Sequence[str],
    rows: Sequence[Sequence[str | Text]],
    whole_columns: Sequence[str] = (),
    free: Sequence[str] | None = None,
    uncut: Sequence[str] = (),
) -> None:
    """Print a table; cells of ``whole_columns`` are never truncated or folded.

    Without ``whole_columns`` every column stays on one line (see :mod:`sandfort_cli.table_layout`):
    the columns named in ``free`` (free text, highest priority first; by default the columns
    with a free-text header, else the last column) are cut with an ellipsis or dropped when the
    width is short, and every other column keeps its full width. With ``whole_columns``, those
    columns get their full width and the others may fold onto several lines.
    A column of ``free`` also named in ``uncut`` (an id) is never cut, only dropped whole.
    When columns are dropped, one note on stderr names them. A cell given as :class:`Text`
    keeps its own wrap and overflow settings.
    """
    console = _console()
    hidden: tuple[str, ...] = ()
    if whole_columns:
        table = whole_column_table(title, columns, rows, whole_columns)
    else:
        marked = default_free_columns(columns) if free is None else free
        table, layout = layout_table(
            title, columns, rows, marked, console.width, cut_at_cluster, uncut
        )
        console.width = layout.width
        hidden = hidden_columns(columns, layout)
    console.print(table)
    if hidden:
        typer.echo(HIDDEN_COLUMNS_NOTE.format(", ".join(hidden)), err=True)


def is_id_field(name: str) -> bool:
    """True for a field that holds an id (``id``, ``sandbox_id``, ``request id``)."""
    return ID_FIELD_RE.search(name) is not None


def print_fields(title: str, fields: Mapping[str, str], folded: Sequence[str] = ()) -> None:
    """A FIELD / VALUE table; the value of a field named in ``folded``, and every id value
    (users copy ids into other commands), is never cut: it keeps its line breaks and folds onto
    further lines when the width is short."""
    rows = [
        (
            name,
            Text(value, no_wrap=False, overflow="fold")
            if name in folded or is_id_field(name)
            else value,
        )
        for name, value in fields.items()
    ]
    print_table(title, ("FIELD", "VALUE"), rows)


def shown(value: object, api_key: str) -> str:
    """One server value as a success view may print it: ``str(value)`` through the sanitiser
    (terminal sequences and controls out, credentials and the caller's key masked, whitespace
    flattened), cut only at the raw bound."""
    return sanitise_text(str(value), api_key=api_key, limit=MAX_RAW_CHARS)


def scalar_text(value: object, key: str) -> str:
    """``value`` as ``--json`` prints it: a number or boolean in its json form, never through
    the text sanitiser (a typed value carries no text to mask, so ``0`` stays ``0``); a string
    sanitised like the json view; null as blank."""
    if value is None:
        return ""
    if isinstance(value, bool | int | float):
        return json.dumps(value)
    return shown(value, key)


def _free_key(name: str, taken: Container[str]) -> str:
    """``name``, or ``name#<n>`` when sanitising made two keys the same (never overwritten)."""
    if name not in taken:
        return name
    number = 2
    while f"{name}#{number}" in taken:
        number += 1
    return f"{name}#{number}"


def clean_key_names(keys: Sequence[Any], api_key: str) -> list[str]:
    """The printed name of every key of one mapping, in the mapping's order.

    A key that sanitising left as it was keeps its exact name, also one shaped like ``a#2``. A
    key that sanitising changed takes its cleaned name when that is free, else ``<name>#<n>``
    with the lowest free number (changed keys are numbered in the mapping's order). So a key
    with a hidden character can never take the plain name of a genuine key, whichever order
    the server sent them in. A non-empty key made only of invisible characters (cleaned to a
    blank name) is named :data:`INVISIBLE_KEY_NAME`, numbered like the others on collision.
    """
    raw = [str(key) for key in keys]
    cleaned = [visible_key_name(text, shown(text, api_key)) for text in raw]
    taken: set[str] = set()
    names: dict[int, str] = {}
    for index, (text, name) in enumerate(zip(raw, cleaned, strict=True)):
        if name == text and name not in taken:
            taken.add(name)
            names[index] = name
    for index, name in enumerate(cleaned):
        if index not in names:
            names[index] = _free_key(name, taken)
            taken.add(names[index])
    return [names[index] for index in range(len(cleaned))]


def visible_key_name(raw: str, cleaned: str) -> str:
    """``cleaned``, or :data:`INVISIBLE_KEY_NAME` when sanitising changed the key and left
    nothing visible of it (empty or whitespace only after cleaning, so a key of invisible
    characters, or of whitespace and a hidden character, is named too). A key sanitising left
    as typed keeps its name, a whitespace-only one included."""
    if cleaned != raw and not cleaned.strip():
        return INVISIBLE_KEY_NAME
    return cleaned


def clean_strings(value: Any, api_key: str, depth: int = 0) -> Any:
    """``value`` (json-like) with every string, mapping keys included, sanitised by :func:`shown`.

    Numbers, booleans and ``None`` stay typed and the shape is kept (no entry cap, unlike
    :func:`clean_value`, which is for error text). A level deeper than ``MAX_PAYLOAD_DEPTH``
    becomes the ellipsis. Keys that collide after sanitising are named by
    :func:`clean_key_names` (a key that was already clean keeps its plain name).
    """
    if isinstance(value, str):
        return shown(value, api_key)
    if isinstance(value, Mapping | list | tuple) and depth >= MAX_PAYLOAD_DEPTH:
        return ELLIPSIS
    if isinstance(value, Mapping):
        names = clean_key_names(list(value.keys()), api_key)
        return {
            name: clean_strings(item, api_key, depth + 1)
            for name, item in zip(names, value.values(), strict=True)
        }
    if isinstance(value, list | tuple):
        return [clean_strings(item, api_key, depth + 1) for item in value]
    return value


def is_spaces_only(value: object) -> bool:
    """True for a non-empty string of plain spaces (a label value the sanitiser would flatten
    to nothing)."""
    return isinstance(value, str) and value != "" and value.strip(SPACE) == ""


def exact_labels(cleaned: Any, raw: Mapping[str, Any] | None) -> Any:
    """The ``--json`` labels mapping ``cleaned`` (from :func:`clean_strings`) with every value
    that is only spaces put back exactly as stored; nothing else changes."""
    if not isinstance(cleaned, dict) or not raw or len(cleaned) != len(raw):
        return cleaned
    return {
        name: value if is_spaces_only(value) else shown_value
        for (name, shown_value), value in zip(cleaned.items(), raw.values(), strict=True)
    }


def sandbox_payload(info: SandboxInfo) -> dict[str, Any]:
    """The sandbox object for ``--json``: every datetime as an ISO 8601 string, every string
    from the server sanitised (numbers, booleans and null stay typed)."""
    payload = asdict(info)
    for name, value in payload.items():
        if isinstance(value, datetime):
            payload[name] = value.isoformat()
    cleaned: dict[str, Any] = clean_strings(payload, caller_key())
    cleaned["labels"] = exact_labels(cleaned.get("labels"), info.labels)
    return cleaned


def label_pair(key: str, value: str, name: str, api_key: str) -> str:
    """One label as ``key=value``: the joined text is sanitised as a whole (a secret spanning
    the ``=`` is masked), then split at its first ``=``. When the key part is the key as
    sanitised alone, it is replaced by ``name`` (:func:`clean_key_names`); otherwise the
    joined text is printed as it was sanitised. A value of only spaces is quoted
    (``key="  "``) so the spaces are visible."""
    if is_spaces_only(value):
        return f'{name}="{value}"'
    joined = shown(f"{key}={value}", api_key)
    head, separator, tail = joined.partition("=")
    if separator and head == shown(key, api_key):
        return f"{name}={tail}"
    return joined


def label_pairs(labels: Mapping[str, str], api_key: str) -> list[str]:
    """Every label as a sanitised ``key=value`` (:func:`label_pair`); the keys are named by
    :func:`clean_key_names` exactly as in ``--json``, so two keys that sanitise alike never
    print as one key twice."""
    names = clean_key_names(list(labels.keys()), api_key)
    return [
        label_pair(str(key), str(value), name, api_key)
        for (key, value), name in zip(labels.items(), names, strict=True)
    ]


def labels_lines(labels: Mapping[str, str]) -> str:
    """Every label as ``key=value`` (:func:`label_pairs`), one per line, each sanitised like
    the table cell (so a line break inside a label cannot fake another label) but never cut to
    the cell width; ``-`` when there is none."""
    lines = label_pairs(labels, caller_key())
    return "\n".join(lines) if lines else "-"


def sandbox_fields(info: SandboxInfo) -> dict[str, str]:
    key = caller_key()

    def cell(value: object) -> str:
        return shown(value, key)

    fields = {
        "id": cell(info.id),
        "name": cell(info.name),
        "state": cell(info.state),
        "isolation": cell(info.isolation),
        "snapshot": cell(info.snapshot) if info.snapshot else "-",
        "cpu_millicores": cell(info.resources.cpu_millicores),
        "memory_mib": cell(info.resources.memory_mib),
        "disk_gib": cell(info.resources.disk_gib),
        "block_network": str(info.block_network).lower(),
        "public": str(info.public).lower(),
        "auto_stop_minutes": cell(info.auto_stop_minutes),
        "auto_delete_minutes": cell(info.auto_delete_minutes),
        LABELS_FIELD: labels_lines(info.labels),
    }
    if info.created_at is not None:
        fields["created_at"] = info.created_at.isoformat()
    if info.updated_at is not None:
        fields["updated_at"] = info.updated_at.isoformat()
    if info.error_reason:
        fields["error_reason"] = cell(info.error_reason)
    if info.error_code:
        fields["error_code"] = cell(info.error_code)
    if info.stop_cause:
        fields["stop_cause"] = cell(info.stop_cause)
    if info.stopped_at is not None:
        fields["stopped_at"] = info.stopped_at.isoformat()
    return fields


def error_cell(info: SandboxInfo) -> str:
    """The REASON cell: ``<code>: <reason>`` when a code is set, else the reason alone; with
    neither, the stop cause (empty when there is none either)."""
    reason = info.error_reason or ""
    if not info.error_code:
        return truncate_cell(reason or info.stop_cause or "")
    return truncate_cell(f"{info.error_code}: {reason}" if reason else info.error_code)


def render_sandbox(state: AppState, info: SandboxInfo) -> None:
    if state.json_output:
        print_json(sandbox_payload(info))
    else:
        print_fields("sandbox", sandbox_fields(info), folded=(LABELS_FIELD,))


def truncate_cell(value: str, limit: int = TABLE_CELL_MAX) -> str:
    """``value`` sanitised (see :func:`shown`, which also flattens it) and cut to at most
    ``limit`` characters at a grapheme cluster boundary; a cut value ends in an ellipsis."""
    return cut_at_cluster(shown(value, caller_key()), limit)


# Extended grapheme cluster boundaries (UAX #29) from the standard library's unicodedata: the
# break classes it cannot derive from the general category are listed here.
ZWJ = "‍"
HANGUL_L = ((0x1100, 0x115F), (0xA960, 0xA97C))
HANGUL_V = ((0x1160, 0x11A7), (0xD7B0, 0xD7C6))
HANGUL_T = ((0x11A8, 0x11FF), (0xD7CB, 0xD7FB))
HANGUL_SYLLABLES = (0xAC00, 0xD7A3)
HANGUL_T_COUNT = 28
REGIONAL_INDICATORS = (0x1F1E6, 0x1F1FF)
# Extend beyond the mark categories: ZWNJ, halfwidth sound marks, emoji modifiers, tag characters.
EXTEND_RANGES = ((0x200C, 0x200C), (0xFF9E, 0xFF9F), (0x1F3FB, 0x1F3FF), (0xE0020, 0xE007F))
SPACING_MARK_RANGES = ((0x0E33, 0x0E33), (0x0EB3, 0x0EB3))
PREPEND_RANGES = (
    (0x0600, 0x0605), (0x06DD, 0x06DD), (0x070F, 0x070F), (0x0890, 0x0891), (0x08E2, 0x08E2),
    (0x0D4E, 0x0D4E), (0x110BD, 0x110BD), (0x110CD, 0x110CD), (0x111C2, 0x111C3),
    (0x1193F, 0x1193F), (0x11941, 0x11941), (0x11A3A, 0x11A3A), (0x11A84, 0x11A89),
    (0x11D46, 0x11D46), (0x11F02, 0x11F02),
)  # fmt: skip
# Extended_Pictographic (emoji-data.txt), outside the regional indicators and emoji modifiers.
PICTOGRAPHIC_RANGES = (
    (0x00A9, 0x00A9), (0x00AE, 0x00AE), (0x203C, 0x203C), (0x2049, 0x2049), (0x2122, 0x2122),
    (0x2139, 0x2139), (0x2194, 0x2199), (0x21A9, 0x21AA), (0x231A, 0x231B), (0x2328, 0x2328),
    (0x2388, 0x2388), (0x23CF, 0x23CF), (0x23E9, 0x23F3), (0x23F8, 0x23FA), (0x24C2, 0x24C2),
    (0x25AA, 0x25AB), (0x25B6, 0x25B6), (0x25C0, 0x25C0), (0x25FB, 0x25FE), (0x2600, 0x2605),
    (0x2607, 0x2612), (0x2614, 0x2685), (0x2690, 0x2705), (0x2708, 0x2712), (0x2714, 0x2714),
    (0x2716, 0x2716), (0x271D, 0x271D), (0x2721, 0x2721), (0x2728, 0x2728), (0x2733, 0x2734),
    (0x2744, 0x2744), (0x2747, 0x2747), (0x274C, 0x274C), (0x274E, 0x274E), (0x2753, 0x2755),
    (0x2757, 0x2757), (0x2763, 0x2767), (0x2795, 0x2797), (0x27A1, 0x27A1), (0x27B0, 0x27B0),
    (0x27BF, 0x27BF), (0x2934, 0x2935), (0x2B05, 0x2B07), (0x2B1B, 0x2B1C), (0x2B50, 0x2B50),
    (0x2B55, 0x2B55), (0x3030, 0x3030), (0x303D, 0x303D), (0x3297, 0x3297), (0x3299, 0x3299),
    (0x1F000, 0x1F0FF), (0x1F10D, 0x1F10F), (0x1F12F, 0x1F12F), (0x1F16C, 0x1F171),
    (0x1F17E, 0x1F17F), (0x1F18E, 0x1F18E), (0x1F191, 0x1F19A), (0x1F1AD, 0x1F1E5),
    (0x1F201, 0x1F20F), (0x1F21A, 0x1F21A), (0x1F22F, 0x1F22F), (0x1F232, 0x1F23A),
    (0x1F23C, 0x1F23F), (0x1F249, 0x1F3FA), (0x1F400, 0x1F53D), (0x1F546, 0x1F64F),
    (0x1F680, 0x1F6FF), (0x1F774, 0x1F77F), (0x1F7D5, 0x1F7FF), (0x1F80C, 0x1F80F),
    (0x1F848, 0x1F84F), (0x1F85A, 0x1F85F), (0x1F888, 0x1F88F), (0x1F8AE, 0x1F8FF),
    (0x1F90C, 0x1F93A), (0x1F93C, 0x1F945), (0x1F947, 0x1FAFF), (0x1FC00, 0x1FFFD),
)  # fmt: skip
# Indic conjuncts (GB9c): the viramas that link two consonants, and the script blocks whose
# letters at offsets 0x15-0x3A (plus the nukta forms listed) are InCB=Consonant.
INDIC_LINKERS = frozenset("्্્୍్്")
INDIC_BLOCKS = (0x0900, 0x0980, 0x0A80, 0x0B00, 0x0C00, 0x0D00)
INDIC_CONSONANT_SPAN = (0x15, 0x3A)
INDIC_EXTRA_CONSONANTS = (
    (0x0958, 0x095F), (0x0978, 0x097F), (0x09DC, 0x09DD), (0x09DF, 0x09DF), (0x09F0, 0x09F1),
    (0x0AF9, 0x0AF9), (0x0B5C, 0x0B5D), (0x0B5F, 0x0B5F), (0x0B71, 0x0B71), (0x0C58, 0x0C5A),
)  # fmt: skip
HARD_BREAK_CLASSES = frozenset({"CR", "LF", "Control"})
EXTEND_CLASSES = frozenset({"Extend", "Linker"})


def _in(code: int, ranges: Sequence[tuple[int, int]]) -> bool:
    return any(low <= code <= high for low, high in ranges)


def _is_indic_consonant(char: str) -> bool:
    code = ord(char)
    if _in(code, INDIC_EXTRA_CONSONANTS):
        return True
    low, high = INDIC_CONSONANT_SPAN
    in_span = any(low <= code - base <= high for base in INDIC_BLOCKS)
    return in_span and unicodedata.category(char) == "Lo"


def _hangul_class(code: int) -> str | None:
    if _in(code, HANGUL_L):
        return "L"
    if _in(code, HANGUL_V):
        return "V"
    if _in(code, HANGUL_T):
        return "T"
    if HANGUL_SYLLABLES[0] <= code <= HANGUL_SYLLABLES[1]:
        return "LV" if (code - HANGUL_SYLLABLES[0]) % HANGUL_T_COUNT == 0 else "LVT"
    return None


def _break_class(char: str) -> str:
    """The grapheme break class of ``char`` (InCB consonants and linkers apart)."""
    code = ord(char)
    category = unicodedata.category(char)
    if char in "\r\n":
        return "CR" if char == "\r" else "LF"
    if char == ZWJ:
        return "ZWJ"
    if char in INDIC_LINKERS:
        return "Linker"
    if _in(code, PREPEND_RANGES):
        return "Prepend"
    if category in ("Mn", "Me") or _in(code, EXTEND_RANGES):
        return "Extend"
    if category in ("Cc", "Cf", "Zl", "Zp"):
        return "Control"
    if category == "Mc" or _in(code, SPACING_MARK_RANGES):
        return "SpacingMark"
    if REGIONAL_INDICATORS[0] <= code <= REGIONAL_INDICATORS[1]:
        return "RI"
    if _in(code, PICTOGRAPHIC_RANGES):
        return "Pict"
    if _is_indic_consonant(char):
        return "Consonant"
    return _hangul_class(code) or "Other"


class _ClusterState(NamedTuple):
    """What the rules need to know about the cluster so far: the run of regional indicators,
    an emoji (with extenders) and its trailing joiner, an open or linked Indic conjunct."""

    regional: int = 0
    pictographic: bool = False
    pictographic_zwj: bool = False
    conjunct: bool = False
    linked: bool = False


def _hangul_joins(prev: str, cur: str) -> bool:
    """GB6-GB8: Hangul syllable sequences."""
    if prev == "L":
        return cur in ("L", "V", "LV", "LVT")
    if prev in ("LV", "V"):
        return cur in ("V", "T")
    return prev in ("LVT", "T") and cur == "T"


def _joins(prev: str, cur: str, state: _ClusterState) -> bool:
    """True when there is no boundary between a character of class ``prev`` and one of ``cur``."""
    if prev == "CR" and cur == "LF":
        return True
    if prev in HARD_BREAK_CLASSES or cur in HARD_BREAK_CLASSES:
        return False
    if _hangul_joins(prev, cur):
        return True
    if cur in EXTEND_CLASSES or cur in ("ZWJ", "SpacingMark") or prev == "Prepend":
        return True
    if cur == "Consonant" and state.linked:
        return True
    if prev == "ZWJ" and cur == "Pict" and state.pictographic_zwj:
        return True
    return prev == "RI" and cur == "RI" and state.regional % 2 == 1


def _next_state(state: _ClusterState, cur: str) -> _ClusterState:
    """The state after a character of class ``cur``."""
    open_conjunct = state.conjunct and (cur in EXTEND_CLASSES or cur == "ZWJ")
    return _ClusterState(
        regional=state.regional + 1 if cur == "RI" else 0,
        pictographic=cur == "Pict" or (state.pictographic and cur in EXTEND_CLASSES),
        pictographic_zwj=cur == "ZWJ" and state.pictographic,
        conjunct=cur == "Consonant" or open_conjunct,
        linked=cur != "Consonant" and open_conjunct and (state.linked or cur == "Linker"),
    )


def grapheme_clusters(text: str) -> Iterator[str]:
    """The extended grapheme clusters of ``text`` (UAX #29), in order."""
    start = 0
    prev = ""
    state = _ClusterState()
    for index, char in enumerate(text):
        cur = _break_class(char)
        if index and not _joins(prev, cur, state):
            yield text[start:index]
            start = index
        state = _next_state(state, cur)
        prev = cur
    if text:
        yield text[start:]


def cut_at_cluster(text: str, limit: int) -> str:
    """``text`` when it fits in ``limit`` characters; else its longest prefix of whole grapheme
    clusters that fits with the ellipsis, plus the ellipsis (never half an emoji sequence, a
    base without its marks, a lone regional indicator or a conjunct cut at the virama)."""
    if len(text) <= limit:
        return text
    room = limit - len(ELLIPSIS)
    kept = 0
    for cluster in grapheme_clusters(text):
        if kept + len(cluster) > room:
            break
        kept += len(cluster)
    return text[:kept] + ELLIPSIS


def labels_cell(labels: Mapping[str, str], limit: int = TABLE_CELL_MAX) -> str:
    """``key=value`` pairs (:func:`label_pairs`) joined by commas, truncated for a table cell.

    ``limit`` is the cut; a table that lays its labels column out itself passes a large one and
    lets the layout cut to the width the terminal leaves.

    The pairs are already sanitised; the join is flattened once more, unless a value of only
    spaces is quoted in it (flattening would hide the spaces the quotes are there to show)."""
    joined = ",".join(label_pairs(labels, caller_key()))
    if any(is_spaces_only(value) for value in labels.values()):
        return cut_at_cluster(joined, limit)
    return truncate_cell(joined, limit)


def utc_cell(value: datetime | None) -> str:
    """``value`` in UTC as ``YYYY-MM-DD HH:MM:SS`` (a naive value counts as UTC); blank if None."""
    if value is None:
        return ""
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.astimezone(UTC).strftime(TABLE_TIME_FORMAT)


def render_sandboxes(state: AppState, infos: Sequence[SandboxInfo]) -> None:
    if state.json_output:
        print_json([sandbox_payload(info) for info in infos])
        return
    key = caller_key()
    rows = [
        (
            shown(info.id, key),
            shown(info.name, key),
            shown(info.state, key),
            shown(info.isolation, key),
            shown(info.resources.cpu_millicores, key),
            shown(info.resources.memory_mib, key),
            shown(info.resources.disk_gib, key),
            utc_cell(info.created_at),
            labels_cell(info.labels),
            error_cell(info),
        )
        for info in infos
    ]
    columns = (
        "ID",
        "NAME",
        "STATE",
        "ISOLATION",
        "CPU (m)",
        "MEM (MiB)",
        "DISK (GiB)",
        "CREATED",
        "LABELS",
        "REASON",
    )
    # Free text, highest priority first; STATE, ISOLATION and the numbers are never squeezed.
    print_table("sandboxes", columns, rows, free=("NAME", "REASON", "LABELS"))


def render_isolation(state: AppState, info: IsolationInfo) -> None:
    """The default tier and the tiers a create may name, as a table or the json object."""
    key = caller_key()
    if state.json_output:
        payload = {"default": info.default, "available": list(info.available)}
        print_json(clean_strings(payload, key))
        return
    rows = [(shown(tier, key), "yes" if tier == info.default else "") for tier in info.available]
    print_table("isolation", ("TIER", "DEFAULT"), rows)


def render_message(state: AppState, message: str, payload: Mapping[str, Any]) -> None:
    if state.json_output:
        print_json(dict(payload))
    else:
        typer.echo(message)


# A collection cut to ``MAX_RELAYED_ENTRIES`` stays pure; its dropped count is a sibling number
# named ``<key>_beyond_cap`` (the same name the missing scopes use).
BEYOND_CAP_SUFFIX = "_beyond_cap"
# Validation errors written out in the text line before the rest is only counted.
MAX_VALIDATION_LINES = 5
MAX_VALIDATION_LOC_PARTS = 10
VALIDATION_ERRORS_KEY = "errors"
# Text-line cap of one validation message: wide enough for a full list of allowed values (the
# twelve documented api key scopes come to about 200 characters). The json is cut as before.
MAX_VALIDATION_MESSAGE_CHARS = 600


@dataclass(frozen=True)
class RelayedEntry:
    """One kept entry of a relayed mapping: its printed name, its cleaned value and how many
    entries were cut from that value (``0`` when none)."""

    name: str
    value: Any
    omitted: int


@dataclass(frozen=True)
class RelayedMapping:
    """A relayed mapping: the json shape (cut children with their ``<key>_beyond_cap``
    sibling), the kept entries without those siblings, and how many entries were cut."""

    cleaned: dict[str, Any]
    entries: tuple[RelayedEntry, ...]
    omitted: int


def relay_mapping(value: Mapping[Any, Any], api_key: str, depth: int = 0) -> RelayedMapping:
    """The mapping branch of :func:`relay_value`, keeping the kept entries apart from the
    sibling counts so the text line can say ``and N more`` instead of the raw sibling."""
    pairs = sorted(value.items(), key=lambda pair: str(pair[0]))
    cleaned: dict[str, Any] = {}
    entries: list[RelayedEntry] = []
    for key, item in pairs[:MAX_RELAYED_ENTRIES]:
        shown_key = sanitise_text(str(key), api_key=api_key, limit=MAX_RELAYED_CODE_CHARS)
        name = _free_key(shown_key, cleaned)
        child, child_omitted = relay_value(item, api_key, depth + 1)
        cleaned[name] = child
        entries.append(RelayedEntry(name, child, child_omitted))
        if child_omitted:
            cleaned[_free_key(f"{name}{BEYOND_CAP_SUFFIX}", cleaned)] = child_omitted
    return RelayedMapping(cleaned, tuple(entries), max(0, len(pairs) - MAX_RELAYED_ENTRIES))


def _relay_mapping(
    value: Mapping[Any, Any], api_key: str, depth: int
) -> tuple[dict[str, Any], int]:
    """The mapping branch of :func:`relay_value`; sibling counts for cut children."""
    relayed = relay_mapping(value, api_key, depth)
    return relayed.cleaned, relayed.omitted


def relay_value(value: Any, api_key: str, depth: int = 0) -> tuple[Any, int]:
    """``value`` (a json-like server value) sanitised for printing, and how many entries of
    ``value`` itself were dropped by the entry cap.

    Strings are sanitised exactly as :func:`clean_value` does (also mapping keys); numbers,
    booleans and ``None`` stay; a level deeper than ``MAX_RELAYED_DEPTH`` becomes the ellipsis.
    A mapping or list holds at most ``MAX_RELAYED_ENTRIES`` entries and is never given a marker
    entry: the data stays what the server sent. A cut child of a mapping is reported by the
    sibling number ``<key>_beyond_cap``; a list has no room for a sibling, so the entries cut
    from the collections inside it are added to its own count. That count is the second result
    (the caller says it), so no cut is silent. Colliding keys are kept apart with ``#<n>``.
    """
    if isinstance(value, dict | list | tuple):
        if depth >= MAX_RELAYED_DEPTH:
            return ELLIPSIS, 0
        if isinstance(value, dict):
            return _relay_mapping(value, api_key, depth)
        return _relay_list(list(value), api_key, depth)
    return clean_value(value, api_key), 0


def _relay_list(items: list[Any], api_key: str, depth: int) -> tuple[list[Any], int]:
    """The list branch of :func:`relay_value`: the kept items, and the entries cut from the list
    itself plus those cut from the collections nested in it."""
    shown_items: list[Any] = []
    omitted = max(0, len(items) - MAX_RELAYED_ENTRIES)
    for item in items[:MAX_RELAYED_ENTRIES]:
        child, child_omitted = relay_value(item, api_key, depth + 1)
        shown_items.append(child)
        omitted += child_omitted
    return shown_items, omitted


def omitted_note(omitted: int) -> str:
    """``and N more`` for the text line of a cut collection (empty when nothing was cut)."""
    return f"and {omitted} more" if omitted > 0 else ""


def _detail_text(cleaned: Any) -> str:
    """One already-cleaned ``details`` value on one line: a string plain, the rest as json."""
    if isinstance(cleaned, str):
        return cleaned
    # Real characters, not \uXXXX escapes (the strings are already sanitised). A lone surrogate
    # cannot be written to a terminal, so it stays an escape instead of failing the echo.
    text = json.dumps(
        cleaned, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False
    )
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


def _validation_location(entry: Mapping[Any, Any], api_key: str) -> str:
    """The dotted ``loc`` of one validation error entry, sanitised (empty when it has none)."""
    loc = entry.get("loc")
    parts = loc[:MAX_VALIDATION_LOC_PARTS] if isinstance(loc, list | tuple) else [loc]
    plain = [str(part) for part in parts if isinstance(part, str | int)]
    return sanitise_text(".".join(plain), api_key=api_key, limit=MAX_ECHOED_VALUE_CHARS)


def _validation_line(entry: object, api_key: str) -> str | None:
    """``location: message`` for one validation error entry, or ``None`` if it has no message."""
    if not isinstance(entry, Mapping):
        return None
    message = entry.get("msg")
    if not isinstance(message, str) or not message.strip():
        return None
    where = _validation_location(entry, api_key)
    what = sanitise_text(message, api_key=api_key, limit=MAX_VALIDATION_MESSAGE_CHARS)
    return f"{where}: {what}" if where else what


def validation_head(message: str, errors: object, api_key: str) -> str:
    """``message`` without the first issue the server repeated after it.

    The server's validation message is ``<base>: <location>: <msg>`` (plus ``(and N more)``),
    which the pair list says again; the text line keeps only ``<base>``. A message that does
    not repeat the first issue's location is kept whole.
    """
    if not isinstance(errors, list | tuple) or not errors or not isinstance(errors[0], Mapping):
        return message
    where = _validation_location(errors[0], api_key)
    cut = message.find(f": {where}") if where else -1
    return message[:cut] if cut > 0 else message


def validation_summary(errors: object, api_key: str) -> str | None:
    """The server's validation ``errors`` list as ``location: message`` pairs joined by ``; ``
    (at most ``MAX_VALIDATION_LINES``, then ``and N more``), each part sanitised and capped.

    ``None`` when ``errors`` is not such a list (every shown entry needs a message), so the
    caller shows the value as it shows any other detail.
    """
    if not isinstance(errors, list | tuple) or not errors:
        return None
    lines: list[str] = []
    for entry in errors[:MAX_VALIDATION_LINES]:
        line = _validation_line(entry, api_key)
        if line is None:
            return None
        lines.append(line)
    note = omitted_note(len(errors) - len(lines))
    return "; ".join([*lines, note] if note else lines)


def _entry_text(entry: RelayedEntry) -> str:
    """``name=value`` for one kept detail; a cut collection ends in ``; and N more`` inside its
    closing bracket (as the validation list does), never in a raw ``_beyond_cap`` pair."""
    text = _detail_text(entry.value)
    if not entry.omitted:
        return f"{entry.name}={text}"
    note = omitted_note(entry.omitted)
    if text[-1:] in ("]", "}"):
        return f"{entry.name}={text[:-1]}; {note}{text[-1]}"
    return f"{entry.name}={text} ({note})"


def _details_pairs(details: Mapping[str, Any], api_key: str, *, skip_errors: bool) -> str:
    """The ``key=value`` pairs of ``details`` (without ``errors`` when ``skip_errors``)."""
    rest = {k: v for k, v in details.items() if not (skip_errors and k == VALIDATION_ERRORS_KEY)}
    relayed = relay_mapping(rest, api_key)
    parts = [_entry_text(entry) for entry in relayed.entries]
    if relayed.omitted:
        parts.append(omitted_note(relayed.omitted))
    return "; ".join(parts)


def describe_details(details: Mapping[str, Any], api_key: str | None = None) -> str:
    """``key=value`` pairs on one line; strings plain, everything else as compact json.

    The mapping is cleaned by the same rule the ``--json`` error uses (:func:`relay_value`):
    sanitising, the entry cap, colliding keys and the nesting depth. A cut says ``and N more``
    here: after the pairs for the mapping itself, inside the brackets for a cut child (the
    json's ``<key>_beyond_cap`` sibling is not printed). A validation ``errors`` list is written
    as ``errors=[location: message; ...]``.
    """
    key_for_masking = caller_key() if api_key is None else api_key
    summary = validation_summary(details.get(VALIDATION_ERRORS_KEY), key_for_masking)
    rest = _details_pairs(details, key_for_masking, skip_errors=summary is not None)
    if summary is None:
        return rest
    head = f"{VALIDATION_ERRORS_KEY}=[{summary}]"
    return f"{head}; {rest}" if rest else head


def details_text(details: object, api_key: str | None = None) -> str:
    """The text form of a server ``details`` value: an object as ``key=value`` pairs
    (:func:`describe_details`); anything else (a string, a list) as ``details=<value>``,
    cleaned by the same rule the ``--json`` error uses."""
    if isinstance(details, Mapping):
        return describe_details(details, api_key)
    key = caller_key() if api_key is None else api_key
    cleaned, omitted = relay_value(details, key)
    note = f", {omitted_note(omitted)}" if omitted else ""
    return f"details={_detail_text(cleaned)}{note}"


def _clean_id(value: object, api_key: str) -> str | None:
    """A request id from the server, sanitised and short; ``None`` stays ``None``."""
    if not isinstance(value, str):
        return None
    return sanitise_text(value, api_key=api_key, limit=MAX_RELAYED_ID_CHARS) or None


def clean_hint(hint: str, api_key: str | None = None) -> str:
    """A hint line (it may repeat what the user typed or an id from the server), sanitised."""
    key = caller_key() if api_key is None else api_key
    return sanitise_text(hint, api_key=key, limit=USAGE_MESSAGE_CHARS)


def clean_repr_literals(text: str, api_key: str) -> str:
    """``text`` with every quoted python literal in it (a value written with ``!r``) cleaned.

    A repr shows an escape byte as the four characters ``\\x1b``, so a key split by a terminal
    sequence would read as plain text to the sanitiser. Each literal is therefore evaluated back
    to the string it stands for, sanitised on its own (bounded by ``MAX_ECHOED_VALUE_CHARS``)
    and written again with ``repr``. A literal that does not evaluate to a string stays as is.
    """

    def clean(match: "re.Match[str]") -> str:
        try:
            value = ast.literal_eval(match.group(0))
        except (ValueError, SyntaxError, MemoryError, RecursionError):
            return match.group(0)
        if not isinstance(value, str):
            return match.group(0)
        return repr(sanitise_text(value, api_key=api_key, limit=MAX_ECHOED_VALUE_CHARS))

    return REPR_LITERAL_RE.sub(clean, text)


def strip_dangerous_terminal(text: str) -> str:
    """``text`` without OSC (the clipboard write included), DCS, SOS, PM and APC sequences and
    their C1 introducers; everything else, CSI included, is kept exactly as it is.

    For program output that is relayed faithfully: nothing is masked or reshaped.
    """
    return DANGEROUS_SEQUENCE_RE.sub("", text)


def _message_text(exc: SandfortSDKError | CliError, api_key: str) -> str:
    """``str(exc)`` as it may be printed: SDK errors carry server or network text (sanitised
    and capped), a CLI error is the CLI's own text (control characters and keys removed). A
    Python exception class name in it (``IsADirectoryError``) is written in plain words."""
    if isinstance(exc, SandfortSDKError):
        text = plain_error_names(str(exc))
        if isinstance(exc, InvalidResponseError):  # its messages quote the bad value with !r
            text = clean_repr_literals(text, api_key)
        return sanitise_text(text, api_key=api_key, limit=USAGE_MESSAGE_CHARS)
    return scrub_local(plain_error_names(str(exc)), api_key)


def api_error_text(exc: ApiError, api_key: str) -> str:
    """The server error line (:func:`_api_error_line`); a CAPACITY error gets one more line,
    its hint (:mod:`sandfort_cli.error_hints`). Text mode only: the json error object is built
    elsewhere."""
    line = _api_error_line(exc, api_key)
    hint = hint_for(exc)
    return line if hint is None else f"{line}\n{hint}"


def _api_error_line(exc: ApiError, api_key: str) -> str:
    """``<code>: <message> (<details>)`` for a server error.

    A validation answer is ``<code>: <base message>: <location: message>; ...`` with the pair
    list written once (the server's copy of the first pair and its count are dropped from the
    message), and any other details in the parentheses.
    """
    code = sanitise_text(exc.code, api_key=api_key, limit=MAX_RELAYED_CODE_CHARS)
    details = plain_name_rules(exc.details)
    errors = details.get(VALIDATION_ERRORS_KEY) if isinstance(details, Mapping) else None
    summary = validation_summary(errors, api_key)
    message = sanitise_text(
        plain_name_rule(exc.message),
        api_key=api_key,
        limit=MAX_RELAYED_CHARS if summary is None else MAX_VALIDATION_MESSAGE_CHARS,
    )
    if summary is None or not isinstance(details, Mapping):
        shown_details = details_text(details, api_key) if details else ""
        base = f"{code}: {message}"
        return f"{base} ({shown_details})" if shown_details else base
    head = validation_head(message, errors, api_key)
    base = f"{code}: {head}: {summary}" if head else f"{code}: {summary}"
    rest = _details_pairs(details, api_key, skip_errors=True)
    return f"{base} ({rest})" if rest else base


def describe_error(exc: SandfortSDKError | CliError) -> str:
    """The text line of ``exc``; a ``request_id`` is named once, at the end (the SDK's tail).

    Everything the server said (code, message, details, ids) is sanitised and capped, so a
    hostile reply cannot put terminal escapes, credentials or the caller's key on the terminal.
    """
    api_key = caller_key()
    if isinstance(exc, ApiError):
        text = api_error_text(exc, api_key)
    elif isinstance(exc, SandboxFailedError):
        text = with_error_code(exc, api_key)
    else:
        text = _message_text(exc, api_key)
    request_id = _clean_id(getattr(exc, "request_id", None), api_key)
    if isinstance(exc, ApiError):  # the id ends the error line, ahead of any hint line
        head, newline, hint = text.partition("\n")
        return head + request_id_tail(text, request_id) + newline + hint
    return text + request_id_tail(text, request_id)


def with_error_code(failed: SandboxFailedError, api_key: str | None = None) -> str:
    """The failure text with ``[<error_code>]`` after the state: "... is error [code]: ...".

    Built from the code-free message. With a code that does not fit after the state (the text
    does not name it in the SDK's form), the code is appended at the end instead. The message,
    code, id and state are server text and are sanitised.
    """
    key = caller_key() if api_key is None else api_key
    text = sanitise_text(failed.message, api_key=key, limit=USAGE_MESSAGE_CHARS)
    if not failed.error_code:
        return text
    code = sanitise_text(failed.error_code, api_key=key, limit=MAX_RELAYED_CODE_CHARS)
    sandbox_id = sanitise_text(failed.sandbox_id, api_key=key, limit=MAX_RELAYED_ID_CHARS)
    state = sanitise_text(failed.state, api_key=key, limit=MAX_RELAYED_CODE_CHARS)
    prefix = f"sandbox {sandbox_id} is {state}"
    if not text.startswith(prefix):
        return f"{text} [{code}]"
    return f"{prefix} [{code}]{text[len(prefix) :]}"


def set_json_errors(enabled: bool) -> None:
    """Record whether the global ``--json`` flag is on, for ``cli_errors`` to read."""
    _json_errors.set(enabled)


def is_not_running_conflict(exc: SandfortSDKError | CliError) -> bool:
    """True for a 409 whose message says the sandbox is not started or not running."""
    if not isinstance(exc, ApiError) or exc.status_code != HTTP_CONFLICT:
        return False
    message = exc.message.lower()
    return any(phrase in message for phrase in NOT_RUNNING_PHRASES)


STOP_CAUSE_KEY = "stop_cause"


def conflict_stop_cause(exc: SandfortSDKError | CliError) -> str | None:
    """The ``stop_cause`` the server put in the error details, sanitised and short; ``None``
    when there is none (the field is optional, and details may not even be an object)."""
    details = getattr(exc, "details", None)
    cause = details.get(STOP_CAUSE_KEY) if isinstance(details, Mapping) else None
    if not isinstance(cause, str):
        return None
    return sanitise_text(cause, api_key=caller_key(), limit=MAX_RELAYED_CODE_CHARS) or None


def start_hint(sandbox_ref: str, stop_cause: str | None = None) -> str:
    """How to start the sandbox, with the reference exactly as the user gave it; with a
    ``stop_cause``, ``; stopped because: <cause>`` follows."""
    hint = f"start it with: sandfort sandbox start {sandbox_ref}"
    return f"{hint}; stopped because: {stop_cause}" if stop_cause else hint


def timeout_details(exc: SandboxTimeoutError) -> dict[str, Any]:
    """``sandbox_id`` (when known) and ``deleted`` of a wait that ran out of time.

    ``deleted`` is the SDK attribute when the error has one, else whether the message says the
    sandbox was deleted.
    """
    details: dict[str, Any] = {}
    sandbox_id = getattr(exc, "sandbox_id", None)
    if sandbox_id:
        details["sandbox_id"] = sandbox_id
    deleted = getattr(exc, "deleted", None)
    details["deleted"] = deleted if isinstance(deleted, bool) else DELETED_PHRASE in str(exc)
    return details


def _exception_chain(exc: BaseException) -> Iterator[BaseException]:
    """``exc``'s causes and contexts (``raise ... from None`` keeps the context), oldest last."""
    seen: set[int] = set()
    link = exc.__cause__ or exc.__context__
    while link is not None and id(link) not in seen:
        seen.add(id(link))
        yield link
        link = link.__cause__ or link.__context__


def never_sent(exc: BaseException) -> bool:
    """True when no request of the failed step reached the server: a connect failure, a timeout
    before sending, a :class:`CliError` with ``client=True`` unless an SDK error in its chain
    reached the server. An ambiguous name is found in a list reply, so it is never one."""
    if isinstance(exc, CliError):
        chained = (e for e in _exception_chain(exc) if isinstance(e, SandfortSDKError))
        return exc.client and all(never_sent(e) for e in chained)
    if isinstance(exc, RequestTimedOut):
        return not exc.request_sent
    return isinstance(exc, TransportError) and isinstance(exc.__cause__, httpx.ConnectError)


def error_payload(exc: SandfortSDKError | CliError, hint: str | None = None) -> dict[str, Any]:
    """The ``{"error": {...}}`` object printed for ``exc`` when ``--json`` is on.

    ``request_id`` is the exception's or ``None``; ``"source": "client"`` only when
    :func:`never_sent`; ``hint``, when given, is added as ``"hint"``; without one, the error's
    own hint (a CAPACITY error has one, see :mod:`sandfort_cli.error_hints`).

    Every string that came from the server (code, message, details, ids, reasons) is sanitised
    and capped exactly as in the text line: no terminal escapes, credentials or caller key.
    """
    api_key = caller_key()

    def text(value: str | None, limit: int = MAX_RELAYED_ID_CHARS) -> str | None:
        return None if value is None else sanitise_text(value, api_key=api_key, limit=limit)

    request_id = _clean_id(getattr(exc, "request_id", None), api_key)
    details_omitted = 0
    if isinstance(exc, ApiError):
        cleaned_details, details_omitted = relay_value(plain_name_rules(exc.details), api_key)
        error: dict[str, Any] = {
            "code": text(exc.code, MAX_RELAYED_CODE_CHARS),
            "message": sanitise_text(plain_name_rule(exc.message), api_key=api_key),
            "details": cleaned_details,
            "request_id": request_id,
        }
    else:
        error = {
            "code": CLI_ERROR_CODE,
            "message": _message_text(exc, api_key),
            "details": (
                relay_value(timeout_details(exc), api_key)[0]
                if isinstance(exc, SandboxTimeoutError)
                else {}
            ),
            "request_id": request_id,
        }
    if details_omitted:
        error[f"details{BEYOND_CAP_SUFFIX}"] = details_omitted
    if never_sent(exc):
        error["source"] = CLIENT_SOURCE
    if isinstance(exc, SandboxFailedError):
        error.update(
            code=SANDBOX_FAILED_CODE,
            message=sanitise_text(exc.message, api_key=api_key, limit=USAGE_MESSAGE_CHARS),
            sandbox_id=text(exc.sandbox_id),
            state=text(exc.state, MAX_RELAYED_CODE_CHARS),
            error_reason=text(exc.error_reason, USAGE_MESSAGE_CHARS),
            error_code=text(exc.error_code, MAX_RELAYED_CODE_CHARS),
            deleted=exc.deleted,
            request_id=request_id,
        )
    hint = hint if hint is not None else hint_for(exc)
    if hint is not None:
        error["hint"] = clean_hint(hint, api_key)
    return {"error": error}


ErrorExtras = Callable[[], Mapping[str, Any]]
# Called with the failure; the line it returns (or None) is the hint under the error.
ErrorHint = Callable[[SandfortSDKError | CliError], str | None]


@contextmanager
def cli_errors(
    exit_code: int = EXIT_FAILURE,
    sandbox_ref: str | None = None,
    extras: ErrorExtras | None = None,
    hint: ErrorHint | None = None,
) -> Iterator[None]:
    """Turn SDK and CLI failures into one error report and ``exit_code``.

    The report is ``error: <description>`` on stderr, or with ``--json`` a single json object
    on stdout (:func:`error_payload`). With ``sandbox_ref`` (the sandbox as the user typed it),
    a not-running conflict adds the line ``start it with: sandfort sandbox start <ref>`` (json:
    an ``error.hint`` field). ``extras``, when given, is called at the failure and its fields
    join the json document next to ``error`` (one document, never two). ``hint``, when given, is
    called with the failure and may return a hint line (``error.hint`` with --json); it wins
    over the start hint.
    """
    try:
        yield
    except (SandfortSDKError, CliError) as exc:
        line = hint(exc) if hint else None
        if line is None and sandbox_ref and is_not_running_conflict(exc):
            line = start_hint(sandbox_ref, conflict_stop_cause(exc))
        if _json_errors.get():
            print_json({**error_payload(exc, line), **(extras() if extras else {})})
        else:
            typer.echo(f"error: {describe_error(exc)}", err=True)
            if line is not None:
                typer.echo(clean_hint(line), err=True)
        raise typer.Exit(exit_code) from None
