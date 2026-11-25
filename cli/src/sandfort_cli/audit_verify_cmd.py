"""The ``audit verify-head`` command: its reason table, checks and output helpers.

``register_verify_head`` adds the command to the ``audit`` group of ``sandfort_cli.audit``.
"""

import base64
import binascii
import hashlib
import io
import sys
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Any, TextIO

import typer
from sandfort_sdk.audit_continuation import event_lines
from sandfort_sdk.audit_export import (
    REASON_CHAIN_BREAK,
    REASON_CONTENT_MISMATCH,
    REASON_COUNT_MISMATCH,
    REASON_FIRST_ROW_MISMATCH,
    REASON_HEAD_MISMATCH,
    REASON_MALFORMED_ROW,
    REASON_MISPLACED_TRAILER,
    REASON_NO_TRAILER,
    REASON_NOT_A_CONTINUATION,
    REASON_ORG_MISMATCH,
    REASON_TRUNCATED,
    REASON_UNCHAINED,
    ExportScan,
    ExportVerification,
    bounded_lines,
    export_result,
    scan_export,
)
from sandfort_sdk.audit_head import (
    REASON_EXPECTED_ORG_MISMATCH,
    REASON_FUTURE,
    HeadVerification,
    verify_head,
)
from typer.core import TyperCommand, TyperOption

try:  # typer 0.27+ vendors click; its classes are not the installed click's
    from typer._click import core as click_core
    from typer._click import exceptions as click_exceptions
except ImportError:  # pragma: no cover - older typer builds on the installed click
    from click import core as click_core  # type: ignore[no-redef]
    from click import exceptions as click_exceptions  # type: ignore[no-redef]

from sandfort_cli.audit_verify_status import proof_line, server_public_key
from sandfort_cli.output import (
    AppState,
    CliError,
    app_state,
    clean_strings,
    cli_errors,
    print_fields,
    print_json,
    shown,
)
from sandfort_cli.sanitise import caller_key

EXIT_BROKEN_CHAIN = 3  # same as `audit-verify` of the admin CLI
EXIT_USAGE = 2
KEY_BYTES = 32
FINGERPRINT_CHARS = 16  # hex characters of sha256(raw public key)
REASONS = {
    "unsigned": "the head carries no Ed25519 signature",
    "signature": "the signature does not verify with this public key",
    "key_mismatch": "the head names a different public key than the one you trust",
    "undated": "the signature verifies, but the head has no valid signed_at "
    "(absent, without a UTC offset, or before 1970-01-02)",
    REASON_FUTURE: "the signature verifies, but signed_at is more than 5 minutes in the future",
    REASON_EXPECTED_ORG_MISMATCH: "the signed head names a different org_id than --expect-org",
    REASON_TRUNCATED: "the last row of the file is not the row the signed head names "
    "(rows were cut, or the trailer is from a different (earlier or later) export)",
    REASON_HEAD_MISMATCH: "the last row is the head's row, but its hash differs from the head's",
    REASON_CHAIN_BREAK: "a row's prev_hash is not the hash of the row before it in the file",
    REASON_CONTENT_MISMATCH: "the number of event lines is right, but their SHA-256 is not the "
    "one the signed head binds (a line was edited or reordered)",
    REASON_COUNT_MISMATCH: "the number of event lines is not the row_count the signed head "
    "binds (rows were removed or added)",
    REASON_FIRST_ROW_MISMATCH: "the first event line is not the first_row_id the signed head binds",
    REASON_ORG_MISMATCH: "a row's org_id is not the org_id of the signed head",
    REASON_NOT_A_CONTINUATION: "the event lines of the --previous export are not an exact "
    "prefix of this export's event lines",
    REASON_MALFORMED_ROW: "a line is not a JSON object with a text id, occurred_at, org_id and "
    "action, the hash and prev_hash keys (text or null), is not valid UTF-8, is nested too "
    "deeply, or is longer than 1 MiB",
    REASON_MISPLACED_TRAILER: "an audit_head or export_summary line is not the final line",
    REASON_UNCHAINED: "a row carries no hash (pass --allow-unchained to accept rows "
    "nobody has chained)",
    REASON_NO_TRAILER: "the file has event rows, but its last line is not a usable audit_head "
    "trailer (missing, junk, an unsigned export_summary, or a row after the trailer)",
}
FILE_REASONS = frozenset(
    {
        REASON_CONTENT_MISMATCH,
        REASON_COUNT_MISMATCH,
        REASON_FIRST_ROW_MISMATCH,
        REASON_ORG_MISMATCH,
        REASON_NOT_A_CONTINUATION,
        REASON_TRUNCATED,
        REASON_HEAD_MISMATCH,
        REASON_CHAIN_BREAK,
        REASON_MALFORMED_ROW,
        REASON_MISPLACED_TRAILER,
        REASON_UNCHAINED,
        REASON_NO_TRAILER,
    }
)
LINE_REASONS = frozenset(
    {
        REASON_MALFORMED_ROW,
        REASON_MISPLACED_TRAILER,
        REASON_UNCHAINED,
        REASON_NO_TRAILER,
        REASON_ORG_MISMATCH,
    }
)
FILTERED_NOTE = (
    "note: filtered export: the rows are not a contiguous run of the chain, so the linkage "
    "between neighbouring rows was not checked"
)
LEGACY_NOTE = (
    "note: legacy head: content not bound (the head signs the last row only; rows above it "
    "were not checked against it)"
)
UNCHAINED_TAIL = "not checked; the server-side check covers them: sandfort audit verify"
UNCHAINED_ONE = f"note: 1 row carries no hash and was {UNCHAINED_TAIL}"
UNCHAINED_MANY = "note: {count} rows carry no hash and were " + UNCHAINED_TAIL
NO_TRAILER = "{name} does not end with an audit_head trailer line"
STDIN_ARGUMENT = "-"
STDIN_NAME = "standard input"
EMPTY_PREVIOUS = "the previous export has no event rows: {name}"
BYTE_FOR_BYTE = "exports must be verified byte for byte as downloaded"
BOM = "\ufeff"
HINT_REASONS = frozenset({REASON_CONTENT_MISMATCH, REASON_MALFORMED_ROW, REASON_NO_TRAILER})
NONE_CELL = "-"
STATUS_PATH = "/v1/status"
STANDARD_TO_URLSAFE = str.maketrans("+/", "-_")
STATUS_TIMEOUT_S = 15.0
NOT_PROVEN = (
    "not verified: the keyed row hashes (only the chain key proves them: sandfort audit "
    "verify) and that this is the newest export"
)
SECONDS_PER = (("d", 86400), ("h", 3600), ("m", 60))


def option_name(token: str) -> str:
    return token.split("=", 1)[0]


class SingleValueCommand(TyperCommand):
    """A command that refuses a single-value option given more than once.

    Click keeps the last value of a repeated option without a word; for an audit query that
    silently changes what is asked, so a repeat is a usage error naming the option.
    """

    def value_options(self) -> dict[str, TyperOption]:
        return {
            name: param
            for param in self.params
            if isinstance(param, TyperOption) and not param.is_flag and not param.multiple
            for name in param.opts
        }

    def parse_args(self, ctx: click_core.Context, args: list[str]) -> list[str]:
        options = self.value_options()
        seen: set[str] = set()
        tokens = iter(args)
        for token in tokens:
            if token == "--":
                break
            name = option_name(token)
            if not name.startswith("--") or name not in options:
                continue
            if name in seen:
                raise click_exceptions.UsageError(f"{name} was given more than once", ctx=ctx)
            seen.add(name)
            if "=" not in token:
                next(tokens, None)  # the option's value
        return super().parse_args(ctx, args)


class LineFormat:
    """Notes, while an export is read, whether it has a BOM or CRLF line endings."""

    def __init__(self) -> None:
        self.bom = False
        self.crlf = False

    def watch(self, lines: Iterable[str]) -> Iterator[str]:
        for number, line in enumerate(lines):
            self.bom = self.bom or (number == 0 and line.startswith(BOM))
            self.crlf = self.crlf or line.endswith("\r\n")
            yield line

    def hint(self) -> str | None:
        """The hint line when the file was changed after the download; else ``None``."""
        found = [
            text for flag, text in ((self.crlf, "CRLF line endings"), (self.bom, "a BOM")) if flag
        ]
        return f"the file has {' and '.join(found)}; {BYTE_FOR_BYTE}" if found else None


def cell(value: object) -> str:
    """One server value for a table cell: sanitised; ``-`` when absent or empty."""
    return NONE_CELL if value is None else shown(value, caller_key()) or NONE_CELL


def key_fingerprint(public_key: str) -> str | None:
    """The first 16 hex characters of sha256 over the raw key; ``None`` when not a 32-byte key
    in urlsafe base64."""
    text = public_key.strip().translate(STANDARD_TO_URLSAFE)
    try:
        padded = (text + "=" * (-len(text) % 4)).encode("ascii")
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        return None
    if len(raw) != KEY_BYTES:
        return None
    return hashlib.sha256(raw).hexdigest()[:FINGERPRINT_CHARS]


def open_export(path: Path) -> TextIO:
    """``path`` opened for line-by-line reading; undecodable bytes survive as escapes."""
    return path.open(encoding="utf-8", errors="surrogateescape", newline="\n")


@contextmanager
def open_source(path: Path) -> Iterator[TextIO]:
    """The export ``path`` for reading; ``-`` is standard input (left open afterwards)."""
    if str(path) != STDIN_ARGUMENT:
        with open_export(path) as handle:
            yield handle
        return
    wrapper = io.TextIOWrapper(
        sys.stdin.buffer, encoding="utf-8", errors="surrogateescape", newline="\n"
    )
    try:
        yield wrapper
    finally:
        wrapper.detach()


def display_name(path: Path) -> str:
    return STDIN_NAME if str(path) == STDIN_ARGUMENT else shown(str(path), caller_key())


def read_export(
    path: Path, previous: Path | None = None, line_format: LineFormat | None = None
) -> ExportScan:
    """The trailer and the row linkage of an export file, read once with bounded lines.

    A missing or unreadable file, an empty one, or one without any valid event row whose last
    non-blank line is not a usable ``audit_head``, is a usage error; a bad row, bytes that are
    not UTF-8 inside a row, and a missing trailer after valid rows are not (they fail the check
    later). The file is decoded line by line (undecodable bytes survive as surrogate escapes,
    which the scan reports as ``malformed_row``). With ``previous``, that earlier export is read
    in step and its event lines must be a byte prefix of this file's.
    """
    name = display_name(path)
    watch = (line_format or LineFormat()).watch
    try:
        with open_source(path) as handle:
            if previous is None:
                return scan_export(watch(bounded_lines(handle)))
            return scan_earlier(watch(bounded_lines(handle)), previous)
    except FileNotFoundError:
        raise CliError(f"no such file: {name}", client=True) from None
    except OSError as exc:
        raise CliError(f"cannot read {name}: {type(exc).__name__}", client=True) from None
    except ValueError as exc:
        detail = shown(str(exc), caller_key())
        raise CliError(f"{NO_TRAILER.format(name=name)} ({detail})", client=True) from None


def scan_earlier(lines: Iterable[str], previous: Path) -> ExportScan:
    """The scan of the export ``lines`` compared with the earlier export ``previous``, which
    must hold at least one event row (an empty one proves nothing)."""
    earlier = shown(str(previous), caller_key())
    try:
        with open_export(previous) as probe:
            if next(event_lines(bounded_lines(probe)), None) is None:
                raise CliError(EMPTY_PREVIOUS.format(name=earlier), client=True)
        with open_export(previous) as other:
            return scan_export(lines, bounded_lines(other))
    except FileNotFoundError:
        raise CliError(f"no such file: {earlier}", client=True) from None
    except OSError as exc:
        raise CliError(f"cannot read {earlier}: {type(exc).__name__}", client=True) from None


def format_hint(result: HeadVerification, line_format: LineFormat | None) -> str | None:
    """The line-ending / BOM hint for a failure that such a change explains; else ``None``."""
    if line_format is None or result.ok or result.reason not in HINT_REASONS:
        return None
    return line_format.hint()


def head_payload(result: HeadVerification) -> dict[str, Any]:
    """The json document: the head fields, plus the file checks for an export verification."""
    key = result.public_key
    payload: dict[str, Any] = {
        "ok": result.ok,
        "row_id": result.row_id,
        "entry_hash": result.entry_hash,
        "public_key": key,
        "reason": result.reason,
        "fingerprint": None if key is None else key_fingerprint(key),
        "signed_at": None if result.signed_at is None else result.signed_at.isoformat(),
        "org_id": result.org_id,
    }
    if isinstance(result, ExportVerification):
        payload["rows_checked"] = result.rows
        payload["first_break"] = result.first_break
        payload["unchained"] = result.unchained
        payload["content_bound"] = result.content_bound
        payload["filtered"] = result.filtered
        if result.bad_line is not None:
            payload["bad_line"] = result.bad_line
        if result.new_rows is not None:
            payload["previous_rows"] = result.previous_rows
            payload["new_rows"] = result.new_rows
    cleaned: dict[str, Any] = clean_strings(payload, caller_key())
    return cleaned


def head_fields(result: HeadVerification) -> dict[str, str]:
    """The table fields: the json fields, without ``unchained`` (it has its own note) and
    ``first_break`` when there is none."""
    payload = head_payload(result)
    fields = {name: cell(value) for name, value in payload.items() if name != "unchained"}
    fields["ok"] = str(result.ok).lower()
    for name in ("content_bound", "filtered"):
        if name in payload:
            fields[name] = str(payload[name]).lower()
    if payload.get("first_break") is None:
        fields.pop("first_break", None)
    return fields


def failure_line(result: HeadVerification) -> str:
    """``error: ... not verified (<reason>): <explanation>``, naming the rows involved."""
    reason = result.reason or "signature"
    detail = ""
    if isinstance(result, ExportVerification) and reason == REASON_TRUNCATED:
        detail = f" (head row {cell(result.row_id)}, last row {cell(result.last_row_id)})"
    elif isinstance(result, ExportVerification) and reason == REASON_CHAIN_BREAK:
        detail = f" (first break at row {cell(result.first_break)})"
    elif isinstance(result, ExportVerification) and reason in LINE_REASONS:
        detail = f" (line {cell(result.bad_line)})"
    subject = "export" if reason in FILE_REASONS else "head"
    return f"error: {subject} not verified ({reason}): {REASONS.get(reason, '')}{detail}"


def unchained_note(count: int) -> str:
    return UNCHAINED_ONE if count == 1 else UNCHAINED_MANY.format(count=count)


def render_head(
    state: AppState,
    result: HeadVerification,
    line_format: LineFormat | None = None,
    expected_org: str | None = None,
) -> None:
    hint = format_hint(result, line_format)
    if state.json_output:
        print_json({**head_payload(result), **({} if hint is None else {"hint": hint})})
    else:
        print_fields("audit head", head_fields(result), folded=("entry_hash", "public_key"))
    if (
        isinstance(result, ExportVerification)
        and result.unchained
        and result.reason != REASON_UNCHAINED
    ):
        typer.echo(unchained_note(result.unchained), err=True)
    if isinstance(result, ExportVerification) and result.ok and not result.content_bound:
        typer.echo(LEGACY_NOTE, err=True)
    if isinstance(result, ExportVerification) and result.ok and result.filtered:
        typer.echo(FILTERED_NOTE, err=True)
    if result.ok and not state.json_output:
        typer.echo(proof_line(result, expected_org), err=True)
    if not result.ok and not state.json_output:
        typer.echo(failure_line(result), err=True)
        if hint is not None:
            typer.echo(f"hint: {hint}", err=True)


def verify_head_command(
    ctx: typer.Context,
    file: Annotated[
        Path,
        typer.Argument(metavar="<file>", help="An audit export file; - reads standard input."),
    ],
    public_key: Annotated[
        str | None,
        typer.Option(
            "--public-key",
            help="Ed25519 public key, 32 bytes in urlsafe or standard base64; default: "
            "audit_public_key of the server (read from /v1/status, no login needed).",
        ),
    ] = None,
    head_only: Annotated[
        bool,
        typer.Option("--head-only", help="Check only the trailer's signature, not the rows."),
    ] = False,
    allow_unchained: Annotated[
        bool,
        typer.Option(
            "--allow-unchained",
            help="Accept rows without a hash (default: they fail the check as unchained_rows).",
        ),
    ] = False,
    previous: Annotated[
        Path | None,
        typer.Option(
            "--previous",
            metavar="<file>",
            help="An earlier export of the same org: its event lines must be an exact prefix "
            "of this file's (not_a_continuation otherwise); the new rows are counted.",
        ),
    ] = None,
    expect_org: Annotated[
        str | None,
        typer.Option(
            "--expect-org",
            metavar="<org_id>",
            help="The org the signed head must name (expected_org_mismatch otherwise, also "
            "when the head names none).",
        ),
    ] = None,
) -> None:
    """Verify an export file against its signed audit_head trailer line.

    Checks the Ed25519 signature and signed_at of the trailer; then, when the head binds the
    content (servers from round 63 on), that the file's event lines are the ones the server
    signed: their SHA-256, count and first row (content_mismatch, count_mismatch,
    first_row_mismatch); then that every row has an id, occurred_at, org_id and action and the
    head's org_id, that the last row is the row the head names with the head's hash, that every
    row's prev_hash is the hash of the row before it, and that every row carries a hash
    (--head-only checks the signature alone). With --previous, the earlier export's event
    lines must be an exact prefix of this file's, and the new rows are counted. With
    --expect-org <org_id>, the signed head must name that org (expected_org_mismatch otherwise);
    without it a genuine export of another org verifies, and org_id in the output says whose.

    A head marked filtered (an export cut by request_id or outcome) binds the content but its
    rows are not a contiguous run, so the linkage between neighbouring rows is not checked and
    the output says so. On success a line states what was proven and what not (the age of
    signed_at is shown; keyed row hashes are not).

    A head from an older server binds only the LAST row (legacy head: content not bound, noted
    on stderr); rows before the last can then be replaced or removed by someone who rewrites
    prev_hash and hash consistently, and an older genuinely signed export still verifies (check
    signed_at). Row hashes are keyed, so even with a bound head a server that signs a fabricated
    export verifies, and only the server-side verification proves the keyed hashes and the full
    chain: `sandfort audit verify` (admin: `audit-verify`).

    Exit 0 when every check passes, 3 when one fails (the reason is shown; a file with a
    trailer and no rows under it is exit 3 truncated, as are a malformed row, a row without a
    hash, a trailer that is not the last line, and a file with rows but no usable trailer), 2
    when the file or --previous is unreadable, empty, or has neither a usable trailer nor any
    valid row (a --previous without event rows is refused too), or when a public key is missing
    or unusable. A file named - is read from standard input. A file whose line endings were
    converted (CRLF) or that starts with a BOM fails as content_mismatch, with a hint: verify an
    export byte for byte as downloaded. The trailer's own public_key is never
    trusted on its own: the key comes from --public-key or from the server status.
    """
    state = app_state(ctx)
    expected_org = None if expect_org is None else expect_org.strip()
    with cli_errors(EXIT_USAGE):
        if expected_org == "":
            raise CliError("--expect-org must not be empty", client=True)
        if head_only and previous is not None:
            raise CliError(
                "--previous needs the rows: do not combine it with --head-only", client=True
            )
        line_format = LineFormat()
        scan = read_export(file, previous, line_format)
        if public_key is not None and key_fingerprint(public_key) is None:
            raise CliError("--public-key must be 32 bytes in urlsafe base64", client=True)
    key = public_key.strip() if public_key is not None else server_public_key()
    with cli_errors(EXIT_USAGE):
        try:
            if head_only:
                if scan.head is None:
                    name = NO_TRAILER.format(name=shown(str(file), caller_key()))
                    detail = shown(scan.trailer_error or "", caller_key())
                    raise CliError(f"{name} ({detail})", client=True)
                result: HeadVerification = verify_head(
                    scan.head, key, expected_org_id=expected_org
                )
            else:
                result = export_result(
                    scan, key, allow_unchained=allow_unchained, expected_org_id=expected_org
                )
        except ValueError as exc:
            raise CliError(shown(str(exc), caller_key()), client=True) from None
    render_head(state, result, line_format, expected_org)
    if not result.ok:
        raise typer.Exit(EXIT_BROKEN_CHAIN)


def register_verify_head(app: typer.Typer) -> None:
    """Add ``verify-head`` to the ``audit`` command group ``app``."""
    app.command("verify-head", cls=SingleValueCommand)(verify_head_command)
