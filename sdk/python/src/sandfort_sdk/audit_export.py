"""Auditor-side check of an audit export file against its signed ``audit_head`` trailer.

:func:`~sandfort_sdk.audit_head.verify_head` proves only that the server signed the head. It says
nothing about the rows above it: an export with its newest rows cut, old rows under a fresh
trailer, or a row whose ``hash`` or ``prev_hash`` was edited all pass it. :func:`verify_export`
adds the checks a client can make on the file itself: the last event row is the row the head
names, with the head's hash, and every row's ``prev_hash`` is the previous row's ``hash``.

Row hashes are keyed (HMAC with the server's chain key), so a client cannot recompute them. An
edit of a row's CONTENT that keeps its ``hash`` and ``prev_hash`` passes these checks; only the
server-side check (``sandfort audit verify``, or ``audit-verify`` of the admin CLI) catches it.

A head from servers since round 63 also binds the export's content (row count, first row id and
a SHA-256 over every event line), which the checks below recompute from the file. Against an older
head the client check binds only the last row (to the signed head) and the linkage between
neighbouring rows. See :func:`verify_export` for what it does not prove.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sandfort_sdk.audit_continuation import HEAD_TYPE, MAX_LINE_CHARS, SUMMARY_TYPE, TRAILER_TYPES
from sandfort_sdk.audit_head import (
    EXPECTED_ORG_EMPTY,
    HeadVerification,
    head_binding,
    head_is_filtered,
    trusted_key_text,
    verify_head,
)
from sandfort_sdk.audit_scan import (
    EMPTY_EXPORT,
    ExportScan,
    bounded_lines,
    scan_export,
    scan_export_async,
)

REASON_TRUNCATED = "truncated"
REASON_HEAD_MISMATCH = "head_mismatch"
REASON_CHAIN_BREAK = "chain_break"
REASON_MALFORMED_ROW = "malformed_row"
REASON_MISPLACED_TRAILER = "misplaced_trailer"
REASON_UNCHAINED = "unchained_rows"
REASON_NO_TRAILER = "no_trailer"
REASON_CONTENT_MISMATCH = "content_mismatch"
REASON_COUNT_MISMATCH = "count_mismatch"
REASON_FIRST_ROW_MISMATCH = "first_row_mismatch"
REASON_ORG_MISMATCH = "org_mismatch"
REASON_NOT_A_CONTINUATION = "not_a_continuation"
__all__ = [
    "EMPTY_EXPORT",
    "HEAD_TYPE",
    "MAX_LINE_CHARS",
    "SUMMARY_TYPE",
    "TRAILER_TYPES",
    "ExportScan",
    "ExportVerification",
    "bounded_lines",
    "export_result",
    "scan_export",
    "scan_export_async",
    "verify_export",
]


@dataclass(frozen=True, slots=True)
class ExportVerification(HeadVerification):
    """The outcome of :func:`verify_export`: the head verification plus the file checks.

    ``ok`` and ``reason`` cover both. ``reason`` is a head reason (see
    :class:`HeadVerification`) when the head fails; otherwise, checked in this order,
    ``"malformed_row"`` (a line that is not a JSON object, has no text ``id``, ``occurred_at``,
    ``org_id`` or ``action``, lacks the ``hash`` or ``prev_hash`` key, has a non-text one, or is
    longer than 1 MiB), ``"misplaced_trailer"`` (an
    ``audit_head`` or ``export_summary`` line that is not the final non-blank line),
    ``"org_mismatch"`` (a row's ``org_id`` is not the head's),
    ``"truncated"`` (the last event row is not the row the head names, the head's row is absent,
    or there are no event rows at all), ``"head_mismatch"`` (the last row is the head's row but
    its hash differs or is missing), ``"chain_break"`` (a row's ``prev_hash`` is not the
    previous row's ``hash``) or ``"unchained_rows"`` (a row carries no ``hash`` and
    ``allow_unchained`` is false). ``"no_trailer"`` replaces all of these when the file has
    valid event rows but its last non-blank line is not a usable ``audit_head`` (``row_id`` and
    ``entry_hash`` are then empty). When the head binds the content (``content_bound``), three
    reasons come first, right after the signature: ``"count_mismatch"`` (the number of event lines
    differs: rows were removed or added), ``"content_mismatch"`` (the number is right but the
    SHA-256 over the exact bytes of every event line differs: a line was edited or reordered)
    and ``"first_row_mismatch"`` (the first event line's id differs). A last reason,
    ``"not_a_continuation"``, applies only with ``previous``: the earlier export's event lines
    are not an exact byte prefix of this export's. ``rows`` counts the event rows with a ``hash``;
    ``unchained`` counts rows that carry none. ``first_break`` is the id of the first row where
    the linkage breaks, set whenever there is one, even when another reason comes first (but
    ``None`` for ``"no_trailer"`` and for a filtered head: its rows are not a contiguous run, so
    ``filtered`` is true and neighbour linkage is not checked).
    ``last_row_id`` is the id of the last event row (hashed or not), ``None`` without rows.
    ``bad_line`` is the 1-based line number behind ``"malformed_row"``, ``"misplaced_trailer"``,
    ``"unchained_rows"`` (the first row without a hash) or ``"no_trailer"`` (the last non-blank
    line), else ``None``.
    """

    rows: int = 0
    first_break: str | None = None
    last_row_id: str | None = None
    unchained: int = 0
    bad_line: int | None = None
    content_bound: bool = False
    filtered: bool = False
    previous_rows: int | None = None
    new_rows: int | None = None


def _content_reason(scan: ExportScan, head: dict[str, Any]) -> str | None:
    """The content checks of a head that binds the export; ``None`` for a legacy head."""
    binding = head_binding(head)
    if binding is None:
        return None
    count, first, digest = binding
    # The count first: the digest covers every line, so it differs whenever a row is cut or
    # added, and checking it first would hide the more telling reason behind a general one.
    if scan.line_count != count:
        return REASON_COUNT_MISMATCH
    if scan.lines_sha256 != digest:
        return REASON_CONTENT_MISMATCH
    if scan.first_line_id != first:
        return REASON_FIRST_ROW_MISMATCH
    return None


def _foreign_org_line(scan: ExportScan, org_id: object) -> int | None:
    """The line of the first row whose ``org_id`` is not the head's; ``None`` when none."""
    for seen, line in scan.orgs:
        if seen != org_id:
            return line
    return None


def _file_reason(
    scan: ExportScan, head: HeadVerification, allow_unchained: bool, record: dict[str, Any]
) -> str | None:
    if scan.malformed_line is not None:
        return REASON_MALFORMED_ROW
    if scan.misplaced_line is not None:
        return REASON_MISPLACED_TRAILER
    if _foreign_org_line(scan, record.get("org_id")) is not None:
        return REASON_ORG_MISMATCH
    if scan.last_row_id != head.row_id:  # also without any event row: the head names one
        return REASON_TRUNCATED
    if scan.last_hash != head.entry_hash:
        return REASON_HEAD_MISMATCH
    if scan.first_break is not None and not head_is_filtered(record):
        return REASON_CHAIN_BREAK
    if scan.unchained and not allow_unchained:
        return REASON_UNCHAINED
    if scan.previous_ok is False:
        return REASON_NOT_A_CONTINUATION
    return None


def _no_trailer_result(scan: ExportScan, public_key: str | bytes) -> ExportVerification:
    return ExportVerification(
        ok=False,
        row_id="",
        entry_hash="",
        public_key=trusted_key_text(public_key),
        reason=REASON_NO_TRAILER,
        rows=scan.rows,
        first_break=None,
        last_row_id=scan.last_row_id,
        unchained=scan.unchained,
        bad_line=scan.trailer_line,
    )


def export_result(
    scan: ExportScan,
    public_key: str | bytes,
    *,
    allow_unchained: bool = False,
    expected_org_id: str | None = None,
) -> ExportVerification:
    """The head signature of ``scan`` checked against ``public_key``, then the file checks.

    A scan without a usable trailer fails with ``"no_trailer"`` (the key is still validated);
    ``ValueError`` for an unusable ``public_key`` or an empty ``expected_org_id``. With
    ``expected_org_id`` a signed head of another org fails with ``"expected_org_mismatch"`` and
    the file checks do not run.
    """
    if expected_org_id == "":
        raise ValueError(EXPECTED_ORG_EMPTY)
    if scan.head is None:
        return _no_trailer_result(scan, public_key)
    head = verify_head(scan.head, public_key, expected_org_id=expected_org_id)
    reason = head.reason
    if head.ok:
        reason = _content_reason(scan, scan.head) or _file_reason(
            scan, head, allow_unchained, scan.head
        )
    bad_line = {
        REASON_MALFORMED_ROW: scan.malformed_line,
        REASON_MISPLACED_TRAILER: scan.misplaced_line,
        REASON_UNCHAINED: scan.unchained_line,
        REASON_ORG_MISMATCH: _foreign_org_line(scan, scan.head.get("org_id")),
    }.get(reason or "")
    continued = scan.previous_ok is not None and reason is None
    return ExportVerification(
        ok=reason is None,
        row_id=head.row_id,
        entry_hash=head.entry_hash,
        public_key=head.public_key,
        reason=reason,
        signed_at=head.signed_at,
        org_id=head.org_id,
        rows=scan.rows,
        first_break=None if head_is_filtered(scan.head) else scan.first_break,
        last_row_id=scan.last_row_id,
        unchained=scan.unchained,
        bad_line=bad_line,
        content_bound=head_binding(scan.head) is not None,
        filtered=head_is_filtered(scan.head),
        previous_rows=scan.previous_lines if continued else None,
        new_rows=scan.line_count - scan.previous_lines if continued else None,
    )


def verify_export(
    lines: str | Iterable[str],
    public_key: str | bytes,
    *,
    allow_unchained: bool = False,
    previous: str | Iterable[str] | None = None,
    expected_org_id: str | None = None,
) -> ExportVerification:
    """Check an export file against its signed ``audit_head`` trailer.

    ``lines`` is the whole newline-delimited JSON body or an iterable of its lines (an open
    file works and is read once; lines end at ``\\n`` only). ``public_key`` is the trust anchor,
    as for :func:`~sandfort_sdk.audit_head.verify_head`. The checks, in order: the head
    signature; no line is malformed (``"malformed_row"``: not a JSON object, not valid UTF-8,
    nested too deeply, no text ``id``, a non-text ``hash`` or ``prev_hash``, or over 1 MiB;
    ``bad_line`` names it); the head is the last non-blank line (``"misplaced_trailer"`` for an
    ``audit_head`` or ``export_summary`` line anywhere else); the last event row's ``id`` and
    ``hash`` equal the head's ``row_id`` and ``hash`` (reason ``"truncated"`` when the head's row
    is not the last row, is absent, or there are no event rows at all, since the head names a
    row; ``"head_mismatch"`` when the ids match and the hashes differ or the last row has no
    hash); every row's ``prev_hash`` equals the previous row's ``hash`` (reason
    ``"chain_break"``, ``first_break`` names the row); and every row carries a ``hash``
    (reason ``"unchained_rows"``, ``bad_line`` names the first row without one). The first
    hashed row's ``prev_hash`` is not checked, since an export may start mid-chain. Server
    exports always carry hashes. With ``allow_unchained=True`` rows without a ``hash`` before the
    first hashed row are only counted in ``unchained`` and skipped by the chain comparison (one
    after it is still a break), which accepts a prefix nobody has chained. Every row, hashed or
    not, can be the last row, so an export stripped of its hashes does not verify. When the file
    has at least one valid event row but its last non-blank line is no usable ``audit_head``
    (missing, junk, or an extra row after the trailer), the reason is ``"no_trailer"`` and
    ``bad_line`` is that line.

    A head that binds the content (``content_bound``, servers from round 63 on) fixes the file's
    event lines as a whole: any added, removed, reordered or edited line (an edit that keeps
    ``hash`` and ``prev_hash`` included) is caught. Against a legacy head the client check binds
    only the last row (to the signed head) and the linkage between neighbouring rows: rows
    before the last can still be replaced or removed by someone who rewrites ``prev_hash`` and
    ``hash`` consistently, and an older, genuinely signed export still verifies (check
    ``signed_at``). In both cases the row hashes are keyed (HMAC with the server's chain key),
    so a client cannot recompute them and a server that signs a fabricated export verifies.
    Only the server-side verification proves the full chain, keyed hashes included:
    ``sandfort audit verify``, or ``audit-verify`` of the admin CLI.

    With ``expected_org_id`` the signed head must name that org, else the reason is
    ``"expected_org_mismatch"`` (head-level, no ``bad_line``; the file checks do not run). Without
    it a genuinely signed export of another org verifies: ``org_id`` of the result tells whose it
    is. Not to be confused with ``"org_mismatch"``, where a row's org differs from the head's.

    Raises ``ValueError`` for an unusable file or key: an empty file, a file without any valid
    event row whose last line is no usable ``audit_head``, a malformed key (see
    :func:`scan_export`), or an empty ``expected_org_id``.
    """
    return export_result(
        scan_export(lines, previous),
        public_key,
        allow_unchained=allow_unchained,
        expected_org_id=expected_org_id,
    )
