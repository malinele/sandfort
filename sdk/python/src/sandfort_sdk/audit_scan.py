"""Reading an audit export: the trailer, the row linkage, the content digest and a continuation.

:func:`scan_export` reads an export once, line by line and without keeping the rows. It records
what :func:`sandfort_sdk.audit_export.export_result` needs: the trailer, the linkage of the event
rows, the SHA-256 over the exact text of every event line, and (with ``previous``) whether an
earlier export is a byte prefix of this one.
"""

import hashlib
import json
from collections.abc import AsyncIterable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any, TextIO

from sandfort_sdk.audit_continuation import (
    HEAD_TYPE,
    MAX_LINE_CHARS,
    SUMMARY_TYPE,
    TRAILER_TYPES,
    PrefixCheck,
)
from sandfort_sdk.audit_head import parse_head

EMPTY_EXPORT = "the export is empty: no audit_head trailer line"
ROW_TEXT_FIELDS = ("occurred_at", "org_id", "action")  # a row without one is malformed
ROW_CHAIN_FIELDS = ("hash", "prev_hash")  # both keys are always written (null = unchained)
NOT_UTF8 = "line {number} is not valid UTF-8"
TOO_DEEP = "line {number} is nested too deeply"


@dataclass(frozen=True, slots=True)
class ExportScan:
    """What :func:`scan_export` read from an export: the trailer and the row linkage."""

    head: dict[str, Any] | None
    rows: int
    unchained: int
    last_row_id: str | None
    last_hash: str | None
    first_break: str | None
    malformed_line: int | None = None
    misplaced_line: int | None = None
    unchained_line: int | None = None
    trailer_line: int | None = None
    trailer_error: str | None = None
    line_count: int = 0
    lines_sha256: str = ""
    first_line_id: str | None = None
    orgs: tuple[tuple[str, int], ...] = ()
    previous_ok: bool | None = None
    previous_lines: int = 0


class _MalformedRow(ValueError):
    """A line that cannot be an event row (or, as the last line, a trailer)."""


def _record(line: str, number: int) -> dict[str, Any]:
    if len(line) > MAX_LINE_CHARS:
        raise _MalformedRow(f"line {number} is longer than {MAX_LINE_CHARS} characters")
    if not line.isascii():
        try:
            line.encode("utf-8")  # a lone surrogate is an undecodable byte (surrogateescape)
        except UnicodeEncodeError:
            raise _MalformedRow(NOT_UTF8.format(number=number)) from None
    try:
        record: Any = json.loads(line)
    except RecursionError:
        raise _MalformedRow(TOO_DEEP.format(number=number)) from None
    except ValueError:
        raise _MalformedRow(f"line {number} is not JSON") from None
    if not isinstance(record, dict):
        raise _MalformedRow(f"line {number} is not a JSON object")
    return record


def _hash_field(record: dict[str, Any], name: str, number: int) -> str | None:
    """``record[name]`` as text; ``None`` when absent, null or empty."""
    value = record.get(name)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise _MalformedRow(f"line {number}: {name!r} is not text")
    return value


class _Linkage:
    """Walks the event rows in file order and keeps only what the checks need."""

    def __init__(self) -> None:
        self.rows = 0
        self.unchained = 0
        self.last_row_id: str | None = None
        self.last_hash: str | None = None
        self.first_break: str | None = None
        self.first_unchained: int | None = None
        self.orgs: list[tuple[str, int]] = []  # the first two distinct org ids, with their line

    def _break_at(self, row_id: str) -> None:
        if self.first_break is None:
            self.first_break = row_id

    def add(self, record: dict[str, Any], number: int) -> None:
        row_id = record.get("id")
        if not isinstance(row_id, str) or not row_id:
            raise _MalformedRow(f"line {number}: event row lacks a non-empty text 'id'")
        for name in ROW_TEXT_FIELDS:
            value = record.get(name)
            if not isinstance(value, str) or not value:
                raise _MalformedRow(f"line {number}: event row lacks a non-empty text {name!r}")
        for name in ROW_CHAIN_FIELDS:
            if name not in record:
                raise _MalformedRow(f"line {number}: event row lacks the {name!r} key")
        entry_hash = _hash_field(record, "hash", number)
        prev_hash = _hash_field(record, "prev_hash", number)
        org_id = record["org_id"]
        if len(self.orgs) < 2 and all(org_id != seen for seen, _ in self.orgs):
            self.orgs.append((org_id, number))
        started = self.rows > 0
        if entry_hash is None:
            self.unchained += 1
            if self.first_unchained is None:
                self.first_unchained = number
            if started:
                self._break_at(row_id)
        else:
            if started and prev_hash != self.last_hash:
                self._break_at(row_id)
            self.rows += 1
        # Every row, hashed or not, is the candidate last row the head is compared with.
        self.last_row_id, self.last_hash = row_id, entry_hash


class _Scanner:
    """Takes the lines of an export one at a time; the last non-blank line is held back."""

    def __init__(self, previous: str | Iterable[str] | None = None) -> None:
        self._linkage = _Linkage()
        self._pending: tuple[str, int] | None = None
        self._number = 0
        self._malformed: int | None = None
        self._misplaced: int | None = None
        self._sha = hashlib.sha256()
        self._lines = 0
        self._first_id: str | None = None
        self._prefix = None if previous is None else PrefixCheck(previous)

    def feed(self, raw: str) -> None:
        """Take one raw line; ``body`` keeps a trailing ``\\r`` (it is part of the bytes)."""
        self._number += 1
        body = raw.removesuffix("\n")
        if not body.removesuffix("\r").strip():
            return
        if self._pending is not None:
            self._settle(*self._pending)
        self._pending = (body, self._number)

    def _flag_malformed(self, number: int) -> None:
        if self._malformed is None:
            self._malformed = number

    def _take(self, body: str, record: dict[str, Any] | None) -> None:
        """Count an event line, extend the digest with its exact bytes and compare it."""
        line = body + "\n"
        if self._lines == 0 and record is not None and isinstance(record.get("id"), str):
            self._first_id = record["id"]
        self._lines += 1
        try:
            self._sha.update(line.encode("utf-8", "surrogateescape"))
        except UnicodeEncodeError:  # a lone surrogate other than an escaped byte: malformed
            self._sha.update(line.encode("utf-8", "surrogatepass"))
        if self._prefix is not None:
            self._prefix.feed(line)

    def _settle(self, body: str, number: int) -> None:
        """A line followed by another one: it must be an event row."""
        record: dict[str, Any] | None = None
        try:
            record = _record(body.removesuffix("\r"), number)
        except _MalformedRow:
            self._flag_malformed(number)
        if record is not None and record.get("type") in TRAILER_TYPES:
            if self._misplaced is None:
                self._misplaced = number
            return
        self._take(body, record)
        if record is None:
            return
        try:
            self._linkage.add(record, number)
        except _MalformedRow:
            self._flag_malformed(number)

    def result(self) -> ExportScan:
        if self._pending is None:
            raise ValueError(EMPTY_EXPORT)
        body, number = self._pending
        line = body.removesuffix("\r")
        try:
            head: dict[str, Any] | None = parse_head(_record(line, number))
        except ValueError as exc:  # also the private malformed-row error: re-raised plain below
            return self._without_trailer(line, number, str(exc))
        return self._scan(head)

    def _scan(
        self, head: dict[str, Any] | None, trailer_line: int | None = None, error: str | None = None
    ) -> ExportScan:
        linkage = self._linkage
        previous_ok, previous_lines = (None, 0) if self._prefix is None else self._prefix.finish()
        return ExportScan(
            head, linkage.rows, linkage.unchained,
            linkage.last_row_id, linkage.last_hash, linkage.first_break,
            self._malformed, self._misplaced, linkage.first_unchained, trailer_line, error,
            self._lines, self._sha.hexdigest(), self._first_id, tuple(linkage.orgs),
            previous_ok, previous_lines,
        )  # fmt: skip

    def _without_trailer(self, line: str, number: int, error: str) -> ExportScan:
        """The last line is no usable ``audit_head``: it may itself be a (last) event row."""
        try:
            record = _record(line, number)
            if record.get("type") == SUMMARY_TYPE:
                raise ValueError(error)  # an unsigned export: the wrong kind of file
            if record.get("type") != HEAD_TYPE:
                self._linkage.add(record, number)
        except _MalformedRow:
            pass
        if self._linkage.rows + self._linkage.unchained == 0:
            raise ValueError(error)  # no valid event row: nothing to check, an unusable file
        return self._scan(None, number, error)


def bounded_lines(handle: TextIO) -> Iterator[str]:
    """The lines of an open text file, none longer than ``MAX_LINE_CHARS`` + 1 characters.

    A longer line is cut after ``MAX_LINE_CHARS`` + 1 characters (so :func:`scan_export` finds
    it malformed) and the rest of it is read in bounded chunks and dropped. Open the file with
    ``newline="\\n"`` so that only ``\\n`` ends a line.
    """
    while True:
        line = handle.readline(MAX_LINE_CHARS + 1)
        if not line:
            return
        if len(line) > MAX_LINE_CHARS and not line.endswith("\n"):
            chunk = line
            while chunk and not chunk.endswith("\n"):
                chunk = handle.readline(MAX_LINE_CHARS)
        yield line


def scan_export(
    lines: str | Iterable[str], previous: str | Iterable[str] | None = None
) -> ExportScan:
    """Read an export (the whole body, or its lines) without keeping the rows.

    Lines end at ``\\n`` only (one trailing ``\\r`` is dropped); blank lines are skipped. The
    last non-blank line is the trailer and must be an ``audit_head``. Raises a plain
    ``ValueError`` for an empty export, or for a last line that is no usable ``audit_head`` (an
    unsigned ``export_summary``, junk, a line over 1 MiB, not UTF-8 or nested too deeply) when
    the file has no valid event row either. With at least one valid event row, an unusable last
    line does not raise: ``head`` is ``None`` and :func:`export_result` fails the check with
    ``"no_trailer"`` (a last ``export_summary`` line, the trailer of an unsigned export, always
    raises). A bad row does not raise: it is recorded in ``malformed_line`` or
    ``misplaced_line``, and :func:`export_result` fails the check. The scan also computes the
    SHA-256 over the exact text of every event line (each with its ``\\n``), their count and
    the first one's id, for heads that bind the content; ``previous`` (an earlier export, as
    lines or text) is compared line by line as a byte prefix (``previous_ok``).
    """
    scanner = _Scanner(previous)
    for raw in lines.split("\n") if isinstance(lines, str) else lines:
        scanner.feed(raw)
    return scanner.result()


async def scan_export_async(
    lines: AsyncIterable[str], previous: str | Iterable[str] | None = None
) -> ExportScan:
    """:func:`scan_export` over an asynchronous stream of lines."""
    scanner = _Scanner(previous)
    async for raw in lines:
        scanner.feed(raw)
    return scanner.result()
