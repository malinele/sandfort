"""The content binding of an audit export head: row count, first row and a SHA-256 of the lines.

A head that names only the last row cannot tell an outsider whether the rows above it are the
ones the server exported. ``ExportDigest`` is fed every event line of an export as it is
streamed and keeps three small values (constant memory, no second pass), which the head then
carries and signs: ``row_count``, ``first_row_id`` and ``export_sha256``. The digest covers the
exact UTF-8 bytes of each event line including its trailing newline, in order, and not the
trailer. An auditor recomputes it from the file; it proves the file's content is what the server
signed, not that the keyed row hashes are right (that needs the chain key, server side).
"""

import hashlib
from dataclasses import dataclass

BINDING_FIELDS = ("row_count", "first_row_id", "export_sha256")
SHA256_HEX_CHARS = 64


@dataclass(frozen=True, slots=True)
class ExportBinding:
    """The three signed fields: how many event lines, the first one's id, their SHA-256 (hex)."""

    row_count: int
    first_row_id: str | None
    export_sha256: str


class ExportDigest:
    """Accumulates the binding of one export (or of one org's section of an admin export)."""

    __slots__ = ("_count", "_first", "_sha")

    def __init__(self) -> None:
        self._sha = hashlib.sha256()
        self._count = 0
        self._first: str | None = None

    def add(self, row_id: str, line: str) -> None:
        """Take one event line (``line`` ends with its newline) whose event id is ``row_id``."""
        if self._count == 0:
            self._first = row_id
        self._count += 1
        self._sha.update(line.encode("utf-8"))

    def binding(self) -> ExportBinding:
        return ExportBinding(self._count, self._first, self._sha.hexdigest())
