"""``--previous``: is an earlier audit export an exact byte prefix of this one?

An export is append-only when the server's chain grows, so a later full export of the same org
starts with the exact event lines of an earlier one. :class:`PrefixCheck` compares them in lockstep
while the later export is scanned (constant memory: it holds one line of each at a time). The
earlier file is not verified here (verify it on its own); only its event lines are used, which are
every non-blank line except its trailer and any other trailer-typed line.
"""

import json
from collections.abc import Iterable, Iterator

HEAD_TYPE = "audit_head"
SUMMARY_TYPE = "export_summary"
TRAILER_TYPES = (HEAD_TYPE, SUMMARY_TYPE)
MAX_LINE_CHARS = 1024 * 1024


def is_trailer_line(body: str) -> bool:
    """Whether ``body`` (one line) is a JSON object typed as an audit head or export summary."""
    if len(body) > MAX_LINE_CHARS:
        return False
    try:
        record = json.loads(body)
    except (ValueError, RecursionError):
        return False
    return isinstance(record, dict) and record.get("type") in TRAILER_TYPES


def event_lines(lines: str | Iterable[str]) -> Iterator[str]:
    """The event lines of an export, each with its trailing ``"\\n"``.

    Blank lines are skipped; the last non-blank line is dropped when it is a trailer, and so is
    any trailer-typed line before it. One trailing ``"\\r"`` is kept (it is part of the bytes).
    """
    pending: str | None = None
    for raw in lines.split("\n") if isinstance(lines, str) else lines:
        body = raw.removesuffix("\n")
        if not body.removesuffix("\r").strip():
            continue
        if pending is not None and not is_trailer_line(pending.removesuffix("\r")):
            yield pending + "\n"
        pending = body
    if pending is not None and not is_trailer_line(pending.removesuffix("\r")):
        yield pending + "\n"


class PrefixCheck:
    """Compares the event lines of the export being scanned with those of an earlier export."""

    def __init__(self, previous: str | Iterable[str]) -> None:
        self._previous = event_lines(previous)
        self._matched = 0
        self._broken = False
        self._exhausted = False

    def feed(self, line: str) -> None:
        """Take the next event line of the later export (with its trailing newline)."""
        if self._broken or self._exhausted:
            return
        expected = next(self._previous, None)
        if expected is None:
            self._exhausted = True
        elif expected == line:
            self._matched += 1
        else:
            self._broken = True

    def finish(self) -> tuple[bool, int]:
        """``(is a prefix, number of earlier lines matched)`` once the later export has ended."""
        if self._broken:
            return False, self._matched
        if not self._exhausted and next(self._previous, None) is not None:
            return False, self._matched  # the earlier export has more lines than this one
        return True, self._matched
