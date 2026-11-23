# ruff: noqa: F401, F811, I001
"""Round 65: a file with fewer (or more) rows than the signed head binds is count_mismatch.

The content hash covers every line, so it differs whenever a row is cut; checking it first made
count_mismatch unreachable for real tampering. The count is now checked before the digest: a
different number of lines is count_mismatch, the same number with other bytes (an edit, a swap)
stays content_mismatch.
"""

from tests.test_cli_audit_r63 import (
    EXIT_FAILED,
    REASONS,
    invoke,
    profile,
    reason_of,
    router,
    verify,
    write,
)
from tests.test_cli_audit_r63 import chain as cli_chain
from tests.test_cli_audit_r63 import head as cli_head
from tests.test_cli_audit_r63 import row as cli_row
from tests.test_cli_audit_r63 import signer as signer
from tests.test_sdk_audit_export_r63 import chain, compact, head, key, row, row_lines

from sandfort_sdk import verify_export  # noqa: E402


def reason(signer, key, lines_for):
    rows = chain(5)
    shown = lines_for(rows)
    return verify_export([*row_lines(shown), compact(head(signer, rows)) + "\n"], key).reason


def test_rows_cut_from_the_end_are_count_mismatch(signer, key):
    assert reason(signer, key, lambda rows: rows[:3]) == "count_mismatch"


def test_a_row_cut_from_the_middle_is_count_mismatch(signer, key):
    assert reason(signer, key, lambda rows: [*rows[:2], *rows[3:]]) == "count_mismatch"


def test_an_added_row_is_count_mismatch(signer, key):
    assert reason(signer, key, lambda rows: [*rows, row(6)]) == "count_mismatch"


def test_an_edited_row_is_still_content_mismatch(signer, key):
    edited = lambda rows: [*rows[:1], row(2, actor_id="x"), *rows[2:]]  # noqa: E731

    assert reason(signer, key, edited) == "content_mismatch"


def test_swapped_rows_are_still_content_mismatch(signer, key):
    swapped = lambda rows: [rows[1], rows[0], *rows[2:]]  # noqa: E731

    assert reason(signer, key, swapped) == "content_mismatch"


def test_the_cli_reports_cut_rows_as_count_mismatch(signer, write):
    rows = cli_chain(5)
    trailer = cli_head(signer, rows)

    result = verify(write(rows[:3], trailer), signer, as_json=True)

    assert result.exit_code == EXIT_FAILED and reason_of(result) == "count_mismatch"


def test_the_help_text_of_the_reasons_names_both_directions():
    assert "removed" in REASONS["count_mismatch"] and "added" in REASONS["count_mismatch"]
    assert "removed" not in REASONS["content_mismatch"]
