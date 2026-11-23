"""SDK round 61: ``verify_export`` checks an export file against its signed ``audit_head``.

The head signature alone proved nothing about the rows: an export with its newest rows cut, old
rows under a fresh trailer, or an edited ``hash``/``prev_hash`` all verified. ``verify_export``
adds the file checks: the last row is the head's row with the head's hash, and every row links
to the previous one. Signed fixtures use a test Ed25519 key, as in ``test_sdk_audit_r59.py``.
"""

import base64
import dataclasses
import hashlib
import json
import sys
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    AsyncAudit,
    Audit,
    ExportVerification,
    HeadVerification,
    verify_export,
)
from sandfort_sdk._transport import AsyncTransport, SyncTransport, client_kwargs  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
STATUS_PATH = "/v1/status"
SIGNED_AT = "2026-11-11T04:00:00+00:00"
SEED_PREV = "00" * 32
Handler = Callable[[httpx.Request], httpx.Response]
Signer = Ed25519PrivateKey


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode()


def public_text(private: Signer) -> str:
    return b64(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def compact(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def row_id(n: int) -> str:
    return f"aud_{n:03d}"


def row_hash(n: int) -> str:
    return hashlib.sha256(f"row-{n}".encode()).hexdigest()


def row(n: int, **changes: Any) -> dict[str, Any]:
    """Event row ``n`` of a chain whose first exported row links to ``SEED_PREV``."""
    record = {
        "id": row_id(n),
        "org_id": "org_1",
        "actor_type": "api_key",
        "actor_id": "key_1",
        "action": "sandbox.create",
        "outcome": "success",
        "occurred_at": "2026-11-11T03:00:00+00:00",
        "details": {"n": n},
        "prev_hash": SEED_PREV if n == 1 else row_hash(n - 1),
        "hash": row_hash(n),
    }
    return {**record, **changes}


def head(private: Signer, n: int, **changes: Any) -> dict[str, Any]:
    """A signed head naming row ``n``; ``changes`` apply after signing (tampering)."""
    record: dict[str, Any] = {
        "type": "audit_head",
        "org_id": "org_1",
        "row_id": row_id(n),
        "hash": row_hash(n),
        "alg": "ed25519",
        "public_key": public_text(private),
        "signed_at": SIGNED_AT,
    }
    record["signature"] = b64(private.sign(compact(record).encode()))
    record["hmac"] = "cd" * 32
    return {**record, **changes}


def lines(rows: list[dict[str, Any]], trailer: dict[str, Any]) -> list[str]:
    return [compact(record) + "\n" for record in [*rows, trailer]]


def chain(count: int) -> list[dict[str, Any]]:
    return [row(n) for n in range(1, count + 1)]


@pytest.fixture
def signer() -> Signer:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def key(signer: Signer) -> str:
    return public_text(signer)


# --- a good export ---------------------------------------------------------------------------


def test_a_good_export_is_ok_with_every_row_counted(signer: Signer, key: str) -> None:
    result = verify_export(lines(chain(3), head(signer, 3)), key)

    assert result.ok and result.reason is None
    assert result.rows == 3
    assert result.first_break is None
    assert result.row_id == row_id(3) and result.entry_hash == row_hash(3)
    assert result.last_row_id == row_id(3)
    assert result.signed_at is not None and result.signed_at.isoformat() == SIGNED_AT


def test_the_whole_body_as_one_text_and_blank_lines_are_accepted(signer: Signer, key: str) -> None:
    body = "\n".join(compact(r) for r in chain(2)) + "\n\n" + compact(head(signer, 2)) + "\n"

    result = verify_export(body, key)

    assert result.ok and result.rows == 2


def test_the_first_row_prev_hash_is_not_checked(signer: Signer, key: str) -> None:
    rows = [row(1, prev_hash="ff" * 32), row(2)]

    assert verify_export(lines(rows, head(signer, 2)), key).ok


def test_a_first_row_without_prev_hash_starts_the_chain(signer: Signer, key: str) -> None:
    rows = [row(1, prev_hash=None), row(2)]

    assert verify_export(lines(rows, head(signer, 2)), key).ok


def test_an_export_without_rows_under_a_head_that_names_a_row_is_truncated(
    signer: Signer, key: str
) -> None:
    result = verify_export(lines([], head(signer, 9)), key)

    assert not result.ok and result.reason == "truncated"
    assert result.rows == 0 and result.last_row_id is None
    assert result.row_id == row_id(9)


# --- truncation and head mismatch ------------------------------------------------------------


def test_an_export_with_its_newest_rows_cut_is_truncated(signer: Signer, key: str) -> None:
    full = chain(5)

    result = verify_export(lines(full[:3], head(signer, 5)), key)

    assert not result.ok and result.reason == "truncated"
    assert result.rows == 3
    assert result.last_row_id == row_id(3)
    assert result.row_id == row_id(5)


def test_old_rows_under_a_fresh_trailer_of_a_later_head_are_truncated(
    signer: Signer, key: str
) -> None:
    old_rows = chain(3)
    later_head = head(signer, 7)

    result = verify_export(lines(old_rows, later_head), key)

    assert not result.ok and result.reason == "truncated"


def test_a_head_naming_a_middle_row_is_truncated(signer: Signer, key: str) -> None:
    result = verify_export(lines(chain(5), head(signer, 3)), key)

    assert not result.ok and result.reason == "truncated"
    assert result.last_row_id == row_id(5)


def test_the_last_row_with_another_hash_than_the_head_is_head_mismatch(
    signer: Signer, key: str
) -> None:
    rows = [*chain(2), row(3, hash="ee" * 32)]

    result = verify_export(lines(rows, head(signer, 3)), key)

    assert not result.ok and result.reason == "head_mismatch"


# --- linkage ---------------------------------------------------------------------------------


def test_an_edited_row_hash_breaks_the_chain_at_the_next_row(signer: Signer, key: str) -> None:
    rows = chain(4)
    rows[1] = row(2, hash="ee" * 32)

    result = verify_export(lines(rows, head(signer, 4)), key)

    assert not result.ok and result.reason == "chain_break"
    assert result.first_break == row_id(3)
    assert result.rows == 4


def test_an_edited_prev_hash_breaks_the_chain_at_that_row(signer: Signer, key: str) -> None:
    rows = chain(4)
    rows[2] = row(3, prev_hash="ee" * 32)

    result = verify_export(lines(rows, head(signer, 4)), key)

    assert not result.ok and result.reason == "chain_break"
    assert result.first_break == row_id(3)


def test_a_removed_middle_row_breaks_the_chain(signer: Signer, key: str) -> None:
    rows = [row(1), row(2), row(4)]

    result = verify_export(lines(rows, head(signer, 4)), key)

    assert result.reason == "chain_break" and result.first_break == row_id(4)


def test_only_the_first_break_is_named(signer: Signer, key: str) -> None:
    rows = [row(1), row(2, prev_hash="aa" * 32), row(3, prev_hash="bb" * 32)]

    result = verify_export(lines(rows, head(signer, 3)), key)

    assert result.first_break == row_id(2)


# --- order of the checks ---------------------------------------------------------------------


def test_a_bad_signature_is_reported_before_the_file_checks(signer: Signer) -> None:
    other = public_text(Ed25519PrivateKey.generate())

    result = verify_export(lines(chain(2), head(signer, 5)), other)

    assert not result.ok and result.reason == "key_mismatch"


def test_a_tampered_head_is_reason_signature(signer: Signer, key: str) -> None:
    tampered = head(signer, 2, hash="ee" * 32)

    result = verify_export(lines(chain(2), tampered), key)

    assert result.reason == "signature"


def test_truncation_is_reported_before_a_chain_break(signer: Signer, key: str) -> None:
    rows = [row(1), row(2, prev_hash="aa" * 32), row(3)]

    result = verify_export(lines(rows, head(signer, 5)), key)

    assert result.reason == "truncated"
    assert result.first_break == row_id(2)


# --- rows without chain fields ---------------------------------------------------------------


def test_rows_without_a_hash_are_counted_as_unchained_and_not_checked(
    signer: Signer, key: str
) -> None:
    rows = [row(n, action="a", hash=None, prev_hash=None) for n in (1, 2)]

    result = verify_export(lines(rows, head(signer, 42)), key)

    assert result.rows == 0 and result.unchained == 2
    assert result.last_row_id == row_id(2)
    assert result.reason == "truncated"


def test_leading_unhashed_rows_then_a_chain_is_checked_when_allowed(
    signer: Signer, key: str
) -> None:
    rows = [row(1, hash=None, prev_hash=None), row(2, prev_hash=None), row(3)]

    result = verify_export(lines(rows, head(signer, 3)), key, allow_unchained=True)

    assert result.ok and result.rows == 2 and result.unchained == 1


def test_an_unhashed_row_after_a_chained_row_breaks_the_chain(signer: Signer, key: str) -> None:
    rows = [row(1), row(2, hash=None), row(3)]

    result = verify_export(lines(rows, head(signer, 3)), key)

    assert result.reason == "chain_break" and result.first_break == row_id(2)


# --- unusable input --------------------------------------------------------------------------


def test_an_export_summary_trailer_is_a_value_error(key: str) -> None:
    summary = {"type": "export_summary", "rows": 2}

    with pytest.raises(ValueError, match="audit_head"):
        verify_export(lines(chain(2), summary), key)


def test_an_empty_export_is_a_value_error(key: str) -> None:
    with pytest.raises(ValueError):
        verify_export([], key)


def test_a_trailer_line_that_is_not_json_is_a_value_error_without_valid_rows(key: str) -> None:
    with pytest.raises(ValueError, match="line 2"):
        verify_export(["{}\n", "not json\n"], key)


def test_a_malformed_key_is_a_value_error(signer: Signer) -> None:
    with pytest.raises(ValueError):
        verify_export(lines(chain(1), head(signer, 1)), "not-a-key")


# --- the result type and the facades ---------------------------------------------------------


def test_the_result_is_frozen_and_extends_the_head_verification(signer: Signer, key: str) -> None:
    result = verify_export(lines(chain(1), head(signer, 1)), key)

    assert isinstance(result, HeadVerification)
    assert isinstance(result, ExportVerification)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.ok = False  # type: ignore[misc]


def test_the_package_exports_the_new_names() -> None:
    import sandfort_sdk

    assert "verify_export" in sandfort_sdk.__all__
    assert "ExportVerification" in sandfort_sdk.__all__


def test_the_docstrings_name_the_server_side_check() -> None:
    for function in (verify_export, Audit.verify_export, AsyncAudit.verify_export):
        text = " ".join((function.__doc__ or "").split())
        assert "keyed" in text
        assert "sandfort audit verify" in text
        assert "audit-verify" in text


class Server:
    def __init__(self, reply: httpx.Response) -> None:
        self.reply = reply
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.reply


def status_reply(public_key: str | None) -> httpx.Response:
    data = {"status": "ok", "version": "0.1.0", "audit_public_key": public_key}
    return httpx.Response(200, json={"success": True, "data": data, "error": None, "meta": None})


def sync_audit(handler: Handler) -> Audit:
    transport = SyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return Audit(transport)


def async_audit(handler: Handler) -> AsyncAudit:
    transport = AsyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return AsyncAudit(transport)


def test_sync_facade_with_an_explicit_key_makes_no_request(signer: Signer, key: str) -> None:
    server = Server(status_reply(None))

    result = sync_audit(server).verify_export(lines(chain(3)[:2], head(signer, 3)), key)

    assert result.reason == "truncated"
    assert server.requests == []


def test_sync_facade_reads_the_status_key(signer: Signer, key: str) -> None:
    server = Server(status_reply(key))

    result = sync_audit(server).verify_export(lines(chain(2), head(signer, 2)), "status")

    assert result.ok
    assert server.requests[0].url.path == STATUS_PATH


def test_sync_facade_status_without_a_published_key_is_a_value_error(signer: Signer) -> None:
    server = Server(status_reply(None))

    with pytest.raises(ValueError, match="audit_public_key"):
        sync_audit(server).verify_export(lines(chain(1), head(signer, 1)), "status")


def test_sync_facade_refuses_a_bad_file_before_any_request(key: str) -> None:
    server = Server(status_reply(key))

    with pytest.raises(ValueError):
        sync_audit(server).verify_export(["{}\n"], "status")
    assert server.requests == []


async def test_async_facade_is_a_coroutine_with_the_same_result(signer: Signer, key: str) -> None:
    rows = chain(3)
    rows[0] = row(1, hash="ee" * 32)
    server = Server(status_reply(key))

    pending = async_audit(server).verify_export(lines(rows, head(signer, 3)), "status")
    result = await pending

    assert result.reason == "chain_break" and result.first_break == row_id(2)
    assert server.requests[0].url.path == STATUS_PATH


async def test_async_facade_with_an_explicit_key(signer: Signer, key: str) -> None:
    server = Server(status_reply(None))

    result = await async_audit(server).verify_export(lines(chain(2), head(signer, 2)), key)

    assert result.ok and result.rows == 2
    assert server.requests == []


# --- review fixes: unhashed rows, empty exports ----------------------------------------------


def stripped(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rows with hash and prev_hash nulled (unchained) and their content edited."""
    return [{**r, "hash": None, "prev_hash": None, "action": "edited"} for r in rows]


def test_stripping_hash_and_prev_hash_from_every_row_is_head_mismatch(
    signer: Signer, key: str
) -> None:
    result = verify_export(lines(stripped(chain(3)), head(signer, 3)), key)

    assert not result.ok and result.reason == "head_mismatch"
    assert result.rows == 0 and result.unchained == 3
    assert result.last_row_id == row_id(3)


def test_an_unhashed_last_row_after_hashed_rows_is_head_mismatch(signer: Signer, key: str) -> None:
    rows = [*chain(2), row(3, hash=None, prev_hash=None)]

    result = verify_export(lines(rows, head(signer, 3)), key)

    assert result.reason == "head_mismatch"
    assert result.last_row_id == row_id(3)
    assert result.first_break == row_id(3)


def test_unhashed_rows_without_the_head_row_are_truncated(signer: Signer, key: str) -> None:
    result = verify_export(lines(stripped(chain(2)), head(signer, 5)), key)

    assert result.reason == "truncated"
    assert result.last_row_id == row_id(2)


def test_the_zero_row_docstring_says_truncated() -> None:
    text = " ".join((verify_export.__doc__ or "").split())
    assert "no event rows" in text and "truncated" in text


# --- review fixes: trailer position ----------------------------------------------------------


@pytest.mark.parametrize("kind", ["audit_head", "export_summary"])
def test_a_trailer_typed_line_before_the_last_line_is_misplaced(
    signer: Signer, key: str, kind: str
) -> None:
    middle = head(signer, 2) if kind == "audit_head" else {"type": kind, "rows": 2}
    body = [compact(row(1)) + "\n", compact(middle) + "\n", compact(row(2)) + "\n"]
    body.append(compact(head(signer, 2)) + "\n")

    result = verify_export(body, key)

    assert not result.ok and result.reason == "misplaced_trailer"
    assert result.bad_line == 2


def test_a_duplicated_trailer_is_misplaced_at_the_first_copy(signer: Signer, key: str) -> None:
    trailer = head(signer, 2)

    result = verify_export(lines(chain(2), trailer) + [compact(trailer) + "\n"], key)

    assert result.reason == "misplaced_trailer" and result.bad_line == 3


def test_a_trailer_followed_only_by_blank_lines_is_still_last(signer: Signer, key: str) -> None:
    body = "".join(lines(chain(2), head(signer, 2))) + "\n \n\n"

    assert verify_export(body, key).ok


def test_a_bad_signature_is_reported_before_a_misplaced_trailer(signer: Signer) -> None:
    other = public_text(Ed25519PrivateKey.generate())
    body = [compact({"type": "export_summary"}) + "\n", *lines(chain(1), head(signer, 1))]

    assert verify_export(body, other).reason == "key_mismatch"


# --- review fixes: splitting on newline only -------------------------------------------------


@pytest.mark.parametrize("separator", [" ", " ", "\x85", "\x1c", "\x1d", "\x1e", "\x0b"])
def test_exotic_line_separators_inside_a_row_do_not_split_it(
    signer: Signer, key: str, separator: str
) -> None:
    rows = [row(1, action=f"a{separator}b"), row(2)]
    text = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in [*rows, head(signer, 2)])

    as_text = verify_export(text, key)
    as_lines = verify_export(text.split("\n")[:-1], key)

    assert as_text.ok and as_text.rows == 2
    assert as_text == as_lines


def test_crlf_line_endings_are_accepted(signer: Signer, key: str) -> None:
    body = "\r\n".join(compact(r) for r in [*chain(2), head(signer, 2)]) + "\r\n"

    assert verify_export(body, key).ok
    assert verify_export(body.split("\n"), key).ok


# --- review fixes: malformed rows are failed checks ------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "not json",
        "[1, 2]",
        '"text"',
        "7",
        compact(row(2, id=7)),
        compact(row(2, id="")),
        compact({k: v for k, v in row(2).items() if k != "id"}),
        compact(row(2, hash=5)),
        compact(row(2, prev_hash=["x"])),
    ],
)
def test_a_malformed_row_is_reason_malformed_row_with_its_line(
    signer: Signer, key: str, bad: str
) -> None:
    body = [compact(row(1)) + "\n", bad + "\n", compact(row(3)) + "\n"]
    body.append(compact(head(signer, 3)) + "\n")

    result = verify_export(body, key)

    assert not result.ok and result.reason == "malformed_row"
    assert result.bad_line == 2


def test_the_first_malformed_line_is_named(signer: Signer, key: str) -> None:
    body = ["{\n", compact(row(1)) + "\n", "[]\n", compact(head(signer, 1)) + "\n"]

    assert verify_export(body, key).bad_line == 1


def test_a_line_over_one_mebibyte_is_malformed_without_being_parsed(
    signer: Signer, key: str
) -> None:
    from sandfort_sdk.audit_export import MAX_LINE_CHARS

    huge = compact(row(1, details={"blob": "x" * MAX_LINE_CHARS}))
    body = [huge + "\n", *lines([row(2)], head(signer, 2))]

    result = verify_export(body, key)

    assert result.reason == "malformed_row" and result.bad_line == 1


def test_a_trailer_over_one_mebibyte_is_a_value_error_without_valid_rows(key: str) -> None:
    from sandfort_sdk.audit_export import MAX_LINE_CHARS

    with pytest.raises(ValueError, match="longer"):
        verify_export(["x" * (MAX_LINE_CHARS + 1)], key)


def test_bounded_lines_cuts_an_oversize_line_and_keeps_the_rest(tmp_path: Path) -> None:
    from sandfort_sdk.audit_export import MAX_LINE_CHARS, bounded_lines

    path = tmp_path / "x.ndjson"
    path.write_text("a\n" + "y" * (MAX_LINE_CHARS * 2 + 5) + "\nlast\n")

    with path.open(encoding="utf-8", newline="\n") as handle:
        got = list(bounded_lines(handle))

    assert got[0] == "a\n" and got[2] == "last\n" and len(got) == 3
    assert len(got[1]) == MAX_LINE_CHARS + 1


def test_duplicate_row_ids_with_a_copied_row_break_the_chain(signer: Signer, key: str) -> None:
    rows = [row(1), row(2), row(2), row(3)]

    result = verify_export(lines(rows, head(signer, 3)), key)

    assert result.reason == "chain_break" and result.first_break == row_id(2)


def test_a_duplicated_last_row_is_a_chain_break(signer: Signer, key: str) -> None:
    result = verify_export(lines([*chain(2), row(2)], head(signer, 2)), key)

    assert result.reason == "chain_break"


def test_the_reasons_are_exported_as_constants() -> None:
    from sandfort_sdk import audit_export

    assert audit_export.REASON_MALFORMED_ROW == "malformed_row"
    assert audit_export.REASON_MISPLACED_TRAILER == "misplaced_trailer"


# --- review fixes: async streams -------------------------------------------------------------


async def agen(items: list[str]) -> AsyncIterator[str]:
    for item in items:
        yield item


async def test_async_facade_accepts_an_async_iterator(signer: Signer, key: str) -> None:
    server = Server(status_reply(None))

    result = await async_audit(server).verify_export(agen(lines(chain(3), head(signer, 3))), key)

    assert result.ok and result.rows == 3
    assert server.requests == []


async def test_async_facade_accepts_an_async_iterable_object(signer: Signer, key: str) -> None:
    class Stream:
        def __init__(self, items: list[str]) -> None:
            self.items = items

        def __aiter__(self) -> AsyncIterator[str]:
            return agen(self.items)

    server = Server(status_reply(None))

    result = await async_audit(server).verify_export(
        Stream(lines(chain(5)[:3], head(signer, 5))), key
    )

    assert result.reason == "truncated"


async def test_async_facade_reads_an_export_lines_stream(signer: Signer, key: str) -> None:
    body = "".join(lines(chain(2), head(signer, 2)))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == STATUS_PATH:
            return status_reply(key)
        return httpx.Response(200, text=body)

    audit = async_audit(handler)

    result = await audit.verify_export(audit.export_lines(), "status")

    assert result.ok and result.rows == 2


async def test_async_facade_malformed_row_in_a_stream(signer: Signer, key: str) -> None:
    items = ["oops\n", *lines(chain(1), head(signer, 1))]

    result = await async_audit(Server(status_reply(None))).verify_export(agen(items), key)

    assert result.reason == "malformed_row" and result.bad_line == 1


async def test_async_facade_empty_stream_is_a_value_error(key: str) -> None:
    with pytest.raises(ValueError):
        await async_audit(Server(status_reply(None))).verify_export(agen([]), key)


async def test_async_facade_still_accepts_text_and_sync_iterables(signer: Signer, key: str) -> None:
    audit = async_audit(Server(status_reply(None)))
    items = lines(chain(2), head(signer, 2))

    assert (await audit.verify_export("".join(items), key)).ok
    assert (await audit.verify_export(iter(items), key)).ok


# --- r61 review: deep nesting, UTF-8, unchained rows, no trailer, limits ---------------------

DEPTH = 100_000  # a 200 KB line: under the 1 MiB cap, far over any recursion limit


def deep_text() -> str:
    return "[" * DEPTH + "]" * DEPTH


def deep_row_line(n: int) -> str:
    body = compact(row(n))
    return body[:-1] + ',"extra":' + deep_text() + "}"


def test_a_deeply_nested_event_row_is_malformed_row_not_a_recursion_error(
    signer: Signer, key: str
) -> None:
    body = [compact(row(1)) + "\n", deep_row_line(2) + "\n", compact(row(3)) + "\n"]
    body.append(compact(head(signer, 3)) + "\n")
    assert len(deep_row_line(2)) < 1024 * 1024

    result = verify_export(body, key)

    assert not result.ok and result.reason == "malformed_row" and result.bad_line == 2


def test_a_deeply_nested_row_is_malformed_on_the_str_path(signer: Signer, key: str) -> None:
    body = deep_row_line(1) + "\n" + "".join(lines([row(2)], head(signer, 2)))

    result = verify_export(body, key)

    assert result.reason == "malformed_row" and result.bad_line == 1


async def test_a_deeply_nested_row_is_malformed_on_the_async_path(signer: Signer, key: str) -> None:
    items = [deep_row_line(1) + "\n", *lines([row(2)], head(signer, 2))]

    result = await async_audit(Server(status_reply(None))).verify_export(agen(items), key)

    assert result.reason == "malformed_row" and result.bad_line == 1


def test_a_deeply_nested_trailer_is_a_plain_value_error_without_valid_rows(key: str) -> None:
    bad = deep_text()

    with pytest.raises(ValueError, match="deeply") as caught:
        verify_export(["{}\n", '{"type":"audit_head","x":' + bad + "}\n"], key)
    assert type(caught.value) is ValueError


def test_a_deeply_nested_trailer_after_valid_rows_is_no_trailer(signer: Signer, key: str) -> None:
    trailer = '{"type":"audit_head","x":' + deep_text() + "}"

    result = verify_export([compact(row(1)) + "\n", trailer + "\n"], key)

    assert not result.ok and result.reason == "no_trailer" and result.bad_line == 2


def test_verify_head_treats_a_deeply_nested_head_as_invalid_signature(
    signer: Signer, key: str
) -> None:
    from sandfort_sdk import verify_head

    nested: Any = []
    for _ in range(DEPTH):
        nested = [nested]
    result = verify_head(head(signer, 1, extra=nested), key)

    assert not result.ok and result.reason == "signature"


def test_verify_head_of_a_deeply_nested_head_line_is_a_value_error(
    signer: Signer, key: str
) -> None:
    from sandfort_sdk import verify_head

    line = '{"type":"audit_head","row_id":"a","hash":"b","x":' + deep_text() + "}"

    with pytest.raises(ValueError, match="deeply"):
        verify_head(line, key)


def surrogate_row(n: int) -> str:
    """Row ``n`` with an undecodable byte, as a ``surrogateescape`` decoder shows it."""
    return compact(row(n, action="x")).replace('"x"', '"\udcff"')


def test_an_undecodable_row_is_malformed_row_on_the_str_path(signer: Signer, key: str) -> None:
    body = compact(row(1)) + "\n" + surrogate_row(2) + "\n"
    body += compact(row(3)) + "\n" + compact(head(signer, 3)) + "\n"

    result = verify_export(body, key)

    assert result.reason == "malformed_row" and result.bad_line == 2


def test_an_undecodable_row_is_malformed_row_on_the_iterable_path(
    signer: Signer, key: str
) -> None:
    body = [surrogate_row(1) + "\n", *lines([row(2)], head(signer, 2))]

    result = verify_export(body, key)

    assert result.reason == "malformed_row" and result.bad_line == 1


async def test_an_undecodable_row_is_malformed_row_on_the_async_path(
    signer: Signer, key: str
) -> None:
    items = [compact(row(1)) + "\n", surrogate_row(2) + "\n", *lines([row(3)], head(signer, 3))]

    result = await async_audit(Server(status_reply(None))).verify_export(agen(items), key)

    assert result.reason == "malformed_row" and result.bad_line == 2


def test_an_undecodable_trailer_without_valid_rows_is_a_plain_value_error(key: str) -> None:
    with pytest.raises(ValueError, match="UTF-8") as caught:
        verify_export([surrogate_row(1) + "\n"], key)
    assert type(caught.value) is ValueError


def test_valid_non_ascii_text_in_a_row_is_fine(signer: Signer, key: str) -> None:
    rows = [row(1, details={"name": "caf\u00e9 \u2603"}), row(2)]

    assert verify_export(lines(rows, head(signer, 2)), key).ok


UNHASHED = {"hash": None, "prev_hash": None}


def test_rows_without_a_hash_before_the_first_hashed_row_fail_by_default(
    signer: Signer, key: str
) -> None:
    rows = [row(1, **UNHASHED), row(2, **UNHASHED), row(3, prev_hash=None), row(4)]

    result = verify_export(lines(rows, head(signer, 4)), key)

    assert not result.ok and result.reason == "unchained_rows"
    assert result.bad_line == 1 and result.unchained == 2 and result.rows == 2


def test_the_first_unchained_line_counts_blank_lines(signer: Signer, key: str) -> None:
    body = [compact(row(1, hash=None, prev_hash=None)) + "\n"]
    body[:0] = ["\n", "\n"]
    body += lines([row(2)], head(signer, 2))

    assert verify_export(body, key).bad_line == 3


def test_allow_unchained_restores_the_note_only_behaviour(signer: Signer, key: str) -> None:
    rows = [row(1, **UNHASHED), row(2, prev_hash=None), row(3)]

    result = verify_export(lines(rows, head(signer, 3)), key, allow_unchained=True)

    assert result.ok and result.unchained == 1 and result.bad_line is None


def test_a_correct_server_export_is_unaffected_by_the_unchained_check(
    signer: Signer, key: str
) -> None:
    result = verify_export(lines(chain(3), head(signer, 3)), key)

    assert result.ok and result.unchained == 0


def test_truncation_still_outranks_unchained_rows(signer: Signer, key: str) -> None:
    result = verify_export(lines([row(1, **UNHASHED), row(2)], head(signer, 9)), key)

    assert result.reason == "truncated"


def test_the_sync_facade_passes_allow_unchained(signer: Signer, key: str) -> None:
    rows = [row(1, **UNHASHED), row(2, prev_hash=None)]
    audit = sync_audit(Server(status_reply(None)))

    assert audit.verify_export(lines(rows, head(signer, 2)), key).reason == "unchained_rows"
    assert audit.verify_export(lines(rows, head(signer, 2)), key, allow_unchained=True).ok


async def test_the_async_facade_passes_allow_unchained(signer: Signer, key: str) -> None:
    rows = [row(1, **UNHASHED), row(2, prev_hash=None)]
    audit = async_audit(Server(status_reply(None)))

    result = await audit.verify_export(agen(lines(rows, head(signer, 2))), key)
    allowed = await audit.verify_export(
        agen(lines(rows, head(signer, 2))), key, allow_unchained=True
    )

    assert result.reason == "unchained_rows" and result.bad_line == 1
    assert allowed.ok


def test_a_missing_trailer_after_valid_rows_is_no_trailer(signer: Signer, key: str) -> None:
    result = verify_export(lines(chain(3), head(signer, 3))[:-1], key)

    assert not result.ok and result.reason == "no_trailer"
    assert result.bad_line == 3 and result.row_id == "" and result.entry_hash == ""
    assert result.public_key == key and result.rows == 3 and result.last_row_id == row_id(3)


def test_junk_after_a_valid_trailer_is_no_trailer(signer: Signer, key: str) -> None:
    body = [*lines(chain(2), head(signer, 2)), "junk\n"]

    result = verify_export(body, key)

    assert result.reason == "no_trailer" and result.bad_line == 4


def test_an_extra_event_row_after_a_valid_trailer_is_no_trailer(signer: Signer, key: str) -> None:
    body = [*lines(chain(2), head(signer, 2)), compact(row(3)) + "\n"]

    result = verify_export(body, key)

    assert result.reason == "no_trailer" and result.bad_line == 4


def test_no_trailer_on_the_str_path(signer: Signer, key: str) -> None:
    body = "".join(lines(chain(2), head(signer, 2))) + "junk"

    assert verify_export(body, key).reason == "no_trailer"


async def test_no_trailer_on_the_async_path(signer: Signer, key: str) -> None:
    items = lines(chain(2), head(signer, 2))[:-1]

    result = await async_audit(Server(status_reply(None))).verify_export(agen(items), key)

    assert result.reason == "no_trailer"


def test_a_single_event_row_without_a_trailer_is_no_trailer(key: str) -> None:
    assert verify_export([compact(row(1)) + "\n"], key).reason == "no_trailer"


def test_no_trailer_still_validates_the_key(signer: Signer) -> None:
    with pytest.raises(ValueError):
        verify_export(lines(chain(1), head(signer, 1))[:-1], "not-a-key")


def test_a_file_without_valid_rows_and_a_bad_last_line_stays_a_value_error(key: str) -> None:
    for body in (["junk\n"], ["[1]\n", "{}\n"], ["\n"], []):
        with pytest.raises(ValueError):
            verify_export(body, key)


def test_the_scan_never_leaks_the_private_malformed_row_error(key: str) -> None:
    from sandfort_sdk.audit_export import scan_export

    for body in (["x" * (1024 * 1024 + 1)], ["[1]"], ['{"id": 5}'], [surrogate_row(1)]):
        with pytest.raises(ValueError) as caught:
            scan_export(body)
        assert type(caught.value) is ValueError


async def test_the_async_scan_never_leaks_the_private_error() -> None:
    from sandfort_sdk.audit_export import scan_export_async

    with pytest.raises(ValueError) as caught:
        await scan_export_async(agen(["not json\n"]))
    assert type(caught.value) is ValueError


def test_the_new_reasons_are_exported_as_constants() -> None:
    from sandfort_sdk import audit_export

    assert audit_export.REASON_UNCHAINED == "unchained_rows"
    assert audit_export.REASON_NO_TRAILER == "no_trailer"


def test_the_docstrings_state_what_the_client_check_binds() -> None:
    for function in (verify_export, Audit.verify_export, AsyncAudit.verify_export):
        text = " ".join((function.__doc__ or "").split())
        assert "binds only the last row" in text
        assert "linkage between neighbouring rows" in text
        assert "rewrites" in text and "prev_hash" in text
        assert "signed_at" in text
    full = " ".join((verify_export.__doc__ or "").split())
    assert "older, genuinely signed export still verifies" in full
    assert "proves the full chain" in full
