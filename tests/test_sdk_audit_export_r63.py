"""SDK round 63: ``verify_export`` checks the content a signed head binds.

A head from round 63 on carries ``row_count``, ``first_row_id`` and ``export_sha256`` (signed). The
client recomputes them from the file right after the signature (``content_mismatch``,
``count_mismatch``, ``first_row_mismatch``), and also checks that every row is well formed and
belongs to the head's org, that ``signed_at`` is not in the future, and (``previous``) that an
earlier export is a byte prefix of this one.
"""

import base64
import hashlib
import json
import sys
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from sandfort_sdk import AsyncAudit, Audit, verify_export  # noqa: E402
from sandfort_sdk._transport import AsyncTransport, SyncTransport, client_kwargs  # noqa: E402
from sandfort_sdk.audit_head import parse_head, verify_head  # noqa: E402

BASE = "http://sandfort.test"
SIGNED_AT = "2026-11-11T04:00:00+00:00"
SEED_PREV = "00" * 32
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


def chain(count: int, first: int = 1) -> list[dict[str, Any]]:
    return [row(n) for n in range(first, first + count)]


def row_lines(rows: Iterable[dict[str, Any]]) -> list[str]:
    return [compact(record) + "\n" for record in rows]


def sha_of(lines: list[str]) -> str:
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def head(
    private: Signer,
    rows: list[dict[str, Any]],
    *,
    over: list[str] | None = None,
    pre: dict[str, Any] | None = None,
    post: dict[str, Any] | None = None,
    signed_at: str = SIGNED_AT,
) -> dict[str, Any]:
    """A signed, content-binding head for ``rows`` (the lines ``over`` when they differ)."""
    text = row_lines(rows) if over is None else over
    last = rows[-1]
    record: dict[str, Any] = {
        "type": "audit_head",
        "org_id": "org_1",
        "row_id": last["id"],
        "hash": last["hash"],
        "alg": "ed25519",
        "public_key": public_text(private),
        "signed_at": signed_at,
        "row_count": len(text),
        "first_row_id": rows[0]["id"],
        "export_sha256": sha_of(text),
    }
    record.update(pre or {})
    record["signature"] = b64(private.sign(compact(record).encode()))
    record["hmac"] = "cd" * 32
    return {**record, **(post or {})}


def legacy_head(private: Signer, n: int, **changes: Any) -> dict[str, Any]:
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


def export(rows: list[dict[str, Any]], private: Signer, **kwargs: Any) -> list[str]:
    return [*row_lines(rows), compact(head(private, rows, **kwargs)) + "\n"]


@pytest.fixture
def signer() -> Signer:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def key(signer: Signer) -> str:
    return public_text(signer)


# --- the content binding -------------------------------------------------------------------------


def test_a_bound_export_verifies_and_says_so(signer: Signer, key: str) -> None:
    result = verify_export(export(chain(4), signer), key)

    assert result.ok and result.reason is None and result.content_bound
    assert result.rows == 4 and not result.filtered
    assert result.previous_rows is None and result.new_rows is None


def test_an_edit_that_keeps_hash_and_prev_hash_is_content_mismatch(
    signer: Signer, key: str
) -> None:
    rows = chain(4)
    signed = head(signer, rows)
    edited = [*rows[:1], row(2, actor_id="someone_else"), *rows[2:]]

    result = verify_export([*row_lines(edited), compact(signed) + "\n"], key)

    assert not result.ok and result.reason == "content_mismatch"


def test_a_removed_middle_row_is_count_mismatch_not_a_chain_break(signer: Signer, key: str) -> None:
    rows = chain(4)
    shown = [rows[0], rows[2], rows[3]]

    result = verify_export([*row_lines(shown), compact(head(signer, rows)) + "\n"], key)

    assert result.reason == "count_mismatch"


def test_reordered_rows_are_content_mismatch_and_added_rows_count_mismatch(
    signer: Signer, key: str
) -> None:
    rows = chain(3)
    trailer = compact(head(signer, rows)) + "\n"

    swapped = verify_export([*row_lines([rows[1], rows[0], rows[2]]), trailer], key)
    added = verify_export([*row_lines([*rows, row(4)]), trailer], key)

    assert swapped.reason == "content_mismatch" and added.reason == "count_mismatch"


def test_content_is_checked_right_after_the_signature_before_malformed_rows(
    signer: Signer, key: str
) -> None:
    rows = chain(3)
    broken = [*rows[:2], {k: v for k, v in rows[2].items() if k != "hash"}]

    result = verify_export([*row_lines(broken), compact(head(signer, rows)) + "\n"], key)

    assert result.reason == "content_mismatch"


def test_the_signature_is_checked_before_the_content(signer: Signer, key: str) -> None:
    rows = chain(3)
    forged = head(signer, rows, post={"export_sha256": "0" * 64})

    result = verify_export([*row_lines(rows), compact(forged) + "\n"], key)

    assert result.reason == "signature"


def test_a_wrong_row_count_under_a_valid_signature_is_count_mismatch(
    signer: Signer, key: str
) -> None:
    rows = chain(3)
    signed = head(signer, rows, pre={"row_count": 4})

    result = verify_export([*row_lines(rows), compact(signed) + "\n"], key)

    assert result.reason == "count_mismatch"


def test_a_wrong_first_row_id_under_a_valid_signature_is_first_row_mismatch(
    signer: Signer, key: str
) -> None:
    rows = chain(3)
    signed = head(signer, rows, pre={"first_row_id": row_id(9)})

    result = verify_export([*row_lines(rows), compact(signed) + "\n"], key)

    assert result.reason == "first_row_mismatch"


def test_the_digest_covers_the_exact_bytes_including_carriage_returns(
    signer: Signer, key: str
) -> None:
    rows = chain(2)
    crlf = [line[:-1] + "\r\n" for line in row_lines(rows)]

    result = verify_export([*crlf, compact(head(signer, rows)) + "\n"], key)

    assert result.reason == "content_mismatch"


def test_the_digest_covers_non_ascii_bytes_and_blank_lines_do_not_count(
    signer: Signer, key: str
) -> None:
    rows = [row(1, details={"name": "café"}), row(2)]
    lines_ = row_lines(rows)
    body = "\n" + lines_[0] + "\n\n" + lines_[1] + compact(head(signer, rows)) + "\n"

    assert verify_export(body, key).ok


def test_a_head_signed_for_an_empty_export_binds_the_empty_hash(signer: Signer, key: str) -> None:
    rows = chain(1)
    signed = head(signer, rows, over=[], pre={"row_count": 0, "first_row_id": None})

    result = verify_export([compact(signed) + "\n"], key)

    assert result.reason == "truncated"  # the head names a row the file does not have


@pytest.mark.parametrize(
    "bad",
    [{"row_count": -1}, {"row_count": "3"}, {"export_sha256": "abc"}, {"first_row_id": 5}],
)
def test_a_malformed_binding_is_not_a_usable_head(bad: dict[str, Any], signer: Signer) -> None:
    with pytest.raises(ValueError, match="content binding"):
        parse_head(head(signer, chain(2), post=bad))


def test_a_partial_binding_is_not_a_usable_head(signer: Signer) -> None:
    record = head(signer, chain(2))
    del record["row_count"]

    with pytest.raises(ValueError, match="content binding"):
        parse_head(record)


# --- legacy heads --------------------------------------------------------------------------------


def test_a_legacy_head_still_verifies_and_reports_content_not_bound(
    signer: Signer, key: str
) -> None:
    lines_ = [*row_lines(chain(3)), compact(legacy_head(signer, 3)) + "\n"]

    result = verify_export(lines_, key)

    assert result.ok and not result.content_bound


def test_a_legacy_head_keeps_the_old_checks(signer: Signer, key: str) -> None:
    rows = [row(1), row(2, prev_hash="ff" * 32), row(3)]

    result = verify_export([*row_lines(rows), compact(legacy_head(signer, 3)) + "\n"], key)

    assert result.reason == "chain_break" and result.first_break == row_id(2)


def test_stripping_the_binding_from_a_bound_head_breaks_the_signature(
    signer: Signer, key: str
) -> None:
    rows = chain(2)
    record = head(signer, rows)
    for name in ("row_count", "first_row_id", "export_sha256"):
        del record[name]

    result = verify_export([*row_lines(rows), compact(record) + "\n"], key)

    assert result.reason == "signature"


# --- malformed rows ------------------------------------------------------------------------------


@pytest.mark.parametrize("missing", ["hash", "prev_hash", "occurred_at", "org_id", "action"])
def test_a_row_missing_a_required_field_is_malformed_not_a_chain_break(
    missing: str, signer: Signer, key: str
) -> None:
    rows = chain(3)
    rows[1] = {k: v for k, v in rows[1].items() if k != missing}

    result = verify_export(export(rows, signer), key)

    assert not result.ok and result.reason == "malformed_row"
    assert result.bad_line == 2


@pytest.mark.parametrize("field", ["occurred_at", "org_id", "action"])
def test_an_empty_or_non_text_required_field_is_malformed(
    field: str, signer: Signer, key: str
) -> None:
    for bad in ("", None, 7):
        rows = chain(2)
        rows[0] = row(1, **{field: bad})

        assert verify_export(export(rows, signer), key).reason == "malformed_row"


# --- org -----------------------------------------------------------------------------------------


def test_a_row_of_another_org_is_org_mismatch_naming_the_line(signer: Signer, key: str) -> None:
    rows = chain(4)
    rows[2] = row(3, org_id="org_2")

    result = verify_export(export(rows, signer), key)

    assert not result.ok and result.reason == "org_mismatch" and result.bad_line == 3


def test_every_row_of_another_org_than_the_head_is_org_mismatch(signer: Signer, key: str) -> None:
    rows = [row(n, org_id="org_2") for n in (1, 2)]

    result = verify_export(export(rows, signer, post=None, pre={"org_id": "org_1"}), key)

    assert result.reason == "org_mismatch" and result.bad_line == 1


def test_org_mismatch_is_found_when_the_first_row_is_the_foreign_one(
    signer: Signer, key: str
) -> None:
    rows = [row(1, org_id="org_2"), row(2), row(3)]

    result = verify_export(export(rows, signer), key)

    assert result.reason == "org_mismatch" and result.bad_line == 1


# --- signed_at -----------------------------------------------------------------------------------


def stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds")


def test_a_signed_at_more_than_five_minutes_ahead_is_future_signed_at(
    signer: Signer, key: str
) -> None:
    ahead = stamp(datetime.now(UTC) + timedelta(minutes=10))

    result = verify_export(export(chain(2), signer, signed_at=ahead), key)

    assert not result.ok and result.reason == "future_signed_at"


def test_a_signed_at_within_five_minutes_of_clock_skew_is_accepted(
    signer: Signer, key: str
) -> None:
    near = stamp(datetime.now(UTC) + timedelta(minutes=3))

    assert verify_export(export(chain(2), signer, signed_at=near), key).ok


def test_verify_head_alone_refuses_a_future_signed_at(signer: Signer, key: str) -> None:
    ahead = stamp(datetime.now(UTC) + timedelta(hours=1))

    result = verify_head(head(signer, chain(2), signed_at=ahead), key)

    assert not result.ok and result.reason == "future_signed_at"


@pytest.mark.parametrize("old", ["1970-01-01T00:00:00+00:00", "1969-12-31T23:59:59+00:00"])
def test_a_signed_at_before_1970_01_02_is_not_a_valid_date(
    old: str, signer: Signer, key: str
) -> None:
    result = verify_head(head(signer, chain(2), signed_at=old), key)

    assert not result.ok and result.reason == "undated" and result.signed_at is None


def test_a_signed_at_on_1970_01_02_is_valid(signer: Signer, key: str) -> None:
    result = verify_head(head(signer, chain(2), signed_at="1970-01-02T00:00:00+00:00"), key)

    assert result.ok


# --- --previous ----------------------------------------------------------------------------------


def test_an_earlier_export_that_is_a_prefix_is_a_continuation_with_new_rows(
    signer: Signer, key: str
) -> None:
    earlier = export(chain(3), signer)
    later = export(chain(5), signer)

    result = verify_export(later, key, previous=earlier)

    assert result.ok and result.previous_rows == 3 and result.new_rows == 2


def test_the_same_export_as_previous_has_no_new_rows(signer: Signer, key: str) -> None:
    both = export(chain(3), signer)

    result = verify_export(both, key, previous=both)

    assert result.ok and result.previous_rows == 3 and result.new_rows == 0


def test_previous_may_be_the_whole_text(signer: Signer, key: str) -> None:
    earlier = "".join(export(chain(2), signer))

    result = verify_export(export(chain(4), signer), key, previous=earlier)

    assert result.ok and result.new_rows == 2


def test_an_edited_earlier_row_is_not_a_continuation(signer: Signer, key: str) -> None:
    earlier = export([row(1), row(2, actor_id="x")], signer)

    result = verify_export(export(chain(4), signer), key, previous=earlier)

    assert not result.ok and result.reason == "not_a_continuation"
    assert result.new_rows is None


def test_a_longer_earlier_export_is_not_a_continuation(signer: Signer, key: str) -> None:
    result = verify_export(export(chain(2), signer), key, previous=export(chain(4), signer))

    assert result.reason == "not_a_continuation"


def test_an_export_starting_at_another_row_is_not_a_continuation(signer: Signer, key: str) -> None:
    result = verify_export(
        export(chain(3, first=2), signer), key, previous=export(chain(2), signer)
    )

    assert result.reason == "not_a_continuation"


def test_a_byte_difference_in_the_earlier_lines_is_not_a_continuation(
    signer: Signer, key: str
) -> None:
    earlier = export(chain(2), signer)
    earlier[0] = earlier[0].replace("sandbox.create", "sandbox.delete")

    assert verify_export(export(chain(3), signer), key, previous=earlier).reason == (
        "not_a_continuation"
    )


def test_other_failures_outrank_not_a_continuation(signer: Signer, key: str) -> None:
    rows = chain(3)
    rows[2] = row(3, org_id="org_2")

    result = verify_export(export(rows, signer), key, previous=export(chain(1, first=5), signer))

    assert result.reason == "org_mismatch"


def test_previous_is_read_in_step_without_materialising_it(signer: Signer, key: str) -> None:
    pulled: list[str] = []

    def earlier() -> Iterable[str]:
        for line in export(chain(2), signer):
            pulled.append(line)
            yield line

    result = verify_export(export(chain(3), signer), key, previous=earlier())

    assert result.ok and len(pulled) == 3  # two rows and the trailer


# --- filtered heads, no_trailer, keys ------------------------------------------------------------


def test_a_filtered_head_skips_the_neighbour_linkage_but_checks_the_content(
    signer: Signer, key: str
) -> None:
    rows = [row(1), row(4, prev_hash=row_hash(3)), row(7, prev_hash=row_hash(6))]
    marked = {"filtered": True, "filters": {"outcome": "success"}}

    result = verify_export(export(rows, signer, pre=marked), key)

    assert result.ok and result.filtered and result.first_break is None


def test_a_filtered_head_still_detects_a_removed_row(signer: Signer, key: str) -> None:
    rows = [row(1), row(4, prev_hash=row_hash(3)), row(7, prev_hash=row_hash(6))]
    marked = {"filtered": True, "filters": {"outcome": "success"}}
    signed = head(signer, rows, pre=marked)

    result = verify_export([*row_lines(rows[:1] + rows[2:]), compact(signed) + "\n"], key)

    assert result.reason == "count_mismatch"


def test_the_same_rows_under_an_unfiltered_head_are_a_chain_break(signer: Signer, key: str) -> None:
    rows = [row(1), row(4, prev_hash=row_hash(3)), row(7, prev_hash=row_hash(6))]

    result = verify_export(export(rows, signer), key)

    assert result.reason == "chain_break" and not result.filtered


def test_a_filtered_marker_needs_the_binding_and_its_filters(signer: Signer) -> None:
    record = head(signer, chain(2), pre={"filtered": True})

    with pytest.raises(ValueError, match="filtered marker"):
        parse_head(record)


def test_first_break_is_none_for_no_trailer(signer: Signer, key: str) -> None:
    rows = [row(1), row(2, prev_hash="ff" * 32)]

    result = verify_export(row_lines(rows) + ['{"x":1}\n'], key)

    assert result.reason == "no_trailer" and result.first_break is None


def test_a_public_key_in_standard_base64_is_accepted(signer: Signer) -> None:
    raw = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    while b"+" not in base64.b64encode(raw) and b"/" not in base64.b64encode(raw):
        signer = Ed25519PrivateKey.generate()
        raw = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    standard = base64.b64encode(raw).decode()

    result = verify_export(export(chain(2), signer), standard)

    assert result.ok and result.public_key == public_text(signer)


# --- facades -------------------------------------------------------------------------------------


class Server:
    def __call__(self, request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request expected")


def sync_audit() -> Audit:
    transport = SyncTransport(BASE, "sf_test", 30.0, max_retries=0)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(Server()), **client_kwargs(BASE, "sf_test", 30.0)
    )
    return Audit(transport)


def async_audit() -> AsyncAudit:
    transport = AsyncTransport(BASE, "sf_test", 30.0, max_retries=0)
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(Server()), **client_kwargs(BASE, "sf_test", 30.0)
    )
    return AsyncAudit(transport)


def test_the_sync_facade_passes_previous(signer: Signer, key: str) -> None:
    result = sync_audit().verify_export(
        export(chain(3), signer), key, previous=export(chain(1), signer)
    )

    assert result.ok and result.new_rows == 2


async def test_the_async_facade_passes_previous(signer: Signer, key: str) -> None:
    async def lines_() -> Any:
        for line in export(chain(3), signer):
            yield line

    result = await async_audit().verify_export(lines_(), key, previous=export(chain(1), signer))
    broken = await async_audit().verify_export(
        export(chain(3), signer), key, previous=export(chain(1, first=2), signer)
    )

    assert result.ok and result.new_rows == 2
    assert broken.reason == "not_a_continuation"
