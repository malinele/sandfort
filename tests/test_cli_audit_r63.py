"""CLI r63: `audit verify-head` checks the content a signed head binds.

New reasons (exit 3): content_mismatch, count_mismatch, first_row_mismatch, org_mismatch,
future_signed_at, not_a_continuation; a new ``--previous <file>``; a success line that says what
was and was not proven; the public key is read from /v1/status without credentials.
"""

import base64
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.audit_verify_cmd import REASONS  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
PROFILE_KEY = "sf_test_key_do_not_print"
STATUS_URL = "/v1/status"
RUNNER = CliRunner()
EXIT_USAGE = 2
EXIT_FAILED = 3
SIGNED_AT = "2026-11-11T04:00:00+00:00"
SEED_PREV = "00" * 32
NEW_REASONS = (
    "content_mismatch",
    "count_mismatch",
    "first_row_mismatch",
    "org_mismatch",
    "not_a_continuation",
    "future_signed_at",
)


def invoke(args, *, as_json=False):
    return RUNNER.invoke(create_app(), (["--json"] if as_json else []) + args)


@pytest.fixture(autouse=True)
def profile(monkeypatch, tmp_path):
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, PROFILE_KEY)


@pytest.fixture
def router():
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


@pytest.fixture
def signer():
    return Ed25519PrivateKey.generate()


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode()


def public_text(private_key):
    return b64(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )


def compact(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def row_id(n):
    return f"aud_{n:03d}"


def row_hash(n):
    return hashlib.sha256(f"row-{n}".encode()).hexdigest()


def row(n, **changes):
    record = {
        "id": row_id(n),
        "org_id": "org_1",
        "actor_type": "api_key",
        "action": "sandbox.create",
        "occurred_at": "2026-11-11T03:00:00+00:00",
        "details": {},
        "prev_hash": SEED_PREV if n == 1 else row_hash(n - 1),
        "hash": row_hash(n),
    }
    return {**record, **changes}


def chain(count, first=1):
    return [row(n) for n in range(first, first + count)]


def head(private_key, rows, *, pre=None, post=None, signed_at=SIGNED_AT, over=None):
    text = ["".join([compact(r), "\n"]) for r in rows] if over is None else over
    record = {
        "type": "audit_head",
        "org_id": "org_1",
        "row_id": rows[-1]["id"],
        "hash": rows[-1]["hash"],
        "alg": "ed25519",
        "public_key": public_text(private_key),
        "signed_at": signed_at,
        "row_count": len(text),
        "first_row_id": rows[0]["id"],
        "export_sha256": hashlib.sha256("".join(text).encode()).hexdigest(),
        **(pre or {}),
    }
    record["signature"] = b64(private_key.sign(compact(record).encode()))
    record["hmac"] = "f" * 64
    return {**record, **(post or {})}


def legacy_head(private_key, n):
    record = {
        "type": "audit_head",
        "org_id": "org_1",
        "row_id": row_id(n),
        "hash": row_hash(n),
        "alg": "ed25519",
        "public_key": public_text(private_key),
        "signed_at": SIGNED_AT,
    }
    record["signature"] = b64(private_key.sign(compact(record).encode()))
    record["hmac"] = "f" * 64
    return record


@pytest.fixture
def write(tmp_path):
    counter = {"n": 0}

    def put(rows, trailer):
        counter["n"] += 1
        path = tmp_path / f"audit{counter['n']}.ndjson"
        path.write_text("".join(compact(record) + "\n" for record in [*rows, trailer]))
        return path

    return put


def verify(path, private_key, *extra, as_json=False):
    args = ["audit", "verify-head", str(path), "--public-key", public_text(private_key), *extra]
    return invoke(args, as_json=as_json)


def reason_of(result):
    return json.loads(result.stdout)["reason"]


# --- success output ---------------------------------------------------------------------------


def test_a_bound_export_exits_0_and_states_what_was_proven_and_what_not(signer, write):
    rows = chain(3)

    result = verify(write(rows, head(signer, rows)), signer)

    assert result.exit_code == 0, result.output
    assert "legacy" not in result.stderr
    line = next(item for item in result.stderr.splitlines() if item.startswith("verified:"))
    assert "Ed25519 signature (signed " in line and " ago)" in line
    assert "SHA-256, count and first row" in line and "linkage between neighbouring rows" in line
    assert "not verified: the keyed row hashes" in line and "newest export" in line
    assert "content_bound" in result.stdout


def test_json_output_has_no_proof_line_and_reports_the_binding(signer, write):
    rows = chain(3)

    result = verify(write(rows, head(signer, rows)), signer, as_json=True)

    document = json.loads(result.stdout)
    assert document["content_bound"] is True and document["filtered"] is False
    assert "verified:" not in result.stderr


def test_the_age_of_signed_at_is_shown(signer, write):
    rows = chain(2)
    two_hours = (datetime.now(UTC) - timedelta(hours=2, minutes=5)).isoformat(timespec="seconds")

    result = verify(write(rows, head(signer, rows, signed_at=two_hours)), signer)

    assert "signed 2h ago" in result.stderr


def test_a_legacy_head_still_exits_0_with_the_content_not_bound_note(signer, write):
    rows = chain(3)

    result = verify(write(rows, legacy_head(signer, 3)), signer, as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["content_bound"] is False
    assert "legacy head: content not bound" in result.stderr


def test_head_only_says_it_checked_the_signature_alone(signer, write):
    rows = chain(2)

    result = verify(write(rows, head(signer, rows)), signer, "--head-only")

    assert result.exit_code == 0, result.output
    assert "(--head-only)" in result.stderr


# --- the new reasons --------------------------------------------------------------------------


def test_an_edited_row_exits_3_as_content_mismatch(signer, write):
    rows = chain(3)
    trailer = head(signer, rows)
    edited = [rows[0], row(2, actor_id="x"), rows[2]]

    result = verify(write(edited, trailer), signer)

    assert result.exit_code == EXIT_FAILED
    assert "content_mismatch" in result.stderr and "SHA-256" in result.stderr


def test_a_wrong_count_exits_3_as_count_mismatch(signer, write):
    rows = chain(3)

    result = verify(write(rows, head(signer, rows, pre={"row_count": 4})), signer, as_json=True)

    assert result.exit_code == EXIT_FAILED and reason_of(result) == "count_mismatch"


def test_a_wrong_first_row_exits_3_as_first_row_mismatch(signer, write):
    rows = chain(3)
    trailer = head(signer, rows, pre={"first_row_id": row_id(9)})

    result = verify(write(rows, trailer), signer, as_json=True)

    assert result.exit_code == EXIT_FAILED and reason_of(result) == "first_row_mismatch"


def test_a_foreign_org_row_exits_3_as_org_mismatch_naming_the_line(signer, write):
    rows = chain(4)
    rows[2] = row(3, org_id="org_2")

    result = verify(write(rows, head(signer, rows)), signer, as_json=True)

    document = json.loads(result.stdout)
    assert result.exit_code == EXIT_FAILED and document["reason"] == "org_mismatch"
    assert document["bad_line"] == 3
    text = verify(write(rows, head(signer, rows)), signer).stderr
    assert "org_mismatch" in text and "(line 3)" in text


def test_a_row_without_the_hash_key_is_a_malformed_row(signer, write):
    rows = chain(3)
    rows[1] = {k: v for k, v in rows[1].items() if k != "hash"}

    result = verify(write(rows, head(signer, rows)), signer, as_json=True)

    assert result.exit_code == EXIT_FAILED and reason_of(result) == "malformed_row"


def test_a_future_signed_at_exits_3(signer, write):
    rows = chain(2)
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat(timespec="seconds")

    result = verify(write(rows, head(signer, rows, signed_at=future)), signer, as_json=True)

    assert result.exit_code == EXIT_FAILED and reason_of(result) == "future_signed_at"


def test_every_new_reason_has_a_table_entry():
    for reason in NEW_REASONS:
        assert REASONS[reason]


def test_first_break_is_null_for_a_file_without_a_trailer(signer, write):
    rows = [row(1), row(2, prev_hash="ff" * 32)]
    path = write(rows[:1], rows[1])

    result = verify(path, signer, as_json=True)

    document = json.loads(result.stdout)
    assert result.exit_code == EXIT_FAILED, result.output
    assert document["reason"] == "no_trailer" and document["first_break"] is None


# --- --previous -------------------------------------------------------------------------------


def test_previous_that_is_a_prefix_exits_0_and_counts_the_new_rows(signer, write):
    earlier = write(chain(2), head(signer, chain(2)))
    later = write(chain(5), head(signer, chain(5)))

    result = verify(later, signer, "--previous", str(earlier), as_json=True)

    document = json.loads(result.stdout)
    assert result.exit_code == 0, result.output
    assert document["previous_rows"] == 2 and document["new_rows"] == 3
    table = verify(later, signer, "--previous", str(earlier))
    assert "new_rows" in table.stdout and "3 new rows" in table.stderr


def test_previous_that_is_not_a_prefix_exits_3_as_not_a_continuation(signer, write):
    rows = chain(2)
    earlier = write([rows[0], row(2, actor_id="x")], head(signer, rows))
    later = write(chain(4), head(signer, chain(4)))

    result = verify(later, signer, "--previous", str(earlier))

    assert result.exit_code == EXIT_FAILED
    assert "not_a_continuation" in result.stderr


def test_a_missing_previous_file_is_a_usage_error(signer, write, tmp_path):
    later = write(chain(2), head(signer, chain(2)))

    result = verify(later, signer, "--previous", str(tmp_path / "nope.ndjson"))

    assert result.exit_code == EXIT_USAGE and "no such file" in result.stderr


def test_previous_with_head_only_is_a_usage_error(signer, write):
    both = write(chain(2), head(signer, chain(2)))

    result = verify(both, signer, "--head-only", "--previous", str(both))

    assert result.exit_code == EXIT_USAGE and "--previous" in result.stderr


# --- filtered exports -------------------------------------------------------------------------


def test_a_filtered_head_skips_linkage_and_says_so(signer, write):
    rows = [row(1), row(4, prev_hash=row_hash(3)), row(7, prev_hash=row_hash(6))]
    marked = {"filtered": True, "filters": {"outcome": "success"}}
    path = write(rows, head(signer, rows, pre=marked))

    result = verify(path, signer)
    as_json = verify(path, signer, as_json=True)

    assert result.exit_code == 0, result.output
    assert "filtered export" in result.stderr and "was not checked" in result.stderr
    assert "linkage between neighbouring rows" not in result.stderr.split("verified:")[-1]
    document = json.loads(as_json.stdout)
    assert document["filtered"] is True and document["first_break"] is None


# --- credentials and keys ---------------------------------------------------------------------


def test_the_public_key_is_read_from_the_status_route_without_credentials(
    signer, write, router, monkeypatch
):
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    (config.profile_path()).unlink()
    monkeypatch.setenv(config.BASE_URL_ENV, BASE)
    body = {"success": True, "error": None, "meta": None,
            "data": {"status": "ok", "audit_public_key": public_text(signer)}}  # fmt: skip
    status = router.get(STATUS_URL).respond(200, json=body)
    rows = chain(2)

    result = invoke(["audit", "verify-head", str(write(rows, head(signer, rows)))])

    assert result.exit_code == 0, result.output
    assert status.called
    assert "authorization" not in {name.lower() for name in status.calls[0].request.headers}


def test_without_any_server_url_the_default_key_source_is_a_usage_error(signer, write, monkeypatch):
    config.profile_path().unlink()
    rows = chain(2)

    result = invoke(["audit", "verify-head", str(write(rows, head(signer, rows)))])

    assert result.exit_code == EXIT_USAGE
    assert "--public-key" in result.stderr


def test_a_public_key_in_standard_base64_is_accepted(write):
    while True:
        private = Ed25519PrivateKey.generate()
        raw = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        if b"+" in base64.b64encode(raw) or b"/" in base64.b64encode(raw):
            break
    rows = chain(2)
    path = write(rows, head(private, rows))

    result = invoke(
        ["audit", "verify-head", str(path), "--public-key", base64.b64encode(raw).decode()]
    )

    assert result.exit_code == 0, result.output


def test_help_documents_previous_the_exit_codes_and_the_key_formats():
    result = invoke(["audit", "verify-head", "--help"])
    text = " ".join(result.output.replace("│", " ").replace("┃", " ").split())

    assert result.exit_code == 0
    assert "--previous" in text and "urlsafe or standard base64" in text
    assert "trailer and no rows under it is exit 3 truncated" in text
    assert "content_mismatch" in text
