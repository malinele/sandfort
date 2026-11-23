"""CLI r61: `audit verify-head <file>` checks the export rows against the signed head.

By default the command now also checks that the last row is the head's row with the head's hash
and that every row's ``prev_hash`` is the previous row's ``hash``; ``--head-only`` keeps the
r60 signature-only check. Fixtures follow ``test_cli_audit_r59.py`` (a test Ed25519 key).
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from sandfort_cli import config  # noqa: E402
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
HEAD_FIELDS = {"ok", "row_id", "entry_hash", "public_key", "reason", "fingerprint", "signed_at"}
FILE_FIELDS = HEAD_FIELDS | {
    "rows_checked", "first_break", "unchained", "content_bound", "filtered",
}  # fmt: skip
NO_TRAILER = "does not end with an audit_head trailer line"


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


def public_text(private_key):
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.urlsafe_b64encode(raw).decode()


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


def chain(count):
    return [row(n) for n in range(1, count + 1)]


def head(private_key, n, **changes):
    record = {
        "type": "audit_head",
        "org_id": "org_1",
        "row_id": row_id(n),
        "hash": row_hash(n),
        "alg": "ed25519",
        "public_key": public_text(private_key),
        "signed_at": SIGNED_AT,
    }
    signature = private_key.sign(compact(record).encode())
    record["signature"] = base64.urlsafe_b64encode(signature).decode()
    record["hmac"] = "f" * 64
    return {**record, **changes}


@pytest.fixture
def export_file(tmp_path):
    def write(rows, trailer):
        path = tmp_path / "audit.ndjson"
        path.write_text("".join(compact(record) + "\n" for record in [*rows, trailer]))
        return path

    return write


def verify(path, private_key, *extra, as_json=False):
    args = ["audit", "verify-head", str(path), "--public-key", public_text(private_key), *extra]
    return invoke(args, as_json=as_json)


# --- a good file -----------------------------------------------------------------------------


def test_a_good_file_exits_0_and_shows_rows_and_signed_at(router, signer, export_file):
    path = export_file(chain(3), head(signer, 3))

    result = verify(path, signer)

    assert result.exit_code == 0, result.output
    assert "true" in result.stdout
    assert "rows_checked" in result.stdout
    assert "signed_at" in result.stdout and "2026-11-11" in result.stdout
    assert "first_break" not in result.stdout
    # r63: success says what was proven; a head without the content binding is noted as legacy
    assert result.stderr.count("\n") == 2
    assert "legacy head: content not bound" in result.stderr
    assert "verified: the Ed25519 signature" in result.stderr


def test_a_good_file_json_keeps_the_head_fields(router, signer, export_file):
    path = export_file(chain(3), head(signer, 3))

    result = verify(path, signer, as_json=True)

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert set(document) == FILE_FIELDS
    assert document["ok"] is True and document["reason"] is None
    assert document["row_id"] == row_id(3)
    assert document["signed_at"] == SIGNED_AT
    assert document["rows_checked"] == 3
    assert document["first_break"] is None and document["unchained"] == 0


def test_the_server_key_is_used_for_the_file_checks(router, signer, export_file):
    body = {"success": True, "error": None, "meta": None,
            "data": {"status": "ok", "audit_public_key": public_text(signer)}}  # fmt: skip
    status = router.get(STATUS_URL).respond(200, json=body)
    path = export_file(chain(3)[:2], head(signer, 3))

    result = invoke(["audit", "verify-head", str(path)])

    assert status.called
    assert result.exit_code == EXIT_FAILED, result.output
    assert "truncated" in result.stderr


# --- failed file checks ----------------------------------------------------------------------


def test_newest_rows_cut_exits_3_as_truncated(router, signer, export_file):
    path = export_file(chain(5)[:3], head(signer, 5))

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "truncated" in result.stderr
    assert "false" in result.stdout
    assert "rows_checked" in result.stdout


def test_newest_rows_cut_json_has_reason_truncated(router, signer, export_file):
    path = export_file(chain(5)[:3], head(signer, 5))

    result = verify(path, signer, as_json=True)

    assert result.exit_code == EXIT_FAILED, result.output
    document = json.loads(result.stdout)
    assert document["ok"] is False and document["reason"] == "truncated"


def test_old_rows_with_a_fresh_trailer_exit_3_as_truncated(router, signer, export_file):
    path = export_file(chain(3), head(signer, 8))

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "truncated" in result.stderr


def test_a_last_row_with_another_hash_exits_3_as_head_mismatch(router, signer, export_file):
    path = export_file([*chain(2), row(3, hash="ee" * 32)], head(signer, 3))

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "head_mismatch" in result.stderr


def test_an_edited_row_hash_exits_3_with_the_break_at_the_next_row(router, signer, export_file):
    rows = chain(4)
    rows[1] = row(2, hash="ee" * 32)
    path = export_file(rows, head(signer, 4))

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "chain_break" in result.stderr
    assert row_id(3) in result.stderr
    assert "first_break" in result.stdout and row_id(3) in result.stdout


def test_an_edited_prev_hash_exits_3_with_the_break_at_that_row(router, signer, export_file):
    rows = chain(4)
    rows[3] = row(4, prev_hash="ee" * 32)
    path = export_file(rows, head(signer, 4))

    result = verify(path, signer, as_json=True)

    assert result.exit_code == EXIT_FAILED, result.output
    assert json.loads(result.stdout)["reason"] == "chain_break"


def test_a_bad_signature_still_exits_3_with_its_own_reason(router, signer, export_file):
    path = export_file(chain(2), head(signer, 5))
    other = Ed25519PrivateKey.generate()

    result = verify(path, other)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "key_mismatch" in result.stderr


def test_leading_rows_without_hashes_are_noted_in_the_plural(router, signer, export_file):
    unhashed = {"hash": None, "prev_hash": None}
    path = export_file([row(1, **unhashed), row(2, **unhashed), row(3)], head(signer, 3))

    result = verify(path, signer, "--allow-unchained")

    assert result.exit_code == 0, result.output
    assert "2 rows carry no hash" in result.stderr


def test_one_row_without_a_hash_is_noted_in_the_singular(router, signer, export_file):
    path = export_file([row(1, hash=None, prev_hash=None), row(2), row(3)], head(signer, 3))

    result = verify(path, signer, "--allow-unchained")

    assert result.exit_code == 0, result.output
    assert "1 row carries no hash" in result.stderr
    assert "1 rows" not in result.stderr


def test_a_file_with_every_hash_stripped_exits_3_as_head_mismatch(router, signer, export_file):
    rows = [row(n, action="edited", hash=None, prev_hash=None) for n in (1, 2, 3)]
    path = export_file(rows, head(signer, 3))

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "head_mismatch" in result.stderr
    assert "3 rows carry no hash" in result.stderr


def test_zero_rows_under_a_head_exit_3_as_truncated(router, signer, export_file):
    path = export_file([], head(signer, 4))

    result = verify(path, signer, as_json=True)

    assert result.exit_code == EXIT_FAILED, result.output
    document = json.loads(result.stdout)
    assert document["reason"] == "truncated" and document["rows_checked"] == 0


# --- --head-only -----------------------------------------------------------------------------


def test_head_only_on_a_truncated_file_still_exits_0(router, signer, export_file):
    path = export_file(chain(5)[:3], head(signer, 5))

    result = verify(path, signer, "--head-only")

    assert result.exit_code == 0, result.output
    assert "signed_at" in result.stdout
    assert "rows_checked" not in result.stdout


def test_head_only_json_has_signed_at_and_no_file_fields(router, signer, export_file):
    path = export_file(chain(5)[:3], head(signer, 5))

    result = verify(path, signer, "--head-only", as_json=True)

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert set(document) == HEAD_FIELDS
    assert document["signed_at"] == SIGNED_AT


def test_head_only_on_a_chain_break_still_exits_0(router, signer, export_file):
    rows = chain(3)
    rows[1] = row(2, hash="ee" * 32)
    path = export_file(rows, head(signer, 3))

    result = verify(path, signer, "--head-only", as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["ok"] is True


# --- unusable files --------------------------------------------------------------------------


def test_an_unsigned_export_summary_still_exits_2_with_the_message(router, signer, export_file):
    path = export_file(chain(2), {"type": "export_summary", "rows": 2})

    result = verify(path, signer)

    assert result.exit_code == EXIT_USAGE, result.output
    assert NO_TRAILER in result.output


def test_an_export_summary_with_head_only_exits_2(router, signer, export_file):
    path = export_file(chain(2), {"type": "export_summary", "rows": 2})

    result = verify(path, signer, "--head-only")

    assert result.exit_code == EXIT_USAGE, result.output
    assert NO_TRAILER in result.output


def test_a_missing_file_exits_2(router, signer, tmp_path):
    result = verify(tmp_path / "nope.ndjson", signer)

    assert result.exit_code == EXIT_USAGE, result.output
    assert "no such file" in result.output


def test_an_unreadable_file_exits_2(router, signer, tmp_path):
    result = verify(tmp_path, signer)  # a directory

    assert result.exit_code == EXIT_USAGE, result.output
    assert "cannot read" in result.output
    assert "Traceback" not in result.output


def test_a_file_that_is_not_utf8_exits_2(router, signer, tmp_path):
    path = tmp_path / "audit.ndjson"
    path.write_bytes(b"\xff\xfe\n")

    result = verify(path, signer)

    assert result.exit_code == EXIT_USAGE, result.output


def test_a_final_line_that_is_not_json_exits_2_without_valid_rows(router, signer, tmp_path):
    path = tmp_path / "audit.ndjson"
    path.write_text("{}\nnot json\n")

    result = verify(path, signer)

    assert result.exit_code == EXIT_USAGE, result.output
    assert NO_TRAILER in result.output


def test_an_empty_file_exits_2_with_the_trailer_message(router, signer, tmp_path):
    path = tmp_path / "audit.ndjson"
    path.write_text("\n\n")

    result = verify(path, signer)

    assert result.exit_code == EXIT_USAGE, result.output
    assert NO_TRAILER in result.output


def test_a_row_that_is_not_json_exits_3_as_malformed_row(router, signer, tmp_path):
    path = tmp_path / "audit.ndjson"
    path.write_text("not json\n" + compact(head(signer, 1)) + "\n")

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "Traceback" not in result.output
    assert "malformed_row" in result.stderr
    assert "line 1" in result.stderr


def write_lines(tmp_path, signer, middle, n=2):
    path = tmp_path / "audit.ndjson"
    body = [compact(row(1)), *middle, compact(row(2)), compact(head(signer, n))]
    path.write_text("".join(text + "\n" for text in body))
    return path


@pytest.mark.parametrize(
    "bad",
    ["[1, 2]", '"x"', compact(row(9, hash=5)), compact(row(9, prev_hash=5)), '{"action": "x"}'],
)
def test_a_non_object_or_badly_typed_row_exits_3_naming_the_line(router, signer, tmp_path, bad):
    path = write_lines(tmp_path, signer, [bad])

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "malformed_row" in result.stderr and "line 2" in result.stderr


def test_a_malformed_row_json_has_the_reason_and_the_line(router, signer, tmp_path):
    path = write_lines(tmp_path, signer, ["{broken"])

    result = verify(path, signer, as_json=True)

    assert result.exit_code == EXIT_FAILED, result.output
    document = json.loads(result.stdout)
    assert document["reason"] == "malformed_row" and document["bad_line"] == 2


def test_a_line_over_one_mebibyte_exits_3_as_malformed_row(router, signer, tmp_path):
    path = write_lines(tmp_path, signer, ["x" * (1024 * 1024 + 10)])

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "malformed_row" in result.stderr and "line 2" in result.stderr


def test_a_malformed_row_with_head_only_still_exits_0(router, signer, tmp_path):
    path = write_lines(tmp_path, signer, ["{broken"])

    result = verify(path, signer, "--head-only")

    assert result.exit_code == 0, result.output


def test_a_trailer_that_is_not_last_exits_3_as_misplaced_trailer(router, signer, tmp_path):
    path = write_lines(tmp_path, signer, [compact({"type": "export_summary", "rows": 2})])

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "misplaced_trailer" in result.stderr and "line 2" in result.stderr


def test_a_duplicated_trailer_exits_3_as_misplaced_trailer(router, signer, tmp_path):
    path = write_lines(tmp_path, signer, [compact(head(signer, 1))])

    result = verify(path, signer, as_json=True)

    assert result.exit_code == EXIT_FAILED, result.output
    document = json.loads(result.stdout)
    assert document["reason"] == "misplaced_trailer" and document["bad_line"] == 2


def test_duplicate_row_ids_exit_3_as_chain_break(router, signer, export_file):
    path = export_file([row(1), row(2), row(2)], head(signer, 2))

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "chain_break" in result.stderr


def test_exotic_separators_inside_a_row_do_not_split_it(router, signer, tmp_path):
    rows = [row(1, action="a\u2028b\x85c\x1cd"), row(2)]
    path = tmp_path / "audit.ndjson"
    body = [json.dumps(r, ensure_ascii=False) for r in [*rows, head(signer, 2)]]
    path.write_text("".join(text + "\n" for text in body), encoding="utf-8")

    result = verify(path, signer)

    assert result.exit_code == 0, result.output


def test_crlf_files_verify(router, signer, tmp_path):
    path = tmp_path / "audit.ndjson"
    body = [compact(r) for r in [*chain(2), head(signer, 2)]]
    path.write_bytes("".join(text + "\r\n" for text in body).encode())

    result = verify(path, signer)

    assert result.exit_code == 0, result.output


# --- the missing-key hint --------------------------------------------------------------------


def test_a_server_without_a_public_key_names_the_operator_settings(router, signer, export_file):
    body = {"success": True, "error": None, "meta": None,
            "data": {"status": "ok", "audit_public_key": None}}  # fmt: skip
    router.get(STATUS_URL).respond(200, json=body)
    path = export_file(chain(2), head(signer, 2))

    result = invoke(["audit", "verify-head", str(path)])

    assert result.exit_code == EXIT_USAGE, result.output
    assert "--public-key" in result.output
    assert "SANDFORT_AUDIT_SIGNING_KEY" in result.output
    assert "SANDFORT_AUDIT_CHAIN_KEY" in result.output


def test_the_truncated_text_says_the_trailer_is_from_another_export():
    from sandfort_cli.audit import REASONS

    text = " ".join(REASONS["truncated"].split())
    assert "the trailer is from a different (earlier or later) export" in text
    assert "belongs to a later export" not in text


# --- reason table ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reason", ["truncated", "head_mismatch", "chain_break", "malformed_row", "misplaced_trailer"]
)
def test_every_file_reason_has_an_explanation(reason):
    from sandfort_cli.audit import REASONS
    from sandfort_sdk import audit_export

    assert reason in {
        audit_export.REASON_TRUNCATED,
        audit_export.REASON_HEAD_MISMATCH,
        audit_export.REASON_CHAIN_BREAK,
        audit_export.REASON_MALFORMED_ROW,
        audit_export.REASON_MISPLACED_TRAILER,
    }
    assert REASONS[reason].strip()


# --- r61 review: deep nesting, UTF-8, unchained rows, no trailer, limits ---------------------

DEPTH = 100_000
UNHASHED = {"hash": None, "prev_hash": None}


def deep_text():
    return "[" * DEPTH + "]" * DEPTH


def deep_line(record):
    return compact(record)[:-1] + ',"extra":' + deep_text() + "}"


def write_raw(tmp_path, chunks):
    path = tmp_path / "audit.ndjson"
    path.write_bytes(b"".join(chunks))
    return path


def encoded(record):
    return compact(record).encode() + b"\n"


def test_a_deeply_nested_row_exits_3_as_malformed_row(router, signer, tmp_path):
    chunks = [encoded(row(1)), deep_line(row(2)).encode() + b"\n", encoded(row(3))]
    path = write_raw(tmp_path, [*chunks, encoded(head(signer, 3))])

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "Traceback" not in result.output
    assert "malformed_row" in result.stderr and "line 2" in result.stderr


def test_a_deeply_nested_row_json_names_the_line(router, signer, tmp_path):
    path = write_raw(tmp_path, [deep_line(row(1)).encode() + b"\n", encoded(head(signer, 1))])

    result = verify(path, signer, as_json=True)

    document = json.loads(result.stdout)
    assert result.exit_code == EXIT_FAILED
    assert document["reason"] == "malformed_row" and document["bad_line"] == 1


def test_a_deeply_nested_trailer_alone_exits_2(router, signer, tmp_path):
    trailer = '{"type":"audit_head","x":' + deep_text() + "}\n"
    path = write_raw(tmp_path, [b"{}\n", trailer.encode()])

    result = verify(path, signer)

    assert result.exit_code == EXIT_USAGE, result.output
    assert "Traceback" not in result.output


def test_a_deeply_nested_trailer_after_valid_rows_exits_3_as_no_trailer(
    router, signer, tmp_path
):
    trailer = '{"type":"audit_head","x":' + deep_text() + "}\n"
    path = write_raw(tmp_path, [encoded(row(1)), trailer.encode()])

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "no_trailer" in result.stderr and "Traceback" not in result.output


def test_a_middle_row_with_invalid_utf8_exits_3_as_malformed_row(router, signer, tmp_path):
    bad = compact(row(2)).encode().replace(b"sandbox.create", b"sand\xffbox")
    path = write_raw(tmp_path, [encoded(row(1)), bad + b"\n", encoded(row(3))])
    path.write_bytes(path.read_bytes() + encoded(head(signer, 3)))

    result = verify(path, signer, as_json=True)

    assert result.exit_code == EXIT_FAILED, result.output
    document = json.loads(result.stdout)
    assert document["reason"] == "malformed_row" and document["bad_line"] == 2


def test_invalid_utf8_in_a_row_agrees_with_the_sdk(router, signer, tmp_path):
    from sandfort_sdk import verify_export

    bad = compact(row(1)).encode().replace(b"sandbox.create", b"sand\xffbox")
    path = write_raw(tmp_path, [bad + b"\n", encoded(row(2)), encoded(head(signer, 2))])

    result = verify(path, signer, as_json=True)
    with path.open(encoding="utf-8", errors="surrogateescape", newline="\n") as handle:
        sdk = verify_export(handle, public_text(signer))

    assert json.loads(result.stdout)["reason"] == sdk.reason == "malformed_row"
    assert json.loads(result.stdout)["bad_line"] == sdk.bad_line == 1


def test_invalid_utf8_in_the_trailer_alone_exits_2(router, signer, tmp_path):
    path = write_raw(tmp_path, [b'{"type":"audit_head","x":"\xff"}\n'])

    result = verify(path, signer)

    assert result.exit_code == EXIT_USAGE, result.output
    assert "Traceback" not in result.output


def test_invalid_utf8_in_the_trailer_after_valid_rows_exits_3_as_no_trailer(
    router, signer, tmp_path
):
    path = write_raw(tmp_path, [encoded(row(1)), b'{"type":"audit_head","x":"\xff"}\n'])

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "no_trailer" in result.stderr


def test_rows_without_a_hash_exit_3_as_unchained_rows_naming_the_line(
    router, signer, export_file
):
    path = export_file([row(1, **UNHASHED), row(2, prev_hash=None), row(3)], head(signer, 3))

    result = verify(path, signer, as_json=True)

    assert result.exit_code == EXIT_FAILED, result.output
    document = json.loads(result.stdout)
    assert document["reason"] == "unchained_rows" and document["bad_line"] == 1
    assert document["ok"] is False and document["unchained"] == 1


def test_unchained_rows_failure_text_names_the_line_and_the_flag(router, signer, export_file):
    path = export_file([row(1, **UNHASHED), row(2, prev_hash=None), row(3)], head(signer, 3))

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "unchained_rows" in result.stderr and "line 1" in result.stderr
    assert "--allow-unchained" in result.stderr
    assert "carry no hash" not in result.stderr


def test_allow_unchained_restores_exit_0_with_the_note(router, signer, export_file):
    path = export_file([row(1, **UNHASHED), row(2, prev_hash=None), row(3)], head(signer, 3))

    result = verify(path, signer, "--allow-unchained", as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["unchained"] == 1
    assert "1 row carries no hash" in result.stderr


def test_a_correct_export_needs_no_flag(router, signer, export_file):
    assert verify(export_file(chain(3), head(signer, 3)), signer).exit_code == 0


def test_a_missing_trailer_after_valid_rows_exits_3_as_no_trailer(router, signer, export_file):
    path = export_file(chain(3), head(signer, 3))
    path.write_text("".join(compact(r) + "\n" for r in chain(3)))

    result = verify(path, signer, as_json=True)

    assert result.exit_code == EXIT_FAILED, result.output
    document = json.loads(result.stdout)
    assert document["reason"] == "no_trailer" and document["bad_line"] == 3
    assert document["ok"] is False and document["rows_checked"] == 3


def test_junk_after_a_valid_trailer_exits_3_as_no_trailer(router, signer, tmp_path):
    path = write_raw(tmp_path, [*map(encoded, [row(1), head(signer, 1)]), b"junk\n"])

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "no_trailer" in result.stderr and "line 3" in result.stderr


def test_an_extra_event_row_after_a_valid_trailer_exits_3_as_no_trailer(
    router, signer, tmp_path
):
    path = write_raw(tmp_path, [*map(encoded, [row(1), head(signer, 1), row(2)])])

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "no_trailer" in result.stderr


def test_no_trailer_with_head_only_exits_2(router, signer, tmp_path):
    path = write_raw(tmp_path, [encoded(row(1)), b"junk\n"])

    result = verify(path, signer, "--head-only")

    assert result.exit_code == EXIT_USAGE, result.output
    assert NO_TRAILER in result.output and "Traceback" not in result.output


def test_a_file_with_no_valid_rows_and_no_trailer_exits_2(router, signer, tmp_path):
    for text in ("junk\n", "[1]\n{}\n", "\n"):
        path = tmp_path / "audit.ndjson"
        path.write_text(text)
        assert verify(path, signer).exit_code == EXIT_USAGE


def test_no_trailer_with_a_bad_public_key_exits_2(router, signer, tmp_path):
    path = write_raw(tmp_path, [encoded(row(1)), b"junk\n"])

    result = invoke(["audit", "verify-head", str(path), "--public-key", "nope"])

    assert result.exit_code == EXIT_USAGE, result.output


def test_the_new_reasons_have_explanations():
    from sandfort_cli.audit import REASONS

    assert "--allow-unchained" in REASONS["unchained_rows"]
    assert REASONS["no_trailer"].strip()


def test_help_states_what_the_client_check_binds():
    result = invoke(["audit", "verify-head", "--help"])
    text = " ".join(result.output.replace("│", " ").split())

    assert result.exit_code == 0
    assert "binds only the LAST row" in text
    assert "linkage between neighbouring rows" in text
    assert "older genuinely signed export still verifies" in text
    assert "sandfort audit verify" in text
    assert "--allow-unchained" in text


def test_head_record_survives_a_deeply_nested_line():
    from sandfort_cli.audit import head_record

    assert head_record('{"type":"audit_head","x":' + deep_text() + "}") is None
