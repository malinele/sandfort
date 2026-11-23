"""CLI r64: audit export without a trailer, --output edge cases, local `audit list` checks,
one json document on errors, an empty --previous, verify-head from stdin, a line-ending hint and
refused repeats of single-value options."""

import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
PROFILE_KEY = "sf_test_key_do_not_print"
AUDIT_URL = "/v1/audit-events"
EXPORT_URL = "/v1/audit-events/export"
RUNNER = CliRunner()
EXIT_USAGE = 2
EXIT_FAILED = 3
SIGNED_AT = "2026-11-11T04:00:00+00:00"
SEED_PREV = "00" * 32
EVENTS = '{"id":"aud_001","action":"sandbox.create"}\n{"id":"aud_002","action":"key.revoke"}\n'
SUMMARY = '{"type":"export_summary","row_count":2}\n'
WARNING = "the export ended without a trailer line; it may be cut short"
FORBIDDEN = {
    "success": False,
    "data": None,
    "error": {"code": "FORBIDDEN", "message": "audit:read needed"},
}


def invoke(args, *, as_json=False, input=None):
    return RUNNER.invoke(create_app(), (["--json"] if as_json else []) + args, input=input)


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


def envelope(data, meta=None):
    return {"success": True, "data": data, "error": None, "meta": meta}


def event_json(number):
    return {
        "id": f"aud_{number:03d}",
        "org_id": "org_1",
        "actor_type": "api_key",
        "actor_id": "key_1",
        "action": "sandbox.create",
        "target_type": "sandbox",
        "target_id": f"sbx_{number:03d}",
        "outcome": "success",
        "request_id": f"req_{number:03d}",
        "occurred_at": "2026-11-01T10:30:00+00:00",
        "details": {},
    }


# --- 1. export without a trailer ---------------------------------------------------------------


def test_export_without_a_trailer_warns_and_exits_3_on_stdout(router):
    router.get(EXPORT_URL).respond(200, text=EVENTS)

    result = invoke(["audit", "export"])

    assert result.exit_code == EXIT_FAILED, result.output
    assert WARNING in result.stderr
    assert result.stdout == EVENTS


def test_export_without_a_trailer_to_a_file_keeps_the_file_and_exits_3(router, tmp_path):
    router.get(EXPORT_URL).respond(200, text=EVENTS)
    target = tmp_path / "audit.ndjson"

    result = invoke(["audit", "export", "--output", str(target)])

    assert result.exit_code == EXIT_FAILED, result.output
    assert WARNING in result.stderr
    assert target.read_text() == EVENTS


def test_an_empty_export_has_no_trailer_either(router):
    router.get(EXPORT_URL).respond(200, text="")

    result = invoke(["audit", "export"])

    assert result.exit_code == EXIT_FAILED
    assert WARNING in result.stderr


def test_an_export_ending_in_an_event_row_has_no_trailer(router):
    router.get(EXPORT_URL).respond(200, text=SUMMARY + EVENTS)

    assert invoke(["audit", "export"]).exit_code == EXIT_FAILED


@pytest.mark.parametrize("trailer", [SUMMARY, '{"type":"audit_head","row_id":"aud_002"}\n'])
def test_export_with_a_trailer_exits_0(router, trailer):
    router.get(EXPORT_URL).respond(200, text=EVENTS + trailer)

    result = invoke(["audit", "export"])

    assert result.exit_code == 0, result.output
    assert WARNING not in result.stderr


# --- 2. --output edge cases --------------------------------------------------------------------


def test_output_dash_writes_to_stdout_not_a_file_named_dash(router, tmp_path, monkeypatch):
    router.get(EXPORT_URL).respond(200, text=EVENTS + SUMMARY)
    monkeypatch.chdir(tmp_path)

    result = invoke(["audit", "export", "--output", "-"])

    assert result.exit_code == 0, result.output
    assert result.stdout == EVENTS + SUMMARY
    assert not (tmp_path / "-").exists()


@pytest.mark.parametrize("name", ["", "  "])
def test_an_empty_output_is_a_usage_error(router, name):
    route = router.get(EXPORT_URL).respond(200, text=EVENTS + SUMMARY)

    result = invoke(["audit", "export", "--output", name])

    assert result.exit_code == EXIT_USAGE
    assert "--output needs a file name" in result.stderr
    assert "directory" not in result.stderr
    assert not route.called


def test_force_without_output_is_a_usage_error(router):
    route = router.get(EXPORT_URL).respond(200, text=EVENTS + SUMMARY)

    result = invoke(["audit", "export", "--force"])

    assert result.exit_code == EXIT_USAGE
    assert "--force needs --output" in result.stderr
    assert not route.called


def test_force_with_output_dash_is_a_usage_error(router):
    result = invoke(["audit", "export", "--force", "--output", "-"])

    assert result.exit_code == EXIT_USAGE
    assert "--force needs --output" in result.stderr


def test_a_quoted_tilde_path_that_cannot_be_written_gets_a_hint(router, tmp_path, monkeypatch):
    router.get(EXPORT_URL).respond(200, text=EVENTS + SUMMARY)
    monkeypatch.chdir(tmp_path)

    result = invoke(["audit", "export", "--output", "~/x.ndjson"])

    assert result.exit_code == 1
    assert "cannot write" in result.stderr
    assert "the shell did not expand ~; use $HOME/x.ndjson or an unquoted ~" in result.stderr


def test_the_tilde_hint_is_in_the_json_error(router, tmp_path, monkeypatch):
    router.get(EXPORT_URL).respond(200, text=EVENTS + SUMMARY)
    monkeypatch.chdir(tmp_path)

    result = invoke(["audit", "export", "--output", "~/x"], as_json=True)

    assert "the shell did not expand ~" in json.loads(result.stdout)["error"]["hint"]


def test_an_ordinary_write_failure_has_no_tilde_hint(router, tmp_path):
    router.get(EXPORT_URL).respond(200, text=EVENTS + SUMMARY)

    result = invoke(["audit", "export", "--output", str(tmp_path / "nope" / "a")])

    assert result.exit_code == 1
    assert "the shell did not expand" not in result.stderr


# --- 3. local validation of audit list ---------------------------------------------------------


def test_list_with_an_unknown_outcome_is_a_usage_error_without_a_request(router):
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--outcome", "bogus"])

    assert result.exit_code == EXIT_USAGE
    assert "--outcome" in result.stderr
    for value in ("success", "denied", "error"):
        assert value in result.stderr
    assert not route.called


@pytest.mark.parametrize("outcome", ["success", "denied", "error"])
def test_list_accepts_the_api_outcomes(router, outcome):
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--outcome", outcome])

    assert result.exit_code == 0, result.output
    assert route.calls[0].request.url.params["outcome"] == outcome


def test_list_with_from_after_to_is_a_usage_error_without_a_request(router):
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--from", "2026-11-05", "--to", "2026-11-01"])

    assert result.exit_code == EXIT_USAGE
    assert "--from" in result.stderr and "--to" in result.stderr
    assert not route.called


def test_list_with_equal_from_and_to_is_sent(router):
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--from", "2026-11-05", "--to", "2026-11-05"])

    assert result.exit_code == 0, result.output
    assert route.called


def test_export_checks_outcome_and_period_locally_too(router):
    route = router.get(EXPORT_URL).respond(200, text=EVENTS + SUMMARY)

    assert invoke(["audit", "export", "--outcome", "bogus"]).exit_code == EXIT_USAGE
    swapped = ["audit", "export", "--from", "2026-11-05", "--to", "2026-11-01"]
    assert invoke(swapped).exit_code == EXIT_USAGE
    assert not route.called


# --- 4. one json document when list --all fails ------------------------------------------------


def paged(pages):
    def answer(request):
        reply = pages[request.url.params.get("cursor")]
        return reply if isinstance(reply, httpx.Response) else httpx.Response(200, json=reply)

    return answer


def test_list_all_json_failure_is_one_document_counting_the_partial_rows(router):
    pages = {
        None: envelope([event_json(1), event_json(2)], meta={"next_cursor": "cur_a"}),
        "cur_a": httpx.Response(403, json=FORBIDDEN),
    }
    router.get(AUDIT_URL).mock(side_effect=paged(pages))

    result = invoke(["audit", "list", "--all"], as_json=True)

    assert result.exit_code == 1
    document = json.loads(result.stdout)
    assert list(document) == ["error"]
    assert document["error"]["message"] == "audit:read needed"
    assert document["error"]["details"]["partial_rows"] == 2


def test_list_all_json_failure_on_the_first_page_counts_zero_rows(router):
    router.get(AUDIT_URL).respond(403, json=FORBIDDEN)

    result = invoke(["audit", "list", "--all"], as_json=True)

    assert result.exit_code == 1
    assert json.loads(result.stdout)["error"]["details"]["partial_rows"] == 0


def test_list_all_json_success_is_still_a_plain_list(router):
    pages = {
        None: envelope([event_json(1)], meta={"next_cursor": "cur_a"}),
        "cur_a": envelope([event_json(2)]),
    }
    router.get(AUDIT_URL).mock(side_effect=paged(pages))

    result = invoke(["audit", "list", "--all"], as_json=True)

    assert result.exit_code == 0, result.output
    assert [item["id"] for item in json.loads(result.stdout)] == ["aud_001", "aud_002"]


# --- verify-head helpers -----------------------------------------------------------------------


def compact(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode()


def public_text(private_key):
    return b64(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )


def row(n):
    return {
        "id": f"aud_{n:03d}",
        "org_id": "org_1",
        "actor_type": "api_key",
        "action": "sandbox.create",
        "occurred_at": "2026-11-11T03:00:00+00:00",
        "details": {},
        "prev_hash": SEED_PREV if n == 1 else hashlib.sha256(f"row-{n - 1}".encode()).hexdigest(),
        "hash": hashlib.sha256(f"row-{n}".encode()).hexdigest(),
    }


def head(private_key, rows):
    text = [compact(r) + "\n" for r in rows]
    record = {
        "type": "audit_head",
        "org_id": "org_1",
        "row_id": rows[-1]["id"],
        "hash": rows[-1]["hash"],
        "alg": "ed25519",
        "public_key": public_text(private_key),
        "signed_at": SIGNED_AT,
        "row_count": len(text),
        "first_row_id": rows[0]["id"],
        "export_sha256": hashlib.sha256("".join(text).encode()).hexdigest(),
    }
    record["signature"] = b64(private_key.sign(compact(record).encode()))
    record["hmac"] = "f" * 64
    return record


@pytest.fixture
def signer():
    return Ed25519PrivateKey.generate()


def export_text(signer, count=3):
    rows = [row(n) for n in range(1, count + 1)]
    return "".join(compact(r) + "\n" for r in [*rows, head(signer, rows)])


def verify(path, signer, *extra, as_json=False, input=None):
    args = ["audit", "verify-head", str(path), "--public-key", public_text(signer), *extra]
    return invoke(args, as_json=as_json, input=input)


# --- 5. an empty --previous --------------------------------------------------------------------


def test_an_empty_previous_file_is_a_usage_error(signer, tmp_path):
    current = tmp_path / "now.ndjson"
    current.write_text(export_text(signer))
    previous = tmp_path / "before.ndjson"
    previous.write_text("")

    result = verify(current, signer, "--previous", str(previous))

    assert result.exit_code == EXIT_USAGE, result.output
    assert "the previous export has no event rows" in result.stderr


def test_a_trailer_only_previous_file_is_a_usage_error(signer, tmp_path):
    current = tmp_path / "now.ndjson"
    current.write_text(export_text(signer))
    previous = tmp_path / "before.ndjson"
    previous.write_text(compact(head(signer, [row(1)])) + "\n")

    result = verify(current, signer, "--previous", str(previous))

    assert result.exit_code == EXIT_USAGE
    assert "the previous export has no event rows" in result.stderr


def test_a_previous_with_rows_still_counts_the_new_rows(signer, tmp_path):
    current = tmp_path / "now.ndjson"
    current.write_text(export_text(signer, 3))
    previous = tmp_path / "before.ndjson"
    previous.write_text(export_text(signer, 2))

    result = verify(current, signer, "--previous", str(previous), as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["new_rows"] == 1


# --- 6. verify-head reads stdin ----------------------------------------------------------------


def test_verify_head_dash_reads_the_export_from_stdin(signer):
    result = invoke(
        ["audit", "verify-head", "-", "--public-key", public_text(signer)],
        input=export_text(signer),
    )

    assert result.exit_code == 0, result.output
    assert "verified:" in result.stderr


def test_verify_head_dash_checks_the_content(signer):
    text = export_text(signer).replace("sandbox.create", "sandbox.delete", 1)

    result = invoke(
        ["audit", "verify-head", "-", "--public-key", public_text(signer)],
        input=text,
        as_json=True,
    )

    assert result.exit_code == EXIT_FAILED
    assert "content_mismatch" in result.output


def test_verify_head_dash_with_empty_stdin_is_a_usage_error(signer):
    result = invoke(["audit", "verify-head", "-", "--public-key", public_text(signer)], input="")

    assert result.exit_code == EXIT_USAGE
    assert "standard input" in result.stderr


# --- 7. CRLF / BOM hint ------------------------------------------------------------------------


def test_a_crlf_file_gets_the_line_ending_hint(signer, tmp_path):
    path = tmp_path / "crlf.ndjson"
    path.write_bytes(export_text(signer).replace("\n", "\r\n").encode())

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "content_mismatch" in result.stderr
    assert (
        "the file has CRLF line endings; exports must be verified byte for byte as downloaded"
        in result.stderr
    )


def test_a_bom_file_gets_the_bom_hint(signer, tmp_path):
    path = tmp_path / "bom.ndjson"
    path.write_bytes(b"\xef\xbb\xbf" + export_text(signer).encode())

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    assert "the file has a BOM; exports must be verified byte for byte" in result.stderr


def test_the_hint_is_a_json_field(signer, tmp_path):
    path = tmp_path / "crlf.ndjson"
    path.write_bytes(export_text(signer).replace("\n", "\r\n").encode())

    result = verify(path, signer, as_json=True)

    document = json.loads(result.stdout)
    assert document["reason"] == "content_mismatch"
    assert "CRLF line endings" in document["hint"]


def test_a_content_mismatch_of_an_unix_file_has_no_hint(signer, tmp_path):
    path = tmp_path / "edited.ndjson"
    path.write_text(export_text(signer).replace("sandbox.create", "sandbox.delete", 1))

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED
    assert "hint:" not in result.stderr


def test_a_good_file_has_no_hint(signer, tmp_path):
    path = tmp_path / "good.ndjson"
    path.write_text(export_text(signer))

    assert "hint" not in verify(path, signer).stderr


# --- 8. repeated single-value options ----------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "option"),
    [
        (["audit", "list", "--limit", "5", "--limit", "6"], "--limit"),
        (["audit", "list", "--order", "oldest", "--order", "newest"], "--order"),
        (["audit", "list", "--actor", "a", "--actor", "b"], "--actor"),
        (["audit", "list", "--limit=5", "--limit", "6"], "--limit"),
        (["audit", "export", "--outcome", "denied", "--outcome", "error"], "--outcome"),
        (["audit", "export", "--output", "a", "--output", "b"], "--output"),
        (["audit", "verify", "--from-id", "a", "--from-id", "b"], "--from-id"),
    ],
)
def test_a_repeated_single_value_option_is_a_usage_error(router, args, option):
    list_route = router.get(AUDIT_URL).respond(200, json=envelope([]))
    export_route = router.get(EXPORT_URL).respond(200, text=EVENTS + SUMMARY)

    result = invoke(args)

    assert result.exit_code == EXIT_USAGE, result.output
    assert f"{option} was given more than once" in result.stderr
    assert not list_route.called and not export_route.called


def test_verify_head_refuses_a_repeated_previous_and_public_key(signer, tmp_path):
    path = tmp_path / "a.ndjson"
    path.write_text(export_text(signer))

    result = verify(path, signer, "--previous", str(path), "--previous", str(path))
    assert result.exit_code == EXIT_USAGE
    assert "--previous was given more than once" in result.stderr

    result = verify(path, signer, "--public-key", public_text(signer))
    assert result.exit_code == EXIT_USAGE
    assert "--public-key was given more than once" in result.stderr


def test_a_value_that_looks_like_an_option_is_not_counted_as_a_repeat(router):
    router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--actor", "--limit", "--limit", "5"])

    assert result.exit_code == 0, result.output


def test_flags_and_distinct_options_are_not_refused(router):
    router.get(AUDIT_URL).respond(200, json=envelope([event_json(1)]))

    result = invoke(["audit", "list", "--all", "--limit", "5", "--order", "oldest"])

    assert result.exit_code == 0, result.output
