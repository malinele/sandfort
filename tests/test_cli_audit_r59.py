"""CLI r59: the `audit` command group (list, verify, export) over `client.audit`.

r60 adds `audit verify-head FILE` and the export note naming the head signing key.
"""

import base64
import hashlib
import json
import os
import signal
import stat
import sys
import tempfile
import threading
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
VERIFY_URL = "/v1/audit-events/verify"
EXPORT_URL = "/v1/audit-events/export"
RUNNER = CliRunner()
EXIT_USAGE = 2
EXIT_BROKEN_CHAIN = 3
ESC = "\x1b"
FORBIDDEN = {
    "success": False,
    "data": None,
    "error": {"code": "FORBIDDEN", "message": "audit:read needed"},
}


def envelope(data, meta=None):
    return {"success": True, "data": data, "error": None, "meta": meta}


def event_json(number, **extra):
    base = {
        "id": f"aud_{number:03d}",
        "org_id": "org_1",
        "actor_type": "api_key",
        "actor_id": f"key_{number:03d}",
        "action": "sandbox.create",
        "target_type": "sandbox",
        "target_id": f"sbx_{number:03d}",
        "outcome": "success",
        "request_id": f"req_{number:03d}",
        "occurred_at": "2026-11-01T10:30:00+00:00",
        "details": {},
    }
    return {**base, **extra}


def verify_json(**extra):
    base = {
        "ok": True,
        "checked": 42,
        "first_id": "aud_001",
        "last_id": "aud_042",
        "last_hash": "abc123",
        "findings": [],
        "findings_truncated": False,
    }
    return {**base, **extra}


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


def query_of(route, call=-1):
    return dict(route.calls[call].request.url.params)


# --- list: query mapping -------------------------------------------------------------------


def test_list_defaults_send_order_desc_and_limit_50(router):
    route = router.get(AUDIT_URL).respond(200, json=envelope([event_json(1)]))

    result = invoke(["audit", "list"])

    assert result.exit_code == 0, result.output
    assert query_of(route) == {"order": "desc", "limit": "50"}


def test_list_maps_every_option_to_its_query_parameter(router):
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(
        [
            "audit", "list", "--actor", "key_9", "--action", "sandbox.delete",
            "--target", "sbx_9", "--request-id", "req_9", "--outcome", "denied",
            "--from", "2026-11-01T00:00:00Z", "--to", "2026-11-02T12:00:00+02:00",
            "--order", "newest", "--limit", "7", "--cursor", "cur_1",
        ]
    )  # fmt: skip

    assert result.exit_code == 0, result.output
    query = query_of(route)
    assert query["actor_id"] == "key_9"
    assert query["action"] == "sandbox.delete"
    assert query["target_id"] == "sbx_9"
    assert query["request_id"] == "req_9"
    assert query["outcome"] == "denied"
    assert query["from"] == "2026-11-01T00:00:00+00:00"
    assert query["to"] == "2026-11-02T12:00:00+02:00"
    assert query["order"] == "desc"
    assert query["limit"] == "7"
    assert query["cursor"] == "cur_1"


def test_list_text_prints_a_table_with_the_six_columns(router):
    router.get(AUDIT_URL).respond(
        200, json=envelope([event_json(1, outcome="denied", action="key.revoke")])
    )

    result = invoke(["audit", "list"])

    assert result.exit_code == 0, result.output
    for header in ("OCCURRED", "ACTOR", "ACTION", "TARGET", "OUTCOME", "REQUEST"):
        assert header in result.stdout
    line = next(row for row in result.stdout.splitlines() if "key.revoke" in row)
    for cell in ("2026-11-01 10:30:00", "key_001", "sbx_001", "denied", "req_001"):
        assert cell in line


def test_list_text_shows_a_dash_for_missing_actor_target_and_request(router):
    router.get(AUDIT_URL).respond(
        200,
        json=envelope(
            [event_json(1, actor_id=None, target_id=None, request_id=None, action="sandbox.x")]
        ),
    )

    result = invoke(["audit", "list"])

    assert result.exit_code == 0, result.output
    line = next(row for row in result.stdout.splitlines() if "sandbox.x" in row)
    assert line.count(" - ") >= 2


def test_list_text_sanitises_server_strings(router):
    router.get(AUDIT_URL).respond(
        200, json=envelope([event_json(1, action=f"evil{ESC}[31mred{ESC}]0;title\x07")])
    )

    result = invoke(["audit", "list"])

    assert result.exit_code == 0, result.output
    assert ESC not in result.stdout
    assert "\x07" not in result.stdout


# --- list: json shapes and paging ----------------------------------------------------------


def test_list_json_without_all_wraps_events_and_next_cursor(router):
    router.get(AUDIT_URL).respond(
        200, json=envelope([event_json(1), event_json(2)], meta={"next_cursor": "cur_2"})
    )

    result = invoke(["audit", "list"], as_json=True)

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert set(document) == {"events", "next_cursor"}
    assert document["next_cursor"] == "cur_2"
    assert [item["id"] for item in document["events"]] == ["aud_001", "aud_002"]
    assert document["events"][0]["occurred_at"] == "2026-11-01T10:30:00+00:00"


def test_list_json_last_page_has_a_null_next_cursor(router):
    router.get(AUDIT_URL).respond(200, json=envelope([event_json(1)]))

    document = json.loads(invoke(["audit", "list"], as_json=True).stdout)

    assert document["next_cursor"] is None


def test_list_json_with_all_prints_a_plain_list_of_every_event(router):
    pages = {
        None: envelope([event_json(1), event_json(2)], meta={"next_cursor": "cur_a"}),
        "cur_a": envelope([event_json(3)], meta={"next_cursor": "cur_b"}),
        "cur_b": envelope([event_json(4)]),
    }

    def answer(request):
        return httpx.Response(200, json=pages[request.url.params.get("cursor")])

    route = router.get(AUDIT_URL).mock(side_effect=answer)

    result = invoke(["audit", "list", "--all", "--limit", "2"], as_json=True)

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert isinstance(document, list)
    assert [item["id"] for item in document] == ["aud_001", "aud_002", "aud_003", "aud_004"]
    assert route.call_count == 3
    assert [query_of(route, n).get("cursor") for n in range(3)] == [None, "cur_a", "cur_b"]
    assert all(query_of(route, n)["limit"] == "2" for n in range(3))


def test_list_all_text_prints_every_page(router):
    pages = {
        None: envelope([event_json(1)], meta={"next_cursor": "cur_a"}),
        "cur_a": envelope([event_json(2)]),
    }
    router.get(AUDIT_URL).mock(
        side_effect=lambda request: httpx.Response(
            200, json=pages[request.url.params.get("cursor")]
        )
    )

    result = invoke(["audit", "list", "--all"])

    assert result.exit_code == 0, result.output
    assert "sbx_001" in result.stdout
    assert "sbx_002" in result.stdout


def test_list_all_with_cursor_is_a_usage_error_before_any_request(router):
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--all", "--cursor", "cur_1"])

    assert result.exit_code == EXIT_USAGE
    assert route.call_count == 0
    assert "--cursor" in result.output


# --- list: validation ----------------------------------------------------------------------


@pytest.mark.parametrize("limit", ["0", "101", "-1"])
def test_list_limit_outside_1_to_100_is_a_usage_error(router, limit):
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--limit", limit])

    assert result.exit_code == EXIT_USAGE
    assert route.call_count == 0


def test_list_limit_bounds_1_and_100_are_accepted(router):
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    assert invoke(["audit", "list", "--limit", "1"]).exit_code == 0
    assert invoke(["audit", "list", "--limit", "100"]).exit_code == 0
    assert route.call_count == 2


def test_list_order_other_than_newest_or_oldest_is_a_usage_error(router):
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--order", "sideways"])

    assert result.exit_code == EXIT_USAGE
    assert route.call_count == 0


@pytest.mark.parametrize(
    "option", ["--actor", "--action", "--target", "--request-id", "--outcome", "--cursor"]
)
@pytest.mark.parametrize("value", ["", "   ", f"{ESC}[0m", "a\x00b"])
def test_list_empty_or_control_option_values_are_usage_errors(router, option, value):
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", option, value])

    assert result.exit_code == EXIT_USAGE, (option, value, result.output)
    assert route.call_count == 0


@pytest.mark.parametrize("option", ["--from", "--to"])
@pytest.mark.parametrize("value", ["yesterday", "2026-13-45", "", "2026-11-01T25:00:00"])
def test_list_invalid_dates_are_usage_errors(router, option, value):
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", option, value])

    assert result.exit_code == EXIT_USAGE, result.output
    assert option in result.output
    assert route.call_count == 0


def test_list_invalid_date_under_json_is_one_json_usage_object(router):
    router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--from", "yesterday"], as_json=True)

    assert result.exit_code == EXIT_USAGE
    assert "error" in json.loads(result.stdout)


def test_list_date_alone_means_midnight_utc(router):
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--from", "2026-11-01", "--to", "2026-11-03"])

    assert result.exit_code == 0, result.output
    assert query_of(route)["from"] == "2026-11-01T00:00:00+00:00"
    assert query_of(route)["to"] == "2026-11-03T00:00:00+00:00"


def test_list_naive_timestamp_counts_as_utc(router):
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--from", "2026-11-01T08:15:00"])

    assert result.exit_code == 0, result.output
    assert query_of(route)["from"] == "2026-11-01T08:15:00+00:00"


def test_list_offset_timestamp_keeps_its_offset(router):
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--to", "2026-11-01T08:15:00-05:00"])

    assert result.exit_code == 0, result.output
    assert query_of(route)["to"] == "2026-11-01T08:15:00-05:00"


def test_list_server_error_exits_one_with_the_message(router):
    router.get(AUDIT_URL).respond(403, json=FORBIDDEN)

    result = invoke(["audit", "list"])

    assert result.exit_code == 1
    assert "audit:read needed" in result.output


# --- verify --------------------------------------------------------------------------------


def test_verify_intact_chain_exits_zero_and_prints_the_fields(router):
    route = router.get(VERIFY_URL).respond(200, json=envelope(verify_json()))

    result = invoke(["audit", "verify"])

    assert result.exit_code == 0, result.output
    assert query_of(route) == {}
    for text in ("ok", "42", "aud_001", "aud_042", "abc123"):
        assert text in result.stdout


def test_verify_sends_from_id(router):
    route = router.get(VERIFY_URL).respond(200, json=envelope(verify_json(anchor_id="aud_010")))

    result = invoke(["audit", "verify", "--from-id", "aud_010"])

    assert result.exit_code == 0, result.output
    assert query_of(route) == {"from_id": "aud_010"}
    assert "aud_010" in result.stdout


@pytest.mark.parametrize("value", ["", "  ", f"{ESC}[0m"])
def test_verify_empty_from_id_is_a_usage_error(router, value):
    route = router.get(VERIFY_URL).respond(200, json=envelope(verify_json()))

    result = invoke(["audit", "verify", "--from-id", value])

    assert result.exit_code == EXIT_USAGE
    assert route.call_count == 0


def broken_chain():
    finding = {"kind": "hash_mismatch", "event_id": "aud_007", "detail": "stored hash differs"}
    return verify_json(ok=False, findings=[finding])


def test_verify_broken_chain_exits_three_and_lists_the_findings(router):
    router.get(VERIFY_URL).respond(200, json=envelope(broken_chain()))

    result = invoke(["audit", "verify"])

    assert result.exit_code == EXIT_BROKEN_CHAIN
    assert "hash_mismatch" in result.stdout
    assert "aud_007" in result.stdout


def test_verify_json_prints_the_result_object_and_still_exits_three(router):
    router.get(VERIFY_URL).respond(200, json=envelope(broken_chain()))

    result = invoke(["audit", "verify"], as_json=True)

    assert result.exit_code == EXIT_BROKEN_CHAIN
    document = json.loads(result.stdout)
    assert document["ok"] is False
    assert document["checked"] == 42
    assert document["findings"] == [
        {"kind": "hash_mismatch", "event_id": "aud_007", "detail": "stored hash differs"}
    ]
    assert document["findings_truncated"] is False


def test_verify_json_intact_chain_exits_zero(router):
    router.get(VERIFY_URL).respond(200, json=envelope(verify_json()))

    result = invoke(["audit", "verify"], as_json=True)

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["ok"] is True
    assert document["first_id"] == "aud_001"
    assert document["last_hash"] == "abc123"


def test_verify_empty_org_exits_zero(router):
    empty = verify_json(checked=0, first_id=None, last_id=None, last_hash=None)
    router.get(VERIFY_URL).respond(200, json=envelope(empty))

    result = invoke(["audit", "verify"])

    assert result.exit_code == 0, result.output


def test_verify_sanitises_server_strings(router):
    finding = {"kind": "link_broken", "event_id": "aud_1", "detail": f"bad{ESC}[31m link"}
    router.get(VERIFY_URL).respond(200, json=envelope(verify_json(ok=False, findings=[finding])))

    result = invoke(["audit", "verify"])

    assert result.exit_code == EXIT_BROKEN_CHAIN
    assert ESC not in result.stdout


# --- export --------------------------------------------------------------------------------

EVENT_LINES = '{"id":"aud_001","action":"sandbox.create"}\n{"id":"aud_002","action":"key.revoke"}\n'
SUMMARY_LINE = '{"type":"export_summary","row_count":2}\n'
NDJSON = EVENT_LINES + SUMMARY_LINE


def test_export_to_stdout_writes_the_body_exactly(router):
    route = router.get(EXPORT_URL).respond(200, text=NDJSON)

    result = invoke(["audit", "export"])

    assert result.exit_code == 0, result.output
    assert result.stdout == NDJSON
    assert query_of(route) == {}


def test_export_maps_the_filters(router):
    route = router.get(EXPORT_URL).respond(200, text=NDJSON)

    result = invoke(
        [
            "audit", "export", "--from", "2026-11-01", "--to", "2026-11-02T00:00:00Z",
            "--request-id", "req_5", "--outcome", "error",
        ]
    )  # fmt: skip

    assert result.exit_code == 0, result.output
    assert query_of(route) == {
        "from": "2026-11-01T00:00:00+00:00",
        "to": "2026-11-02T00:00:00+00:00",
        "request_id": "req_5",
        "outcome": "error",
    }


@pytest.mark.parametrize("option", ["--from", "--to"])
def test_export_invalid_date_is_a_usage_error(router, option):
    route = router.get(EXPORT_URL).respond(200, text=NDJSON)

    result = invoke(["audit", "export", option, "not-a-date"])

    assert result.exit_code == EXIT_USAGE
    assert route.call_count == 0


@pytest.mark.parametrize("option", ["--request-id", "--outcome"])
def test_export_empty_filter_is_a_usage_error(router, option):
    route = router.get(EXPORT_URL).respond(200, text=NDJSON)

    result = invoke(["audit", "export", option, " "])

    assert result.exit_code == EXIT_USAGE
    assert route.call_count == 0


def test_export_to_a_file_has_mode_600_and_the_exact_body(router, tmp_path):
    router.get(EXPORT_URL).respond(200, text=NDJSON)
    target = tmp_path / "audit.ndjson"

    result = invoke(["audit", "export", "--output", str(target)])

    assert result.exit_code == 0, result.output
    assert target.read_text() == NDJSON
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert NDJSON not in result.stdout


def test_export_file_mode_is_600_even_with_a_permissive_umask(router, tmp_path):
    router.get(EXPORT_URL).respond(200, text=NDJSON)
    target = tmp_path / "audit.ndjson"
    old = os.umask(0o000)
    try:
        result = invoke(["audit", "export", "--output", str(target)])
    finally:
        os.umask(old)

    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_export_refuses_to_overwrite_an_existing_file(router, tmp_path):
    router.get(EXPORT_URL).respond(200, text=NDJSON)
    target = tmp_path / "audit.ndjson"
    target.write_text("keep me")

    result = invoke(["audit", "export", "--output", str(target)])

    assert result.exit_code != 0
    assert target.read_text() == "keep me"
    assert "--force" in result.output


def test_export_force_overwrites_and_sets_mode_600(router, tmp_path):
    router.get(EXPORT_URL).respond(200, text=NDJSON)
    target = tmp_path / "audit.ndjson"
    target.write_text("old")
    target.chmod(0o644)

    result = invoke(["audit", "export", "--output", str(target), "--force"])

    assert result.exit_code == 0, result.output
    assert target.read_text() == NDJSON
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_export_into_a_missing_directory_fails_without_a_traceback(router, tmp_path):
    router.get(EXPORT_URL).respond(200, text=NDJSON)

    result = invoke(["audit", "export", "--output", str(tmp_path / "nope" / "a.ndjson")])

    assert result.exit_code == 1
    assert "Traceback" not in result.output
    assert "error:" in result.output


def test_export_server_error_leaves_no_file(router, tmp_path):
    router.get(EXPORT_URL).respond(403, json=FORBIDDEN)
    target = tmp_path / "audit.ndjson"

    result = invoke(["audit", "export", "--output", str(target)])

    assert result.exit_code == 1
    assert not target.exists()


def test_audit_group_without_a_command_prints_help():
    result = invoke(["audit"])

    assert "list" in result.output
    assert "verify" in result.output
    assert "export" in result.output


# --- review fixes: list --all streams --------------------------------------------------------


def paged_answer(pages):
    def answer(request):
        reply = pages[request.url.params.get("cursor")]
        if isinstance(reply, httpx.Response):
            return reply
        return httpx.Response(200, json=reply)

    return answer


def failing_second_page():
    return {
        None: envelope([event_json(1)], meta={"next_cursor": "cur_a"}),
        "cur_a": httpx.Response(403, json=FORBIDDEN),
    }


def test_list_all_text_prints_rows_of_a_page_before_the_next_page_fails(router):
    router.get(AUDIT_URL).mock(side_effect=paged_answer(failing_second_page()))

    result = invoke(["audit", "list", "--all"])

    assert result.exit_code == 1
    assert "sbx_001" in result.stdout
    assert "audit:read needed" in result.stderr


def test_list_all_text_prints_the_header_once_then_aligned_rows(router):
    pages = {
        None: envelope([event_json(1)], meta={"next_cursor": "cur_a"}),
        "cur_a": envelope([event_json(2, action="key.revoke")]),
    }
    router.get(AUDIT_URL).mock(side_effect=paged_answer(pages))

    result = invoke(["audit", "list", "--all"])

    assert result.exit_code == 0, result.output
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert lines[0].startswith("OCCURRED")
    assert sum(line.startswith("OCCURRED") for line in lines) == 1
    header, first, second = lines
    for column, cell in (("ACTION", "sandbox.create"), ("TARGET", "sbx_001")):
        assert first.index(cell) == header.index(column)
    assert second.index("key.revoke") == header.index("ACTION")
    assert second.index("req_002") == header.index("REQUEST ID")


def test_list_all_text_with_no_events_prints_only_the_header(router):
    router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--all"])

    assert result.exit_code == 0, result.output
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0].startswith("OCCURRED")


def test_list_all_text_sanitises_streamed_rows(router):
    router.get(AUDIT_URL).respond(
        200, json=envelope([event_json(1, action=f"evil{ESC}[31mred{ESC}]0;title\x07")])
    )

    result = invoke(["audit", "list", "--all"])

    assert result.exit_code == 0, result.output
    assert ESC not in result.stdout
    assert "\x07" not in result.stdout


def test_list_all_json_with_no_events_is_an_empty_list(router):
    router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--all"], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == []


def test_list_all_json_first_page_failure_is_one_error_document(router):
    router.get(AUDIT_URL).respond(403, json=FORBIDDEN)

    result = invoke(["audit", "list", "--all"], as_json=True)

    assert result.exit_code == 1
    assert "error" in json.loads(result.stdout)


def test_list_all_json_prints_one_document_when_a_later_page_fails(router):
    router.get(AUDIT_URL).mock(side_effect=paged_answer(failing_second_page()))

    result = invoke(["audit", "list", "--all"], as_json=True)

    assert result.exit_code == 1
    document = json.loads(result.stdout)  # one document, not a list followed by an error
    assert document["error"]["message"] == "audit:read needed"


def test_list_all_json_items_keep_the_event_payload_shape(router):
    router.get(AUDIT_URL).respond(200, json=envelope([event_json(1), event_json(2)]))

    document = json.loads(invoke(["audit", "list", "--all"], as_json=True).stdout)

    assert [item["id"] for item in document] == ["aud_001", "aud_002"]
    assert document[0]["occurred_at"] == "2026-11-01T10:30:00+00:00"
    assert document[0]["details"] == {}


# --- review fixes: export streams the body ---------------------------------------------------


class BrokenStream(httpx.SyncByteStream):
    """Sends ``first`` and then loses the connection."""

    def __init__(self, first: bytes):
        self.first = first

    def __iter__(self):
        yield self.first
        raise httpx.ReadError("connection lost")


class ChunkStream(httpx.SyncByteStream):
    def __init__(self, data: bytes, size: int):
        self.data = data
        self.size = size

    def __iter__(self):
        for start in range(0, len(self.data), self.size):
            yield self.data[start : start + self.size]


def chunked(body: str, size: int) -> ChunkStream:
    return ChunkStream(body.encode("utf-8"), size)


def test_export_to_stdout_writes_lines_as_they_arrive(router):
    first = NDJSON.splitlines(keepends=True)[0]
    router.get(EXPORT_URL).mock(
        return_value=httpx.Response(200, stream=BrokenStream(first.encode()))
    )

    result = invoke(["audit", "export"])

    assert result.exit_code == 1
    assert result.stdout.startswith(first)
    assert "Traceback" not in result.output


def test_export_to_a_file_failing_mid_stream_leaves_no_partial_file(router, tmp_path):
    router.get(EXPORT_URL).mock(
        return_value=httpx.Response(200, stream=BrokenStream(NDJSON.encode()[:20]))
    )
    target = tmp_path / "audit.ndjson"

    result = invoke(["audit", "export", "--output", str(target)])

    assert result.exit_code == 1
    assert not target.exists()
    assert "error:" in result.output


@pytest.mark.parametrize("size", [1, 7, 4096])
def test_export_to_a_file_reassembles_chunks_exactly(router, tmp_path, size):
    body = EVENT_LINES + '{"type":"export_summary","note":"café"}'  # no trailing newline
    router.get(EXPORT_URL).mock(return_value=httpx.Response(200, stream=chunked(body, size)))
    target = tmp_path / "audit.ndjson"

    result = invoke(["audit", "export", "--output", str(target)], as_json=True)

    assert result.exit_code == 0, result.output
    assert target.read_bytes() == body.encode("utf-8")
    assert json.loads(result.stdout)["bytes"] == len(body.encode("utf-8"))


def test_export_uses_the_line_iterator_of_the_sdk(router, monkeypatch):
    from sandfort_sdk.audit import Audit

    seen = []

    def lines(self, **filters):
        seen.append(filters)
        yield "a\n"
        yield SUMMARY_LINE

    def whole_body(self, **filters):
        raise AssertionError("the CLI must not read the whole export body")

    monkeypatch.setattr(Audit, "export_lines", lines)
    monkeypatch.setattr(Audit, "export", whole_body)

    result = invoke(["audit", "export", "--outcome", "denied"])

    assert result.exit_code == 0, result.output
    assert result.stdout == "a\n" + SUMMARY_LINE
    assert seen[0]["outcome"] == "denied"


# --- review fixes: the SDK line iterator -----------------------------------------------------


def sdk_client():
    from sandfort_sdk import Client

    return Client(base_url=BASE, api_key=PROFILE_KEY)


@pytest.mark.parametrize("size", [1, 5, 4096])
def test_sdk_export_lines_yields_each_line_with_its_newline(router, size):
    body = EVENT_LINES + '{"id":"aud_003"}'
    router.get(EXPORT_URL).mock(return_value=httpx.Response(200, stream=chunked(body, size)))

    with sdk_client() as client:
        lines = list(client.audit.export_lines())

    assert lines == [
        '{"id":"aud_001","action":"sandbox.create"}\n',
        '{"id":"aud_002","action":"key.revoke"}\n',
        '{"id":"aud_003"}',
    ]


def test_sdk_export_still_returns_the_whole_text(router):
    route = router.get(EXPORT_URL).mock(return_value=httpx.Response(200, stream=chunked(NDJSON, 3)))

    with sdk_client() as client:
        assert client.audit.export(outcome="denied") == NDJSON

    assert query_of(route) == {"outcome": "denied"}


def test_sdk_export_lines_validates_filters_before_iteration(router):
    route = router.get(EXPORT_URL).respond(200, text=NDJSON)

    with sdk_client() as client, pytest.raises(ValueError):
        client.audit.export_lines(outcome=" ")

    assert route.call_count == 0


def test_sdk_export_lines_turns_a_lost_connection_into_a_transport_error(router):
    from sandfort_sdk import TransportError

    router.get(EXPORT_URL).mock(
        return_value=httpx.Response(200, stream=BrokenStream(b'{"id":"aud_001"}\n'))
    )

    with sdk_client() as client:
        lines = client.audit.export_lines()
        assert next(lines) == '{"id":"aud_001"}\n'
        with pytest.raises(TransportError):
            next(lines)


def test_sdk_export_lines_empty_body_yields_nothing(router):
    router.get(EXPORT_URL).respond(200, text="")

    with sdk_client() as client:
        assert list(client.audit.export_lines()) == []


# --- third review: export file handling ------------------------------------------------------

EXIT_FAILURE = 1
SIGNAL_EXIT_BASE = 128
HANDLED_SIGNALS = (signal.SIGTERM, signal.SIGINT)
JOIN_SECONDS = 10

needs_non_root = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores directory permissions"
)


@pytest.fixture
def out_dir(tmp_path):
    directory = tmp_path / "out"
    directory.mkdir()
    yield directory
    directory.chmod(0o700)  # an unwritable directory is restored so tmp_path can be removed


def temporaries(directory):
    return [path for path in directory.iterdir() if path.name.endswith(".tmp")]


def scripted_export(monkeypatch, *steps):
    """``Audit.export_lines`` yields each step: a string, or a callable run at that point."""
    from sandfort_sdk.audit import Audit

    def lines(self, **filters):
        for step in steps:
            if callable(step):
                step()
            else:
                yield step

    monkeypatch.setattr(Audit, "export_lines", lines)


def test_export_through_a_symlink_updates_the_target_and_keeps_the_link(router, out_dir):
    router.get(EXPORT_URL).respond(200, text=NDJSON)
    real = out_dir / "real.ndjson"
    real.write_text("old")
    real.chmod(0o644)
    link = out_dir / "link.ndjson"
    link.symlink_to(real)

    result = invoke(["audit", "export", "--output", str(link), "--force"])

    assert result.exit_code == 0, result.output
    assert link.is_symlink()
    assert os.readlink(link) == str(real)
    assert real.read_text() == NDJSON
    assert stat.S_IMODE(real.stat().st_mode) == 0o600
    assert temporaries(out_dir) == []


def test_export_through_a_symlink_without_force_refuses_an_existing_target(router, out_dir):
    route = router.get(EXPORT_URL).respond(200, text=NDJSON)
    real = out_dir / "real.ndjson"
    real.write_text("keep me")
    link = out_dir / "link.ndjson"
    link.symlink_to(real)

    result = invoke(["audit", "export", "--output", str(link)])

    assert result.exit_code == EXIT_FAILURE
    assert route.call_count == 0
    assert real.read_text() == "keep me"
    assert link.is_symlink()


def test_export_through_a_dangling_symlink_creates_the_target(router, out_dir):
    router.get(EXPORT_URL).respond(200, text=NDJSON)
    real = out_dir / "new.ndjson"
    link = out_dir / "link.ndjson"
    link.symlink_to(real)

    result = invoke(["audit", "export", "--output", str(link)])

    assert result.exit_code == 0, result.output
    assert link.is_symlink()
    assert real.read_text() == NDJSON


@needs_non_root
def test_export_through_a_symlink_writes_the_temporary_file_next_to_the_target(
    router, out_dir, tmp_path
):
    router.get(EXPORT_URL).respond(200, text=NDJSON)
    store = tmp_path / "store"
    store.mkdir()
    real = store / "real.ndjson"
    real.write_text("old")
    link = out_dir / "link.ndjson"
    link.symlink_to(real)
    out_dir.chmod(0o500)  # the link's directory cannot hold a temporary file

    result = invoke(["audit", "export", "--output", str(link), "--force"])

    assert result.exit_code == 0, result.output
    assert real.read_text() == NDJSON
    assert link.is_symlink()
    assert temporaries(store) == []


def test_export_to_the_null_device_writes_directly(router):
    router.get(EXPORT_URL).respond(200, text=NDJSON)

    result = invoke(["audit", "export", "--output", os.devnull], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["bytes"] == len(NDJSON.encode("utf-8"))
    assert stat.S_ISCHR(os.stat(os.devnull).st_mode)


def test_export_to_a_fifo_writes_directly_without_a_temporary_file(router, out_dir):
    router.get(EXPORT_URL).respond(200, text=NDJSON)
    fifo = out_dir / "pipe"
    os.mkfifo(fifo)
    received = []

    def read():
        with open(fifo, encoding="utf-8") as handle:
            received.append(handle.read())

    reader = threading.Thread(target=read, daemon=True)
    reader.start()

    result = invoke(["audit", "export", "--output", str(fifo)])
    reader.join(timeout=JOIN_SECONDS)

    assert result.exit_code == 0, result.output
    assert received == [NDJSON]
    assert stat.S_ISFIFO(os.stat(fifo).st_mode)
    assert temporaries(out_dir) == []


def test_export_to_a_directory_is_an_error_before_any_request(router, out_dir):
    route = router.get(EXPORT_URL).respond(200, text=NDJSON)

    result = invoke(["audit", "export", "--output", str(out_dir), "--force"])

    assert result.exit_code == EXIT_FAILURE
    assert route.call_count == 0
    assert "directory" in result.output


@needs_non_root
def test_export_into_an_unwritable_directory_names_the_directory(router, out_dir):
    router.get(EXPORT_URL).respond(200, text=NDJSON)
    target = out_dir / "audit.ndjson"
    out_dir.chmod(0o500)

    result = invoke(["audit", "export", "--output", str(target)])

    assert result.exit_code == EXIT_FAILURE
    assert "Traceback" not in result.output
    assert str(out_dir) in result.stderr
    assert "temporary file" in result.stderr
    out_dir.chmod(0o700)
    assert list(out_dir.iterdir()) == []


def test_export_refuses_a_file_that_appears_during_the_stream(monkeypatch, out_dir):
    target = out_dir / "audit.ndjson"
    scripted_export(monkeypatch, "a\n", lambda: target.write_text("intruder"), "b\n")

    result = invoke(["audit", "export", "--output", str(target)])

    assert result.exit_code == EXIT_FAILURE
    assert target.read_text() == "intruder"
    assert "created during the export" in result.stderr
    assert "--force" in result.stderr
    assert temporaries(out_dir) == []


def test_export_with_force_replaces_a_file_that_appears_during_the_stream(monkeypatch, out_dir):
    target = out_dir / "audit.ndjson"
    scripted_export(monkeypatch, "a\n", lambda: target.write_text("intruder"), SUMMARY_LINE)

    result = invoke(["audit", "export", "--output", str(target), "--force"])

    assert result.exit_code == 0, result.output
    assert target.read_text() == "a\n" + SUMMARY_LINE


@pytest.mark.parametrize("signum", HANDLED_SIGNALS)
def test_export_signal_removes_the_temporary_file(monkeypatch, out_dir, signum):
    target = out_dir / "audit.ndjson"
    before = signal.getsignal(signum)
    seen = []

    def deliver():
        seen.append(len(temporaries(out_dir)))
        handler = signal.getsignal(signum)
        assert callable(handler)
        assert handler is not before
        handler(signum, None)

    scripted_export(monkeypatch, "a\n", deliver, "b\n")

    result = invoke(["audit", "export", "--output", str(target)])

    assert seen == [1]  # the temporary file existed when the signal arrived
    assert result.exit_code == SIGNAL_EXIT_BASE + signum
    assert not target.exists()
    assert temporaries(out_dir) == []
    assert signal.getsignal(signum) is before


def test_export_restores_the_signal_handlers_after_success(router, out_dir):
    router.get(EXPORT_URL).respond(200, text=NDJSON)
    before = {signum: signal.getsignal(signum) for signum in HANDLED_SIGNALS}

    result = invoke(["audit", "export", "--output", str(out_dir / "audit.ndjson")])

    assert result.exit_code == 0, result.output
    assert {signum: signal.getsignal(signum) for signum in HANDLED_SIGNALS} == before


@pytest.mark.parametrize("signum", HANDLED_SIGNALS)
def test_signal_handler_itself_removes_the_temporary_file_and_exits(out_dir, signum):
    import typer
    from sandfort_cli.atomic_write import SignalCleanup

    temporary = out_dir / ".audit.ndjson.x.tmp"
    temporary.write_text("partial")

    with SignalCleanup() as cleanup, pytest.raises(typer.Exit) as raised:
        cleanup.temporary = temporary
        signal.getsignal(signum)(signum, None)

    assert raised.value.exit_code == SIGNAL_EXIT_BASE + signum
    assert not temporary.exists()


def test_signal_cleanup_off_the_main_thread_changes_no_handler():
    from sandfort_cli.atomic_write import SignalCleanup

    before = signal.getsignal(signal.SIGTERM)
    seen = []

    def run():
        with SignalCleanup():
            seen.append(signal.getsignal(signal.SIGTERM))

    worker = threading.Thread(target=run)
    worker.start()
    worker.join(timeout=JOIN_SECONDS)

    assert seen == [before]


def test_export_file_has_mode_600_with_force_over_a_wide_file(router, out_dir):
    router.get(EXPORT_URL).respond(200, text=NDJSON)
    target = out_dir / "audit.ndjson"
    target.write_text("old")
    target.chmod(0o666)

    result = invoke(["audit", "export", "--output", str(target), "--force"])

    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


@pytest.mark.parametrize("force", [False, True])
def test_export_leaves_no_second_link(router, monkeypatch, out_dir, force):
    router.get(EXPORT_URL).respond(200, text=NDJSON)
    target = out_dir / "audit.ndjson"
    if force:
        target.write_text("old")

    def no_link(*args, **kwargs):
        raise AssertionError("publishing must rename, not hard link")

    monkeypatch.setattr(os, "link", no_link)

    result = invoke(["audit", "export", "--output", str(target)] + (["--force"] if force else []))

    assert result.exit_code == 0, result.output
    assert target.stat().st_nlink == 1
    assert [path.name for path in out_dir.iterdir()] == ["audit.ndjson"]


def test_export_mode_change_failure_closes_the_descriptor(router, monkeypatch, out_dir):
    router.get(EXPORT_URL).respond(200, text=NDJSON)
    made = []
    real_mkstemp = tempfile.mkstemp

    def recording_mkstemp(*args, **kwargs):
        descriptor, name = real_mkstemp(*args, **kwargs)
        made.append(descriptor)
        return descriptor, name

    def failing_fchmod(descriptor, mode):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(tempfile, "mkstemp", recording_mkstemp)
    monkeypatch.setattr(os, "fchmod", failing_fchmod)

    result = invoke(["audit", "export", "--output", str(out_dir / "audit.ndjson")])

    assert result.exit_code == EXIT_FAILURE
    assert "Traceback" not in result.output
    assert len(made) == 1
    with pytest.raises(OSError):
        os.fstat(made[0])
    assert list(out_dir.iterdir()) == []


# --- r60: verify-head and the export note ----------------------------------------------------

STATUS_URL = "/v1/status"
EXIT_SIGNATURE = 3
HEAD_FIELDS = {"ok", "row_id", "entry_hash", "public_key", "reason", "fingerprint", "signed_at"}
# verify-head checks the rows too (round 61), so its json also carries the file checks
FILE_FIELDS = HEAD_FIELDS | {
    "rows_checked", "first_break", "unchained", "content_bound", "filtered",
}  # fmt: skip
HEAD_ROW = "aud_042"
HEAD_HASH = "ab" * 32
SIGNED_AT = "2026-11-11T04:00:00+00:00"
FINGERPRINT_CHARS = 16


def raw_public_key(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def public_text(private_key):
    return base64.urlsafe_b64encode(raw_public_key(private_key)).decode()


def fingerprint_of(private_key):
    return hashlib.sha256(raw_public_key(private_key)).hexdigest()[:FINGERPRINT_CHARS]


def compact(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def head_line(private_key=None, dated=True, **changes):
    """An ``audit_head`` trailer, signed by ``private_key`` when given (with a ``signed_at``
    unless ``dated`` is false, a legacy head); ``changes`` apply after signing (so they tamper
    with a signed line)."""
    record = {"type": "audit_head", "org_id": "org_1", "row_id": HEAD_ROW, "hash": HEAD_HASH,
              "hmac": "f" * 64}  # fmt: skip
    if private_key is not None:
        record["alg"] = "ed25519"
        record["public_key"] = public_text(private_key)
        if dated:
            record["signed_at"] = SIGNED_AT
        body = {name: value for name, value in record.items() if name != "hmac"}
        signature = private_key.sign(compact(body).encode())
        record["signature"] = base64.urlsafe_b64encode(signature).decode()
    return compact({**record, **changes})


def status_body(public_key):
    return envelope({"status": "ok", "version": "0.1.0", "audit_public_key": public_key})


@pytest.fixture
def signer():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def export_file(tmp_path):
    def write(trailer):
        # the one row is the row the heads below name, so the file checks of round 61 pass
        row = compact({
            "id": HEAD_ROW, "org_id": "org_1", "action": "sandbox.create",
            "occurred_at": SIGNED_AT, "prev_hash": None, "hash": HEAD_HASH,
        })  # fmt: skip
        path = tmp_path / "audit.ndjson"
        path.write_text(row + "\n" + trailer + "\n")
        return path

    return write


def test_verify_head_with_a_matching_public_key_exits_0(router, signer, export_file):
    status = router.get(STATUS_URL).respond(200, json=status_body(None))
    path = export_file(head_line(signer))

    result = invoke(["audit", "verify-head", str(path), "--public-key", public_text(signer)])

    assert result.exit_code == 0, result.output
    assert "true" in result.stdout
    assert fingerprint_of(signer) in result.stdout
    assert not status.called


def test_verify_head_takes_the_key_from_the_server_status(router, signer, export_file):
    status = router.get(STATUS_URL).respond(200, json=status_body(public_text(signer)))
    path = export_file(head_line(signer))

    result = invoke(["audit", "verify-head", str(path)])

    assert result.exit_code == 0, result.output
    assert status.called


def test_verify_head_json_carries_the_result_fields(router, signer, export_file):
    path = export_file(head_line(signer))

    result = invoke(
        ["audit", "verify-head", str(path), "--public-key", public_text(signer)], as_json=True
    )

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert set(document) == FILE_FIELDS
    assert document["ok"] is True
    assert document["row_id"] == HEAD_ROW
    assert document["entry_hash"] == HEAD_HASH
    assert document["public_key"] == public_text(signer)
    assert document["reason"] is None
    assert document["fingerprint"] == fingerprint_of(signer)


def test_verify_head_with_another_key_exits_3_and_shows_the_reason(router, signer, export_file):
    path = export_file(head_line(signer))
    other = public_text(Ed25519PrivateKey.generate())

    result = invoke(["audit", "verify-head", str(path), "--public-key", other])

    assert result.exit_code == EXIT_SIGNATURE, result.output
    assert "key_mismatch" in result.stderr
    assert "different public key than the one you trust" in result.stderr
    assert "false" in result.stdout


def test_verify_head_with_another_key_has_reason_key_mismatch_in_json(router, signer, export_file):
    path = export_file(head_line(signer))
    other = public_text(Ed25519PrivateKey.generate())

    result = invoke(["audit", "verify-head", str(path), "--public-key", other], as_json=True)

    assert result.exit_code == EXIT_SIGNATURE, result.output
    assert json.loads(result.stdout)["reason"] == "key_mismatch"


def test_verify_head_of_a_signed_head_without_signed_at_exits_3_as_undated(
    router, signer, export_file
):
    path = export_file(head_line(signer, dated=False))

    result = invoke(["audit", "verify-head", str(path), "--public-key", public_text(signer)])

    assert result.exit_code == EXIT_SIGNATURE, result.output
    assert "undated" in result.stderr
    assert "signed_at" in result.stderr
    assert "false" in result.stdout


def test_verify_head_json_of_an_undated_head_has_reason_undated(router, signer, export_file):
    path = export_file(head_line(signer, dated=False))

    result = invoke(
        ["audit", "verify-head", str(path), "--public-key", public_text(signer)], as_json=True
    )

    assert result.exit_code == EXIT_SIGNATURE, result.output
    document = json.loads(result.stdout)
    assert document["ok"] is False and document["reason"] == "undated"
    assert document["row_id"] == HEAD_ROW


@pytest.mark.parametrize("reason", ["unsigned", "signature", "key_mismatch", "undated"])
def test_every_sdk_reason_has_an_explanation(reason):
    from sandfort_cli.audit import REASONS
    from sandfort_sdk import audit_head

    assert reason in {
        audit_head.REASON_UNSIGNED,
        audit_head.REASON_SIGNATURE,
        audit_head.REASON_KEY_MISMATCH,
        audit_head.REASON_UNDATED,
    }
    assert REASONS[reason].strip()


def test_verify_head_json_failure_has_ok_false_and_the_reason(router, signer, export_file):
    path = export_file(head_line(signer, row_id="aud_999"))

    result = invoke(
        ["audit", "verify-head", str(path), "--public-key", public_text(signer)], as_json=True
    )

    assert result.exit_code == EXIT_SIGNATURE, result.output
    document = json.loads(result.stdout)
    assert set(document) == FILE_FIELDS
    assert document["ok"] is False
    assert document["reason"] == "signature"
    assert document["row_id"] == "aud_999"


def test_verify_head_with_a_server_key_that_differs_exits_3(router, signer, export_file):
    router.get(STATUS_URL).respond(200, json=status_body(public_text(Ed25519PrivateKey.generate())))
    path = export_file(head_line(signer))

    result = invoke(["audit", "verify-head", str(path)])

    assert result.exit_code == EXIT_SIGNATURE, result.output


def test_verify_head_of_an_unsigned_trailer_exits_3_with_reason_unsigned(
    router, signer, export_file
):
    path = export_file(head_line())

    result = invoke(
        ["audit", "verify-head", str(path), "--public-key", public_text(signer)], as_json=True
    )

    assert result.exit_code == EXIT_SIGNATURE, result.output
    assert json.loads(result.stdout)["reason"] == "unsigned"


def test_verify_head_of_a_missing_file_is_a_usage_error(router, signer, tmp_path):
    missing = tmp_path / "nope.ndjson"

    result = invoke(["audit", "verify-head", str(missing), "--public-key", public_text(signer)])

    assert result.exit_code == EXIT_USAGE, result.output
    assert "Traceback" not in result.output


def test_verify_head_without_a_trailer_is_a_usage_error(router, signer, export_file):
    path = export_file(compact({"type": "export_summary", "rows": 2, "filters": ["outcome"]}))

    result = invoke(["audit", "verify-head", str(path), "--public-key", public_text(signer)])

    assert result.exit_code == EXIT_USAGE, result.output
    assert "audit_head" in result.output


def test_verify_head_of_an_empty_file_is_a_usage_error(router, signer, tmp_path):
    path = tmp_path / "empty.ndjson"
    path.write_text("")

    result = invoke(["audit", "verify-head", str(path), "--public-key", public_text(signer)])

    assert result.exit_code == EXIT_USAGE, result.output


def test_verify_head_without_any_key_is_a_usage_error_and_ignores_the_line_key(
    router, signer, export_file
):
    status = router.get(STATUS_URL).respond(200, json=status_body(None))
    path = export_file(head_line(signer))

    result = invoke(["audit", "verify-head", str(path)])

    assert result.exit_code == EXIT_USAGE, result.output
    assert status.called
    assert "--public-key" in result.output


def test_verify_head_malformed_public_key_is_a_usage_error(router, signer, export_file):
    path = export_file(head_line(signer))

    result = invoke(["audit", "verify-head", str(path), "--public-key", "not-a-key"])

    assert result.exit_code == EXIT_USAGE, result.output
    assert "Traceback" not in result.output


def test_verify_head_usage_error_with_json_prints_one_error_document(router, signer, tmp_path):
    missing = tmp_path / "nope.ndjson"

    result = invoke(
        ["audit", "verify-head", str(missing), "--public-key", public_text(signer)],
        as_json=True,
    )

    assert result.exit_code == EXIT_USAGE, result.output
    assert "error" in json.loads(result.stdout)


def test_export_notes_the_signing_key_fingerprint_once(router, signer):
    router.get(EXPORT_URL).respond(200, text=NDJSON + head_line(signer) + "\n")

    result = invoke(["audit", "export"])

    assert result.exit_code == 0, result.output
    assert result.stdout == NDJSON + head_line(signer) + "\n"
    assert result.stderr.count(fingerprint_of(signer)) == 1
    assert len([line for line in result.stderr.splitlines() if "signed" in line]) == 1


def test_export_to_a_file_notes_the_fingerprint(router, signer, tmp_path):
    router.get(EXPORT_URL).respond(200, text=NDJSON + head_line(signer) + "\n")
    target = tmp_path / "audit.ndjson"

    result = invoke(["audit", "export", "--output", str(target)])

    assert result.exit_code == 0, result.output
    assert fingerprint_of(signer) in result.stderr
    assert target.read_text().endswith(head_line(signer) + "\n")


def test_export_with_an_unsigned_trailer_prints_no_note(router):
    router.get(EXPORT_URL).respond(200, text=NDJSON + head_line() + "\n")

    result = invoke(["audit", "export"])

    assert result.exit_code == 0, result.output
    assert "signed" not in result.stderr
    assert "fingerprint" not in result.stderr
