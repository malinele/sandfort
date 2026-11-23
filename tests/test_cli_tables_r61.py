"""CLI round 61: tables on narrow terminals and the CAPACITY hint.

1. Short status and number columns never shrink below their header or longest value; long
   free-text columns absorb the shrinking (ellipsis); when that is not enough the lowest-priority
   free-text column is dropped. Applied by ``print_table`` and ``render_sandboxes``.
2. A CAPACITY error prints the line "the host is full; retry in N s" when the server sent a
   Retry-After header (else a generic line), in text mode and as ``error.hint`` in json.
3. The default free columns never include a status, number or date column; a cut free cell
   never splits a grapheme cluster (a flag); piped output is never cut.
"""

import json
import re
import sys
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config, error_hints, members, output, table_layout, webhooks  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import ApiError, Member, WebhookDelivery  # noqa: E402
from sandfort_sdk._requests import parse_retry_after, parse_retry_after_header  # noqa: E402
from sandfort_sdk._transport import parse_response  # noqa: E402
from sandfort_sdk.exceptions import error_for  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
WID = "whk_01HZZZZZZZZZZZZZZZZZZZZZZZ"
RUNNER = CliRunner()
ANSI_SGR_RE = re.compile(r"\x1b\[[0-9;]*m")
CELL_SPLIT_RE = re.compile(r"[│┃]")
ELLIPSIS = "…"
WIDTHS = (80, 100, 140)
# Rich draws a table as: one border per column plus the closing one, and one space on each
# side of every cell.
BORDER_AND_PADDING_PER_COLUMN = 3
CLOSING_BORDER = 1
COLOR_ENV_VARS = ("FORCE_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE")

SANDBOX_COLUMNS = (
    "ID", "NAME", "STATE", "ISOLATION", "CPU (m)", "MEM (MiB)", "DISK (GiB)", "CREATED",
    "LABELS", "REASON",
)  # fmt: skip
SANDBOX_FREE = ("NAME", "REASON", "LABELS")
SANDBOX_FIXED = tuple(c for c in SANDBOX_COLUMNS if c not in SANDBOX_FREE)
LONG_NAME = "agent-workspace-" + "n" * 40
SANDBOX_ROW = (
    SID, LONG_NAME, "started", "gvisor", "1000", "512", "3", "2026-11-11 10:41:59",
    "team=platform,env=staging,tier=gold", "OOM_KILLED: the container exceeded its memory",
)  # fmt: skip

LONG_URL = "https://hooks.example.test/" + "path/" * 12 + "receive"
ENDPOINT_ROW = (
    WID, LONG_URL, "true", "sandbox.started,sandbox.stopped", "3", "2026-11-11 10:41:59",
)  # fmt: skip
DELIVERY_ROW = (
    WID, "2026-11-11 10:41:59", "sandbox.started", "retrying", "4", "503",
    "connection refused by the receiving host after a long wait", "2026-11-11 10:46:59",
)  # fmt: skip


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def sandbox_json(name: str) -> dict[str, Any]:
    return {
        "id": SID,
        "name": name,
        "state": "destroying",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
        "labels": {"team": "platform", "environment": "staging", "owner": "agents"},
    }


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("TERMINAL_WIDTH", "400")
    for name in COLOR_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def router() -> Iterator[Any]:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


def at_columns(monkeypatch: pytest.MonkeyPatch, columns: int) -> None:
    monkeypatch.setenv("COLUMNS", str(columns))
    monkeypatch.setenv("TERMINAL_WIDTH", str(columns))


def printed(text: str) -> list[str]:
    return [ANSI_SGR_RE.sub("", line) for line in text.splitlines()]


def cells_of(line: str) -> list[str]:
    return [cell.strip() for cell in CELL_SPLIT_RE.split(line.strip())[1:-1]]


def table_dict(lines: Sequence[str], header_marker: str, value_marker: str) -> dict[str, str]:
    """Header name -> cell of the data row, for the header line holding ``header_marker`` and
    the data line holding ``value_marker``."""
    header = next(line for line in lines if header_marker in line)
    row = next(line for line in lines if value_marker in line)
    return dict(zip(cells_of(header), cells_of(row), strict=True))


def fixed_need(columns: Sequence[str], row: Sequence[str], fixed: Sequence[str]) -> int:
    """The width of a table holding only the ``fixed`` columns."""
    cells = sum(max(len(c), len(v)) for c, v in zip(columns, row, strict=True) if c in fixed)
    return cells + BORDER_AND_PADDING_PER_COLUMN * len(fixed) + CLOSING_BORDER


# 1a. the planner ----------------------------------------------------------------------------


def test_everything_fits_when_the_width_is_enough() -> None:
    layout = table_layout.plan_layout(SANDBOX_COLUMNS, [SANDBOX_ROW], SANDBOX_FREE, 400)

    assert layout.kept == tuple(range(len(SANDBOX_COLUMNS)))
    assert layout.limits == {}


@pytest.mark.parametrize("width", WIDTHS)
def test_planner_never_limits_a_fixed_column(width: int) -> None:
    layout = table_layout.plan_layout(SANDBOX_COLUMNS, [SANDBOX_ROW], SANDBOX_FREE, width)

    for index, name in enumerate(SANDBOX_COLUMNS):
        if name in SANDBOX_FIXED:
            assert index in layout.kept
            assert index not in layout.limits


def test_planner_cuts_free_columns_before_dropping_any() -> None:
    need = fixed_need(SANDBOX_COLUMNS, SANDBOX_ROW, SANDBOX_FIXED)
    # Room for NAME and REASON at their minimum, none for LABELS as well.
    width = need + 2 * BORDER_AND_PADDING_PER_COLUMN + 2 * table_layout.MIN_FREE_WIDTH + 2

    layout = table_layout.plan_layout(SANDBOX_COLUMNS, [SANDBOX_ROW], SANDBOX_FREE, width)

    kept_names = [SANDBOX_COLUMNS[i] for i in layout.kept]
    assert "LABELS" not in kept_names
    assert "NAME" in kept_names and "REASON" in kept_names
    name_index = SANDBOX_COLUMNS.index("NAME")
    assert table_layout.MIN_FREE_WIDTH <= layout.limits[name_index] < len(LONG_NAME)


def test_planner_drops_the_lowest_priority_free_column_first() -> None:
    need = fixed_need(SANDBOX_COLUMNS, SANDBOX_ROW, SANDBOX_FIXED)
    one_free = need + BORDER_AND_PADDING_PER_COLUMN + table_layout.MIN_FREE_WIDTH

    layout = table_layout.plan_layout(SANDBOX_COLUMNS, [SANDBOX_ROW], SANDBOX_FREE, one_free)

    kept_free = [SANDBOX_COLUMNS[i] for i in layout.kept if SANDBOX_COLUMNS[i] in SANDBOX_FREE]
    assert kept_free == ["NAME"]


def test_planner_keeps_fixed_columns_whole_even_when_they_alone_overflow() -> None:
    need = fixed_need(SANDBOX_COLUMNS, SANDBOX_ROW, SANDBOX_FIXED)

    layout = table_layout.plan_layout(SANDBOX_COLUMNS, [SANDBOX_ROW], SANDBOX_FREE, need - 30)

    assert [SANDBOX_COLUMNS[i] for i in layout.kept] == list(SANDBOX_FIXED)
    assert layout.limits == {}
    assert layout.width == need


def test_default_free_column_is_the_last_one() -> None:
    assert table_layout.default_free_columns(("ID", "STATE", "NOTE")) == ("NOTE",)
    assert table_layout.default_free_columns(("FIELD", "VALUE")) == ("VALUE",)


def test_default_free_columns_are_the_known_text_headers_only() -> None:
    assert table_layout.default_free_columns(webhooks.ENDPOINT_COLUMNS) == ("URL", "EVENTS")
    assert table_layout.default_free_columns(webhooks.DELIVERY_COLUMNS) == ("LAST ERROR",)
    assert table_layout.default_free_columns(members.MEMBER_COLUMNS) == ("EMAIL", "NAME")


def test_the_last_column_is_free_only_when_no_header_is_a_text_header() -> None:
    assert table_layout.default_free_columns(("ID", "NAME", "CREATED")) == ("NAME",)
    assert table_layout.default_free_columns(("ID", "STATE", "DETAIL")) == ("DETAIL",)
    assert "EMAIL" in table_layout.FREE_TEXT_HEADERS


def test_an_unknown_free_column_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="NOPE"):
        table_layout.plan_layout(("ID", "NAME"), [("a", "b")], ("NOPE",), 80)


def test_a_table_without_rows_is_planned_from_its_headers() -> None:
    layout = table_layout.plan_layout(("ID", "STATE", "NAME"), [], ("NAME",), 20)

    assert 0 in layout.kept and 1 in layout.kept


# 1b. print_table ------------------------------------------------------------------------------


@pytest.mark.parametrize("width", WIDTHS)
def test_sandbox_like_table_keeps_status_and_number_columns_whole(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], width: int
) -> None:
    at_columns(monkeypatch, width)

    output.print_table("sandboxes", SANDBOX_COLUMNS, [SANDBOX_ROW], free=SANDBOX_FREE)

    lines = printed(capsys.readouterr().out)
    shown = table_dict(lines, "STATE", "started")
    for name, value in zip(SANDBOX_COLUMNS, SANDBOX_ROW, strict=True):
        if name in SANDBOX_FIXED:
            assert shown[name] == value, (width, name)
    need = fixed_need(SANDBOX_COLUMNS, SANDBOX_ROW, SANDBOX_FIXED)
    assert max(len(line) for line in lines) <= max(width, need)


def test_sandbox_like_table_at_140_cuts_free_text_and_drops_the_last_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    at_columns(monkeypatch, 140)

    output.print_table("sandboxes", SANDBOX_COLUMNS, [SANDBOX_ROW], free=SANDBOX_FREE)

    lines = printed(capsys.readouterr().out)
    shown = table_dict(lines, "STATE", "started")
    assert max(len(line) for line in lines) <= 140
    assert shown["NAME"].endswith(ELLIPSIS)
    assert LONG_NAME not in "\n".join(lines)
    assert "LABELS" not in shown


@pytest.mark.parametrize("width", [80, 100])
def test_sandbox_like_table_at_80_and_100_drops_every_free_column(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], width: int
) -> None:
    at_columns(monkeypatch, width)

    output.print_table("sandboxes", SANDBOX_COLUMNS, [SANDBOX_ROW], free=SANDBOX_FREE)

    shown = table_dict(printed(capsys.readouterr().out), "STATE", "started")
    assert set(shown) == set(SANDBOX_FIXED)


@pytest.mark.parametrize("width", WIDTHS)
def test_endpoint_table_keeps_number_and_status_columns_whole(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], width: int
) -> None:
    at_columns(monkeypatch, width)

    output.print_table("webhook endpoints", webhooks.ENDPOINT_COLUMNS, [ENDPOINT_ROW])

    lines = printed(capsys.readouterr().out)
    shown = table_dict(lines, "ENABLED", WID)
    assert shown["ID"] == WID
    assert shown["ENABLED"] == "true"
    assert shown["FAILURES"] == "3"
    free = set(table_layout.default_free_columns(webhooks.ENDPOINT_COLUMNS))
    fixed = [c for c in webhooks.ENDPOINT_COLUMNS if c not in free]
    need = fixed_need(webhooks.ENDPOINT_COLUMNS, ENDPOINT_ROW, fixed)
    assert max(len(line) for line in lines) <= max(width, need)


@pytest.mark.parametrize("width", WIDTHS)
def test_delivery_table_keeps_status_and_number_columns_whole(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], width: int
) -> None:
    at_columns(monkeypatch, width)

    output.print_table("webhook deliveries", webhooks.DELIVERY_COLUMNS, [DELIVERY_ROW])

    lines = printed(capsys.readouterr().out)
    shown = table_dict(lines, "ATTEMPTS", WID)
    assert shown["ID"] == WID
    assert shown["EVENT TYPE"] == "sandbox.started"
    assert shown["STATE"] == "retrying"
    assert shown["ATTEMPTS"] == "4"
    assert shown["LAST STATUS"] == "503"
    free = set(table_layout.default_free_columns(webhooks.DELIVERY_COLUMNS))
    fixed = [c for c in webhooks.DELIVERY_COLUMNS if c not in free]
    need = fixed_need(webhooks.DELIVERY_COLUMNS, DELIVERY_ROW, fixed)
    assert max(len(line) for line in lines) <= max(width, need)


def test_default_free_column_is_cut_with_an_ellipsis(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    at_columns(monkeypatch, 40)

    output.print_table("t", ("ID", "STATE", "NOTE"), [("a1", "started", "z" * 100)])

    lines = printed(capsys.readouterr().out)
    shown = table_dict(lines, "STATE", "started")
    assert shown["STATE"] == "started"
    assert shown["NOTE"].endswith(ELLIPSIS)
    assert max(len(line) for line in lines) <= 40


def test_a_marked_free_column_is_cut_and_the_last_column_stays_whole(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    at_columns(monkeypatch, 40)

    output.print_table(
        "t", ("NAME", "STATE", "CODE"), [("n" * 100, "started", "E42")], free=("NAME",)
    )

    shown = table_dict(printed(capsys.readouterr().out), "STATE", "started")
    assert shown["NAME"].endswith(ELLIPSIS)
    assert shown["STATE"] == "started"
    assert shown["CODE"] == "E42"


@pytest.mark.parametrize("width", WIDTHS)
def test_a_table_that_fits_is_printed_unchanged(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], width: int
) -> None:
    at_columns(monkeypatch, width)

    output.print_table("t", ("ID", "STATE", "NOTE"), [("a1", "started", "short note")])

    shown = table_dict(printed(capsys.readouterr().out), "STATE", "started")
    assert shown == {"ID": "a1", "STATE": "started", "NOTE": "short note"}


def test_piped_without_columns_nothing_is_cut(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("COLUMNS", raising=False)

    output.print_table("sandboxes", SANDBOX_COLUMNS, [SANDBOX_ROW], free=SANDBOX_FREE)

    shown = table_dict(printed(capsys.readouterr().out), "STATE", "started")
    assert dict(zip(SANDBOX_COLUMNS, SANDBOX_ROW, strict=True)) == shown


# 1c. sandbox list -----------------------------------------------------------------------------


@pytest.mark.parametrize("width", WIDTHS)
def test_sandbox_list_keeps_state_isolation_cpu_and_mem_whole(
    monkeypatch: pytest.MonkeyPatch, router: Any, width: int
) -> None:
    at_columns(monkeypatch, width)
    router.get("/v1/sandboxes").respond(200, json=envelope([sandbox_json(LONG_NAME)]))

    result = RUNNER.invoke(create_app(None), ["sandbox", "list"])

    assert result.exit_code == 0, result.output
    lines = printed(result.stdout)
    shown = table_dict(lines, "STATE", "destroying")
    assert shown["ID"] == SID
    assert shown["STATE"] == "destroying"
    assert shown["CPU (m)"] == "1000"
    assert shown["MEM (MiB)"] == "512"
    assert shown["DISK (GiB)"] == "3"
    assert "ISOLATION" in shown
    assert LONG_NAME not in result.stdout


def test_sandbox_list_json_is_not_laid_out(monkeypatch: pytest.MonkeyPatch, router: Any) -> None:
    at_columns(monkeypatch, 80)
    router.get("/v1/sandboxes").respond(200, json=envelope([sandbox_json(LONG_NAME)]))

    result = RUNNER.invoke(create_app(None), ["--json", "sandbox", "list"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)[0]["name"] == LONG_NAME


# 2. the CAPACITY hint -------------------------------------------------------------------------


def capacity(header_s: int | None = 7) -> ApiError:
    return error_for(
        "CAPACITY", "no room", status_code=503, retry_after_s=header_s or 1,
        retry_after_header_s=header_s,
    )  # fmt: skip


def test_capacity_error_names_the_retry_after_value() -> None:
    text = output.describe_error(capacity(7))

    assert text.splitlines()[0].startswith("CAPACITY: no room")
    assert text.splitlines()[-1] == "the host is full; retry in 7 s"
    assert error_hints.capacity_hint(capacity(7)) == "the host is full; retry in 7 s"


def test_capacity_error_without_a_retry_after_header_says_retry_later() -> None:
    plain = ApiError("no room", code="CAPACITY", status_code=503)
    parsed = capacity(None)

    for exc in (plain, parsed):
        text = output.describe_error(exc)
        assert text.splitlines()[-1] == "the host is full; retry later or ask the operator"
        assert text.count("the host is full") == 1
        assert "retry in" not in text


def test_the_sdk_default_of_one_second_is_not_shown_as_a_hint() -> None:
    exc = error_for("CAPACITY", "no room", status_code=503)

    assert exc.retry_after_s == 1  # the retry loop still gets a number
    assert exc.retry_after_header_s is None
    assert "retry in" not in error_hints.capacity_hint(exc)


@pytest.mark.parametrize("seconds", [3601, 86_400, 10**9])
def test_a_huge_retry_after_is_capped_in_the_hint(seconds: int) -> None:
    assert error_hints.capacity_hint(capacity(seconds)) == "the host is full; retry in over 60 min"


def test_an_hour_is_still_shown_in_seconds() -> None:
    assert error_hints.capacity_hint(capacity(3600)) == "the host is full; retry in 3600 s"


def test_capacity_hint_is_one_extra_line() -> None:
    assert len(output.describe_error(capacity()).splitlines()) == 2


def test_other_503_errors_have_no_capacity_hint() -> None:
    other = error_for("NODE_UNAVAILABLE", "node is down", status_code=503, retry_after_header_s=3)

    assert output.describe_error(other) == "NODE_UNAVAILABLE: node is down"
    assert error_hints.hint_for(other) is None


def test_the_json_error_carries_the_capacity_hint() -> None:
    payload = output.error_payload(capacity(7))

    assert payload["error"]["hint"] == "the host is full; retry in 7 s"
    generic = output.error_payload(capacity(None))
    assert generic["error"]["hint"] == "the host is full; retry later or ask the operator"


def test_an_explicit_json_hint_wins_over_the_capacity_hint() -> None:
    assert output.error_payload(capacity(7), "mine")["error"]["hint"] == "mine"


def test_other_json_errors_have_no_hint() -> None:
    assert "hint" not in output.error_payload(error_for("NOT_FOUND", "x", status_code=404))["error"]


def test_output_no_longer_holds_the_capacity_hint() -> None:
    assert not hasattr(output, "capacity_hint")
    assert not hasattr(output, "CAPACITY_HINT")


def sdk_reply(headers: dict[str, str]) -> ApiError:
    body = {"success": False, "error": {"code": "CAPACITY", "message": "no room"}}
    with pytest.raises(ApiError) as caught:
        parse_response(httpx.Response(503, json=body, headers=headers))
    return caught.value


def test_the_sdk_error_says_whether_retry_after_was_sent() -> None:
    absent = sdk_reply({})
    present = sdk_reply({"Retry-After": "12"})

    assert (absent.retry_after_s, absent.retry_after_header_s) == (1, None)
    assert (present.retry_after_s, present.retry_after_header_s) == (12, 12)


def test_retry_after_header_parsing() -> None:
    assert parse_retry_after_header(None) is None
    assert parse_retry_after_header("soon") is None
    assert parse_retry_after_header("9") == 9
    assert parse_retry_after_header("Mon, 01 Jan 1990 00:00:00 GMT") == 0
    assert parse_retry_after(None) == 1 and parse_retry_after("soon") == 1
    assert sdk_reply({"Retry-After": "soon"}).retry_after_header_s is None


def test_a_cli_run_prints_the_hint_in_text_and_json(router: Any) -> None:
    body = {"success": False, "error": {"code": "CAPACITY", "message": "no room"}}
    router.get("/v1/sandboxes").respond(503, json=body, headers={"Retry-After": "4"})

    text = RUNNER.invoke(create_app(None), ["sandbox", "list"])
    as_json = RUNNER.invoke(create_app(None), ["--json", "sandbox", "list"])

    assert text.stderr.strip().splitlines()[-1] == "the host is full; retry in 4 s"
    assert json.loads(as_json.stdout)["error"]["hint"] == "the host is full; retry in 4 s"


# 3. free columns, grapheme-safe cuts, piped output ---------------------------------------------

NOW = datetime(2026, 11, 11, 10, 41, 59, tzinfo=UTC)
FLAG = "\U0001f1fa\U0001f1f8"
REGIONAL_INDICATORS = range(0x1F1E6, 0x1F200)
SHOWN_WIDTHS = (60, 80, 100)


def member_rows() -> list[Member]:
    return [
        Member(
            user_id="usr_01HZZZZZZZZZZZZZZZZZZZZZZZ",
            email="a.very.long.address@subdomain.example-company.test",
            display_name="A Member With A Fairly Long Display Name",
            role="developer",
            created_at=NOW,
        )
    ]


def delivery_item() -> WebhookDelivery:
    return WebhookDelivery(
        id=WID, endpoint_id="whk_e1", event_id="evt_1", state="pending", attempts=4,
        event_type="sandbox.started", next_attempt_at=NOW, last_status=503,
        last_error="connection refused by the receiving host after a long wait",
        payload_sha256="ab" * 32, attempt_history=(), created_at=NOW, updated_at=NOW,
    )  # fmt: skip


@pytest.mark.parametrize("width", SHOWN_WIDTHS)
def test_members_table_keeps_user_id_and_role_whole(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], width: int
) -> None:
    at_columns(monkeypatch, width)

    members.render_members(output.AppState(), member_rows())

    lines = printed(capsys.readouterr().out)
    shown = table_dict(lines, "ROLE", "usr_")
    assert shown["USER ID"] == "usr_01HZZZZZZZZZZZZZZZZZZZZZZZ"
    assert shown["ROLE"] == "developer"
    assert max(len(line) for line in lines) <= max(width, 60)


def test_members_table_cuts_email_before_name_and_drops_name_first(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    at_columns(monkeypatch, 100)

    members.render_members(output.AppState(), member_rows())

    shown = table_dict(printed(capsys.readouterr().out), "ROLE", "usr_")
    assert set(shown) == {"USER ID", "EMAIL", "NAME", "ROLE"}
    assert shown["EMAIL"].endswith(ELLIPSIS) and shown["NAME"].endswith(ELLIPSIS)


@pytest.mark.parametrize("width", SHOWN_WIDTHS)
def test_delivery_table_keeps_next_attempt_and_every_fixed_column(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], width: int
) -> None:
    at_columns(monkeypatch, width)

    webhooks.render_deliveries(output.AppState(), [delivery_item()], None, every=True)

    shown = table_dict(printed(capsys.readouterr().out), "ATTEMPTS", WID)
    for name in webhooks.DELIVERY_COLUMNS:
        if name != "LAST ERROR":
            assert name in shown, (width, name)
    assert shown["NEXT ATTEMPT"] == "2026-11-11 10:41:59"
    assert shown["CREATED"] == "2026-11-11 10:41:59"


@pytest.mark.parametrize("width", SHOWN_WIDTHS)
def test_endpoint_table_keeps_created_whole(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], width: int
) -> None:
    at_columns(monkeypatch, width)

    output.print_table("webhook endpoints", webhooks.ENDPOINT_COLUMNS, [ENDPOINT_ROW])

    shown = table_dict(printed(capsys.readouterr().out), "ENABLED", WID)
    assert shown["CREATED"] == "2026-11-11 10:41:59"


def lone_regional_indicators(text: str) -> bool:
    """True when ``text`` holds a regional indicator that is not half of a pair."""
    run = 0
    for char in text + " ":
        if ord(char) in REGIONAL_INDICATORS:
            run += 1
        else:
            if run % 2:
                return True
            run = 0
    return False


def test_a_cut_cell_never_splits_a_flag(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    at_columns(monkeypatch, 28)

    output.print_table("t", ("ID", "NOTE"), [("a1", FLAG * 20)])

    lines = printed(capsys.readouterr().out)
    note = table_dict(lines, "NOTE", "a1")["NOTE"]
    assert note.endswith(ELLIPSIS) and note != ELLIPSIS
    assert note[:-1] == FLAG * ((len(note) - 1) // 2)
    assert not lone_regional_indicators(note)
    assert "\n".join(lines).count("\u2026") == 1


@pytest.mark.parametrize("limit", range(3, 12))
def test_every_cut_width_keeps_the_flags_whole(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], limit: int
) -> None:
    at_columns(monkeypatch, 14 + limit)

    output.print_table("t", ("ID", "NOTE"), [("a1", FLAG * 20)])

    lines = printed(capsys.readouterr().out)
    note = table_dict(lines, "NOTE", "a1")["NOTE"]
    assert not lone_regional_indicators(note)


def test_a_cut_cell_of_wide_characters_still_fits_the_column(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    at_columns(monkeypatch, 30)

    output.print_table("t", ("ID", "NOTE"), [("a1", "\u6f22" * 30)])

    lines = printed(capsys.readouterr().out)
    assert max(table_layout.cell_width(line) for line in lines) <= 30
    assert table_dict(lines, "NOTE", "a1")["NOTE"].endswith(ELLIPSIS)


def test_a_multi_line_free_cell_is_cut_line_by_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    at_columns(monkeypatch, 30)

    output.print_table("t", ("ID", "NOTE"), [("a1", "x" * 60 + "\n" + "y" * 60)])

    text = "\n".join(printed(capsys.readouterr().out))
    assert text.count(ELLIPSIS) == 2
    assert max(len(line) for line in text.splitlines()) <= 30


def test_piped_deliveries_are_not_cut_and_keep_every_column(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # stdout is not a tty here (capsys) and COLUMNS is unset: scripts parse these tables.
    monkeypatch.delenv("COLUMNS", raising=False)
    item = delivery_item()

    webhooks.render_deliveries(output.AppState(), [item], None, every=True)

    out = capsys.readouterr().out
    shown = table_dict(printed(out), "ATTEMPTS", WID)
    assert shown["LAST ERROR"] == item.last_error
    assert shown["NEXT ATTEMPT"] == "2026-11-11 10:41:59"
    assert ELLIPSIS not in out
