"""CLI round 64: `key list` and `audit list` fit narrow terminals; dropped columns are named;
ids in field views are never cut.

1. `key list` uses the fit_table layout: ID, STATUS, EXPIRES and MAX SANDBOXES stay whole;
   NAME, SCOPES and LABELS are cut with an ellipsis or dropped by priority.
2. `audit list` does the same: OCCURRED, ACTION, OUTCOME and STATUS stay whole; TARGET, ACTOR,
   ERROR, PATH and REQUEST ID are cut or dropped; PATH shows only when it differs from TARGET.
3. A column the layout drops is named once on stderr (text mode only).
4. `sandbox get` wraps an id that is longer than the value column instead of cutting it.
"""

import json
import re
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config, output, table_layout  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
KEY_ID = "key_01HZZZZZZZZZZZZZZZZZZZZZZA"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
RUNNER = CliRunner()
ANSI_SGR_RE = re.compile(r"\x1b\[[0-9;]*m")
CELL_SPLIT_RE = re.compile(r"[│┃]")
ELLIPSIS = "…"
WIDTHS = (60, 80, 100, 140)
COLOR_ENV_VARS = ("FORCE_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE")
BORDER_AND_PADDING_PER_COLUMN = 3
CLOSING_BORDER = 1
HIDDEN_NOTE_RE = re.compile(
    r"^\(hidden at this width: ([A-Z ,]+); widen the terminal or use --json\)$", re.MULTILINE
)

KEY_FIXED = ("ID", "STATUS", "EXPIRES", "MAX SANDBOXES")
KEY_FREE = ("NAME", "SCOPES", "LABELS")
AUDIT_FIXED = ("OCCURRED", "ACTION", "OUTCOME", "STATUS")
AUDIT_FREE = ("TARGET", "ACTOR", "ERROR", "PATH", "REQUEST ID")
LONG_NAME = "ci-pipeline-deploy-key-" + "n" * 30
LONG_LABELS = {"team": "platform", "environment": "staging", "tier": "gold"}
LONG_ERROR = "rate limit exceeded for this organisation, retry after a while"
LONG_PATH = "/v1/sandboxes/" + "p" * 40 + "/exec"


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def key_json(**extra: Any) -> dict[str, Any]:
    base = {
        "id": KEY_ID,
        "name": LONG_NAME,
        "prefix": "sf_abcd",
        "scopes": ["sandboxes:read", "sandboxes:write", "volumes:read", "audit:read"],
        "sandbox_labels": LONG_LABELS,
        "max_sandboxes": 25,
        "created_at": "2026-11-06T10:00:00+00:00",
        "last_used_at": None,
        "expires_at": "2027-01-01T00:00:00+00:00",
        "revoked_at": None,
        "created_by": None,
    }
    return {**base, **extra}


def event_json(number: int = 1, **extra: Any) -> dict[str, Any]:
    base = {
        "id": f"aud_{number:03d}",
        "org_id": "org_1",
        "actor_type": "api_key",
        "actor_id": f"key_01HZZZZZZZZZZZZZZZZZZZZZ{number:03d}",
        "action": "sandbox.create",
        "target_type": "sandbox",
        "target_id": f"sbx_01HZZZZZZZZZZZZZZZZZZZZZ{number:03d}",
        "outcome": "failure",
        "request_id": f"req_01HZZZZZZZZZZZZZZZZZZZZZ{number:03d}",
        "occurred_at": "2026-11-01T10:30:00+00:00",
        "details": {"status": 429, "error_code": LONG_ERROR, "path": LONG_PATH},
    }
    return {**base, **extra}


def sandbox_json() -> dict[str, Any]:
    return {
        "id": SID,
        "name": "demo",
        "state": "started",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
        "labels": {},
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


def header_and_row(lines: Sequence[str], marker: str, row_marker: str) -> dict[str, str]:
    """Header name -> cell of the one data row, for the lines holding both markers."""
    header = next(line for line in lines if marker in line)
    row = next(line for line in lines if row_marker in line)
    return dict(zip(cells_of(header), cells_of(row), strict=True))


def table_lines(text: str) -> list[str]:
    """The lines of the table itself (the title and the stderr note are not)."""
    return [line for line in printed(text) if CELL_SPLIT_RE.search(line)]


def invoke_split(args: Sequence[str]) -> Any:
    runner = CliRunner()
    return runner.invoke(create_app(None), list(args))


def hidden_in(stderr: str) -> list[str]:
    match = HIDDEN_NOTE_RE.search(stderr)
    return [] if match is None else match.group(1).split(", ")


# 1. key list --------------------------------------------------------------------------------


@pytest.mark.parametrize("width", WIDTHS)
def test_key_list_keeps_id_status_expiry_and_cap_whole(
    monkeypatch: pytest.MonkeyPatch, router: Any, width: int
) -> None:
    at_columns(monkeypatch, width)
    router.get("/v1/api-keys").respond(200, json=envelope([key_json()]))

    result = invoke_split(["key", "list"])

    assert result.exit_code == 0, result.output
    shown = header_and_row(table_lines(result.stdout), "STATUS", "active")
    assert shown["ID"] == KEY_ID
    assert shown["STATUS"] == "active"
    assert shown["EXPIRES"] == "2027-01-01 00:00"
    assert shown["MAX SANDBOXES"] == "25"


@pytest.mark.parametrize("width", WIDTHS)
def test_key_list_headers_are_never_cut_mid_word(
    monkeypatch: pytest.MonkeyPatch, router: Any, width: int
) -> None:
    at_columns(monkeypatch, width)
    router.get("/v1/api-keys").respond(200, json=envelope([key_json()]))

    result = invoke_split(["key", "list"])

    header = next(line for line in table_lines(result.stdout) if "STATUS" in line)
    assert all(name in KEY_FIXED + KEY_FREE for name in cells_of(header))
    assert "STATUS" in header and "EXPIRES" in header and "MAX SANDBOXES" in header


@pytest.mark.parametrize("width", WIDTHS)
def test_key_list_is_one_line_per_key_and_fits_when_the_fixed_columns_do(
    monkeypatch: pytest.MonkeyPatch, router: Any, width: int
) -> None:
    at_columns(monkeypatch, width)
    router.get("/v1/api-keys").respond(
        200, json=envelope([key_json(), key_json(id=KEY_ID[:-1] + "B", name="b")])
    )

    result = invoke_split(["key", "list"])

    lines = table_lines(result.stdout)
    assert len(lines) == 3  # the header and the two rows: nothing wrapped onto more lines
    fixed_width = max(len(KEY_ID), 16) + 7 + 16 + 13 + 4 * BORDER_AND_PADDING_PER_COLUMN
    allowed = max(width, fixed_width + CLOSING_BORDER)
    assert all(len(line) <= allowed for line in lines)


def test_key_list_at_140_cuts_free_text_with_an_ellipsis(
    monkeypatch: pytest.MonkeyPatch, router: Any
) -> None:
    at_columns(monkeypatch, 140)
    router.get("/v1/api-keys").respond(200, json=envelope([key_json()]))

    result = invoke_split(["key", "list"])

    shown = header_and_row(table_lines(result.stdout), "STATUS", "active")
    assert shown["NAME"].endswith(ELLIPSIS) or shown["NAME"] == LONG_NAME
    assert shown["ID"] == KEY_ID


def test_key_list_at_60_drops_free_columns_and_keeps_the_id(
    monkeypatch: pytest.MonkeyPatch, router: Any
) -> None:
    at_columns(monkeypatch, 60)
    router.get("/v1/api-keys").respond(200, json=envelope([key_json()]))

    result = invoke_split(["key", "list"])

    shown = header_and_row(table_lines(result.stdout), "STATUS", "active")
    assert set(shown) == set(KEY_FIXED)
    assert hidden_in(result.stderr) == ["NAME", "SCOPES", "LABELS"]
    assert LONG_NAME not in result.stdout


def test_key_list_drops_labels_before_scopes_before_name(
    monkeypatch: pytest.MonkeyPatch, router: Any
) -> None:
    router.get("/v1/api-keys").respond(200, json=envelope([key_json()]))
    kept_by_width: dict[int, set[str]] = {}
    for width in range(60, 200, 4):
        at_columns(monkeypatch, width)
        result = invoke_split(["key", "list"])
        header = next(line for line in table_lines(result.stdout) if "STATUS" in line)
        kept_by_width[width] = set(cells_of(header))

    order = ("LABELS", "SCOPES", "NAME")  # first dropped first
    for narrow, wide in zip(sorted(kept_by_width), sorted(kept_by_width)[1:], strict=False):
        for index, name in enumerate(order):
            if name in kept_by_width[narrow]:
                assert all(later in kept_by_width[narrow] for later in order[index + 1 :])
        assert kept_by_width[narrow] <= kept_by_width[wide]


@pytest.mark.parametrize("width", WIDTHS)
def test_key_list_names_what_it_hid_on_stderr_only(
    monkeypatch: pytest.MonkeyPatch, router: Any, width: int
) -> None:
    at_columns(monkeypatch, width)
    router.get("/v1/api-keys").respond(200, json=envelope([key_json()]))

    result = invoke_split(["key", "list"])

    header = next(line for line in table_lines(result.stdout) if "STATUS" in line)
    hidden = hidden_in(result.stderr)
    assert set(hidden) == (set(KEY_FIXED + KEY_FREE) - set(cells_of(header)))
    assert "hidden at this width" not in result.stdout


def test_key_list_wide_terminal_prints_everything_and_no_note(
    monkeypatch: pytest.MonkeyPatch, router: Any
) -> None:
    at_columns(monkeypatch, 400)
    router.get("/v1/api-keys").respond(200, json=envelope([key_json()]))

    result = invoke_split(["key", "list"])

    shown = header_and_row(table_lines(result.stdout), "STATUS", "active")
    assert shown["NAME"] == LONG_NAME
    assert shown["ID"] == KEY_ID
    assert "hidden at this width" not in result.stderr


def test_key_list_json_is_not_laid_out_and_has_no_note(
    monkeypatch: pytest.MonkeyPatch, router: Any
) -> None:
    at_columns(monkeypatch, 60)
    router.get("/v1/api-keys").respond(200, json=envelope([key_json()]))

    result = invoke_split(["--json", "key", "list"])

    assert json.loads(result.stdout)[0]["name"] == LONG_NAME
    assert "hidden at this width" not in result.stderr


# 2. audit list ------------------------------------------------------------------------------


@pytest.mark.parametrize("width", WIDTHS)
def test_audit_list_keeps_time_action_outcome_and_status_whole(
    monkeypatch: pytest.MonkeyPatch, router: Any, width: int
) -> None:
    at_columns(monkeypatch, width)
    router.get("/v1/audit-events").respond(200, json=envelope([event_json()]))

    result = invoke_split(["audit", "list"])

    assert result.exit_code == 0, result.output
    shown = header_and_row(table_lines(result.stdout), "OUTCOME", "failure")
    assert shown["OCCURRED"] == "2026-11-01 10:30:00"
    assert shown["ACTION"] == "sandbox.create"
    assert shown["OUTCOME"] == "failure"
    assert shown["STATUS"] == "429"


@pytest.mark.parametrize("width", WIDTHS)
def test_audit_list_never_cuts_an_id_it_shows(
    monkeypatch: pytest.MonkeyPatch, router: Any, width: int
) -> None:
    at_columns(monkeypatch, width)
    router.get("/v1/audit-events").respond(200, json=envelope([event_json()]))

    result = invoke_split(["audit", "list"])

    shown = header_and_row(table_lines(result.stdout), "OUTCOME", "failure")
    for name, value in (
        ("ACTOR", event_json()["actor_id"]),
        ("REQUEST ID", event_json()["request_id"]),
    ):
        assert shown.get(name, value) == value


@pytest.mark.parametrize("width", WIDTHS)
def test_audit_list_is_one_line_per_event_and_no_wider_than_it_must_be(
    monkeypatch: pytest.MonkeyPatch, router: Any, width: int
) -> None:
    at_columns(monkeypatch, width)
    router.get("/v1/audit-events").respond(200, json=envelope([event_json(1), event_json(2)]))

    result = invoke_split(["audit", "list"])

    lines = table_lines(result.stdout)
    assert len(lines) == 3
    fixed_width = 19 + 14 + 7 + 3 + 4 * BORDER_AND_PADDING_PER_COLUMN + CLOSING_BORDER
    assert all(len(line) <= max(width, fixed_width) for line in lines)


@pytest.mark.parametrize("width", WIDTHS)
def test_audit_list_names_what_it_hid_on_stderr(
    monkeypatch: pytest.MonkeyPatch, router: Any, width: int
) -> None:
    at_columns(monkeypatch, width)
    router.get("/v1/audit-events").respond(200, json=envelope([event_json()]))

    result = invoke_split(["audit", "list"])

    header = next(line for line in table_lines(result.stdout) if "OUTCOME" in line)
    hidden = hidden_in(result.stderr)
    assert set(hidden).isdisjoint(cells_of(header))
    assert set(hidden) | set(cells_of(header)) == set(AUDIT_FIXED + AUDIT_FREE)


def test_audit_list_at_60_keeps_only_the_fixed_columns(
    monkeypatch: pytest.MonkeyPatch, router: Any
) -> None:
    at_columns(monkeypatch, 60)
    router.get("/v1/audit-events").respond(200, json=envelope([event_json()]))

    result = invoke_split(["audit", "list"])

    shown = header_and_row(table_lines(result.stdout), "OUTCOME", "failure")
    assert set(shown) == set(AUDIT_FIXED)
    assert set(hidden_in(result.stderr)) == set(AUDIT_FREE)


def test_audit_list_drops_path_before_error_and_error_before_target(
    monkeypatch: pytest.MonkeyPatch, router: Any
) -> None:
    router.get("/v1/audit-events").respond(200, json=envelope([event_json()]))
    kept: list[set[str]] = []
    for width in range(60, 260, 4):
        at_columns(monkeypatch, width)
        result = invoke_split(["audit", "list"])
        header = next(line for line in table_lines(result.stdout) if "OUTCOME" in line)
        kept.append(set(cells_of(header)))

    for narrow, wide in zip(kept, kept[1:], strict=False):
        assert narrow <= wide
    for names in kept:
        if "PATH" in names:
            assert "ERROR" in names and "TARGET" in names
        if "ERROR" in names:
            assert "TARGET" in names


def test_audit_list_path_shows_only_when_it_differs_from_target(
    monkeypatch: pytest.MonkeyPatch, router: Any
) -> None:
    at_columns(monkeypatch, 400)
    denied = event_json(
        1,
        action="request.denied",
        target_id=None,
        details={"status": 403, "error_code": "FORBIDDEN", "path": "/v1/keys"},
    )
    other = event_json(2, details={"status": 429, "error_code": "RATE", "path": "/v1/x"})
    router.get("/v1/audit-events").respond(200, json=envelope([denied, other]))

    result = invoke_split(["audit", "list"])

    lines = table_lines(result.stdout)
    header = next(line for line in lines if "OUTCOME" in line)
    names = cells_of(header)
    rows = [dict(zip(names, cells_of(line), strict=True)) for line in lines if "/v1/" in line]
    by_action = {row["ACTION"]: row for row in rows if row["ACTION"] != "ACTION"}
    assert by_action["request.denied"]["TARGET"] == "/v1/keys"
    assert by_action["request.denied"]["PATH"] == "-"
    assert by_action["sandbox.create"]["PATH"] == "/v1/x"


def test_audit_list_has_no_path_column_when_every_path_repeats_the_target(
    monkeypatch: pytest.MonkeyPatch, router: Any
) -> None:
    at_columns(monkeypatch, 400)
    denied = event_json(
        1,
        action="request.denied",
        target_id=None,
        details={"status": 403, "error_code": "FORBIDDEN", "path": "/v1/keys"},
    )
    router.get("/v1/audit-events").respond(200, json=envelope([denied]))

    result = invoke_split(["audit", "list"])

    header = next(line for line in table_lines(result.stdout) if "OUTCOME" in line)
    assert "PATH" not in cells_of(header)
    assert "hidden at this width" not in result.stderr


def test_audit_list_json_is_not_laid_out_and_has_no_note(
    monkeypatch: pytest.MonkeyPatch, router: Any
) -> None:
    at_columns(monkeypatch, 60)
    router.get("/v1/audit-events").respond(200, json=envelope([event_json()]))

    result = invoke_split(["--json", "audit", "list"])

    assert json.loads(result.stdout)["events"][0]["details"]["path"] == LONG_PATH
    assert "hidden at this width" not in result.stderr


# 3. the hidden-columns note -----------------------------------------------------------------


def test_print_table_names_dropped_columns_once_on_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    at_columns(monkeypatch, 30)
    columns = ("ID", "NAME", "STATE", "LABELS")
    row = ("id_0123456789", "n" * 40, "started", "l" * 40)

    output.print_table("things", columns, [row], free=("NAME", "LABELS"))

    captured = capsys.readouterr()
    assert captured.err == (
        "(hidden at this width: NAME, LABELS; widen the terminal or use --json)\n"
    )
    assert "hidden" not in captured.out


def test_print_table_prints_no_note_when_a_column_is_only_cut(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    at_columns(monkeypatch, 40)

    output.print_table("things", ("ID", "NAME"), [("id_1", "n" * 80)], free=("NAME",))

    captured = capsys.readouterr()
    assert captured.err == ""
    assert ELLIPSIS in captured.out


def test_uncut_columns_are_dropped_whole_never_cut() -> None:
    columns = ("ID", "NAME", "REF")
    rows = [("i1", "n" * 30, "ref_" + "x" * 26)]

    layout = table_layout.plan_layout(columns, rows, ("NAME", "REF"), 45, uncut=("REF",))

    assert layout.kept == (0, 1)
    assert 2 not in layout.limits
    wide = table_layout.plan_layout(columns, rows, ("NAME", "REF"), 200, uncut=("REF",))
    assert wide.kept == (0, 1, 2)
    snug = table_layout.plan_layout(columns, rows, ("REF", "NAME"), 60, uncut=("REF",))
    assert snug.kept == (0, 1, 2)
    assert snug.limits.get(2) is None
    assert 1 in snug.limits


def test_hidden_columns_lists_the_dropped_names_in_table_order() -> None:
    columns = ("ID", "NAME", "STATE", "LABELS")
    rows = [("id_1", "n" * 40, "started", "l" * 40)]

    layout = table_layout.plan_layout(columns, rows, ("NAME", "LABELS"), 25)

    assert table_layout.hidden_columns(columns, layout) == ("NAME", "LABELS")


# 4. ids in field views ----------------------------------------------------------------------


@pytest.mark.parametrize("width", (40, 50, 60, 80))
def test_sandbox_get_never_cuts_the_id(
    monkeypatch: pytest.MonkeyPatch, router: Any, width: int
) -> None:
    at_columns(monkeypatch, width)
    router.get(f"/v1/sandboxes/{SID}").respond(200, json=envelope(sandbox_json()))

    result = invoke_split(["sandbox", "get", SID])

    assert result.exit_code == 0, result.output
    lines = table_lines(result.stdout)
    start = next(i for i, line in enumerate(lines) if cells_of(line)[:1] == ["id"])
    pieces = []
    for line in lines[start:]:
        cells = cells_of(line)
        if len(cells) != 2 or (cells[0] and cells[0] != "id"):
            break
        pieces.append(cells[1])
    assert "".join(pieces) == SID
    assert ELLIPSIS not in "".join(pieces)


def test_a_field_view_keeps_an_id_value_whole_when_it_fits(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    at_columns(monkeypatch, 100)

    output.print_fields("thing", {"id": SID, "name": "demo"})

    assert SID in capsys.readouterr().out
