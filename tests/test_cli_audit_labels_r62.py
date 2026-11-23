"""CLI r62: audit list columns and order, whitespace label values, blank label keys, name rules.

1. ``audit list`` has STATUS, ERROR and PATH columns (from the event details), shows the route
   path as the target of a ``request.denied`` row, and lists newest first (``--order``
   ``newest|oldest``, sent to the API as ``desc|asc``).
2. A label value made only of spaces is shown exactly (json) or quoted (tables); a label filter
   with such a value is sent unchanged.
3. A label key of only spaces or only invisible characters is "blank or invisible".
4. A server name-rule error shows a plain description, not the raw regex.
"""

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
PROFILE_KEY = "sf_test_key_do_not_print"
AUDIT_URL = "/v1/audit-events"
SANDBOXES_URL = "/v1/sandboxes"
VOLUMES_URL = "/v1/volumes"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
RUNNER = CliRunner()
EXIT_USAGE = 2
ZERO_WIDTH_SPACE = "​"
RAW_NAME_PATTERN = "^[A-Za-z0-9][A-Za-z0-9_.-]*$"
PLAIN_NAME_RULE = "letters, digits, '.', '_' and '-', starting with a letter or digit, at most 63"


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def event_json(number: int, **extra: Any) -> dict[str, Any]:
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


def denied_json(number: int, **extra: Any) -> dict[str, Any]:
    return event_json(
        number,
        action="request.denied",
        outcome="denied",
        target_type=None,
        target_id=None,
        details={
            "method": "GET",
            "path": "/v1/sandboxes/sbx_x",
            "status": 403,
            "error_code": "FORBIDDEN",
        },
        **extra,
    )


def sandbox_json(labels: dict[str, str]) -> dict[str, Any]:
    return {
        "id": SID,
        "name": "demo",
        "state": "started",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
        "labels": labels,
    }


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, PROFILE_KEY)


@pytest.fixture
def router() -> Any:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


def rows_of(output: str) -> list[list[str]]:
    """The table's non-border lines split into cells."""
    lines = [line for line in output.splitlines() if "│" in line or "┃" in line]
    return [[c.strip() for c in re.split(r"[│┃]", line)[1:-1]] for line in lines]


def flat(text: str) -> str:
    """``text`` without Rich box borders and line folds, for substring checks."""
    return " ".join(re.sub(r"[│╭╮╰╯─┃]", " ", text).split())


def query_of(route: Any) -> dict[str, str]:
    return dict(route.calls[-1].request.url.params)


# 1. audit list


def test_audit_list_has_status_and_error_columns_and_no_path_that_repeats_the_target(
    router: Any,
) -> None:
    router.get(AUDIT_URL).respond(200, json=envelope([denied_json(1)]))

    result = invoke(["audit", "list"])

    assert result.exit_code == 0, result.output
    header, row = rows_of(result.stdout)[:2]
    assert header[4:7] == ["OUTCOME", "STATUS", "ERROR"]
    assert row[4:7] == ["denied", "403", "FORBIDDEN"]
    assert "PATH" not in header  # the denied row's path is its TARGET already


def test_request_denied_row_shows_the_route_path_as_its_target(router: Any) -> None:
    router.get(AUDIT_URL).respond(200, json=envelope([denied_json(1)]))

    result = invoke(["audit", "list"])

    header, row = rows_of(result.stdout)[:2]
    assert row[header.index("TARGET")] == "/v1/sandboxes/sbx_x"


def test_a_row_with_a_target_keeps_it_and_missing_details_show_a_dash(router: Any) -> None:
    router.get(AUDIT_URL).respond(200, json=envelope([event_json(2)]))

    result = invoke(["audit", "list"])

    header, row = rows_of(result.stdout)[:2]
    assert row[header.index("TARGET")] == "sbx_002"
    assert row[header.index("STATUS")] == row[header.index("ERROR")] == "-"
    assert "PATH" not in header  # no row has a path to show


def test_path_and_error_details_are_sanitised(router: Any) -> None:
    hostile = denied_json(3)
    hostile["details"] = {
        "path": "/v1/\x1b]0;pwn\x07x",
        "status": 400,
        "error_code": f"BAD\x1b[31mCODE{PROFILE_KEY}",
    }
    router.get(AUDIT_URL).respond(200, json=envelope([hostile]))

    result = invoke(["audit", "list"])

    assert "\x1b" not in result.stdout
    assert PROFILE_KEY not in result.stdout


def test_list_all_text_has_the_new_columns(router: Any) -> None:
    router.get(AUDIT_URL).respond(200, json=envelope([denied_json(1)]))

    result = invoke(["audit", "list", "--all"])

    lines = result.stdout.splitlines()
    for column in ("STATUS", "ERROR", "PATH"):
        assert column in lines[0]
    assert "403" in lines[1] and "FORBIDDEN" in lines[1]
    assert lines[1].count("/v1/sandboxes/sbx_x") == 2  # target and path


def test_audit_list_defaults_to_newest_first(router: Any) -> None:
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    assert invoke(["audit", "list"]).exit_code == 0

    assert query_of(route)["order"] == "desc"


@pytest.mark.parametrize(("choice", "sent"), [("newest", "desc"), ("oldest", "asc")])
def test_audit_list_order_newest_or_oldest(router: Any, choice: str, sent: str) -> None:
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--order", choice])

    assert result.exit_code == 0, result.output
    assert query_of(route)["order"] == sent


@pytest.mark.parametrize(("alias", "sent"), [("asc", "asc"), ("desc", "desc")])
def test_audit_list_order_keeps_asc_and_desc_as_aliases(router: Any, alias: str, sent: str) -> None:
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--order", alias])

    assert result.exit_code == 0, result.output
    assert query_of(route)["order"] == sent


@pytest.mark.parametrize(("alias", "sent"), [("asc", "asc"), ("desc", "desc")])
def test_audit_list_all_accepts_order_aliases(router: Any, alias: str, sent: str) -> None:
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--all", "--order", alias])

    assert result.exit_code == 0, result.output
    assert query_of(route)["order"] == sent


def test_audit_list_help_documents_newest_oldest_and_mentions_aliases() -> None:
    text = invoke(["audit", "list", "--help"]).output

    assert "newest|oldest" in text
    assert "aliases" in text


def test_audit_list_order_rejects_other_values(router: Any) -> None:
    route = router.get(AUDIT_URL).respond(200, json=envelope([]))

    result = invoke(["audit", "list", "--order", "sideways"])

    assert result.exit_code == EXIT_USAGE
    assert route.call_count == 0


# 2. whitespace label values


@pytest.mark.parametrize("value", [" ", "   "])
def test_json_shows_a_spaces_only_label_value_exactly(router: Any, value: str) -> None:
    router.get(f"{SANDBOXES_URL}/{SID}").respond(
        200, json=envelope(sandbox_json({"sp": value, "empty": "", "k": "v"}))
    )

    result = invoke(["sandbox", "get", SID], as_json=True)

    assert json.loads(result.stdout)["labels"] == {"sp": value, "empty": "", "k": "v"}


def test_json_list_shows_a_spaces_only_label_value_exactly(router: Any) -> None:
    router.get(SANDBOXES_URL).respond(200, json=envelope([sandbox_json({"sp": "  "})]))

    result = invoke(["sandbox", "list"], as_json=True)

    assert json.loads(result.stdout)[0]["labels"] == {"sp": "  "}


def test_tables_quote_a_spaces_only_label_value(router: Any) -> None:
    router.get(SANDBOXES_URL).respond(
        200, json=envelope([sandbox_json({"sp": "   ", "empty": ""})])
    )

    result = invoke(["sandbox", "list"])

    assert 'sp="   "' in result.stdout
    assert "empty=" in result.stdout and 'empty="' not in result.stdout


def test_field_view_quotes_a_spaces_only_label_value(router: Any) -> None:
    router.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(sandbox_json({"sp": "  "})))

    result = invoke(["sandbox", "get", SID])

    assert 'sp="  "' in result.stdout


def test_a_label_filter_with_a_whitespace_only_value_is_sent_unchanged(router: Any) -> None:
    route = router.get(SANDBOXES_URL).respond(200, json=envelope([]))

    for value in ("   ", " ", "\t"):
        result = invoke(["sandbox", "list", "-l", f"sp={value}"])
        assert result.exit_code == 0, result.output
        assert route.calls[-1].request.url.params.get_list("label") == [f"sp={value}"]


def test_a_volume_label_filter_with_spaces_is_sent_unchanged(router: Any) -> None:
    route = router.get(VOLUMES_URL).respond(200, json=envelope([]))

    result = invoke(["volume", "list", "-l", "sp=  "])

    assert result.exit_code == 0, result.output
    assert route.calls[-1].request.url.params.get_list("label") == ["sp=  "]


# 3. blank label keys


@pytest.mark.parametrize(
    "key", [" ", "   ", ZERO_WIDTH_SPACE, ZERO_WIDTH_SPACE * 3, f" {ZERO_WIDTH_SPACE} "]
)
@pytest.mark.parametrize("command", [["sandbox", "list"], ["sandbox", "create", "demo"]])
def test_a_blank_or_invisible_label_key_says_so(router: Any, command: list[str], key: str) -> None:
    result = invoke([*command, "-l", f"{key}=x"])

    assert result.exit_code == EXIT_USAGE
    assert "label key is blank or invisible" in flat(result.stderr)
    assert "expected KEY=VALUE" not in flat(result.stderr)
    assert router.calls.call_count == 0


def test_a_label_without_equals_still_says_expected_key_value(router: Any) -> None:
    result = invoke(["sandbox", "list", "-l", "novalue"])

    assert result.exit_code == EXIT_USAGE
    assert "expected KEY=VALUE" in flat(result.stderr)


# 4. plain name rule


def pattern_error(location: str = "name") -> dict[str, Any]:
    msg = f"String should match pattern '{RAW_NAME_PATTERN}'"
    return {
        "success": False,
        "data": None,
        "error": {
            "code": "VALIDATION_ERROR",
            "message": f"request validation failed: {location}: {msg}",
            "details": {
                "errors": [
                    {
                        "loc": ["body", location],
                        "msg": msg,
                        "type": "string_pattern_mismatch",
                        "ctx": {"pattern": RAW_NAME_PATTERN},
                    }
                ]
            },
        },
    }


@pytest.mark.parametrize("as_json", [False, True])
def test_a_name_rule_error_shows_a_plain_description(router: Any, as_json: bool) -> None:
    router.post(SANDBOXES_URL).respond(422, json=pattern_error())

    result = invoke(["sandbox", "create", "bad_"], as_json=as_json)

    shown = result.stdout if as_json else result.stderr
    assert result.exit_code != 0
    assert RAW_NAME_PATTERN not in shown
    assert "A-Za-z0-9" not in shown
    assert PLAIN_NAME_RULE in shown


def test_other_validation_errors_are_untouched(router: Any) -> None:
    body = pattern_error()
    body["error"]["details"]["errors"][0]["msg"] = "Input should be a valid string"
    body["error"]["message"] = "request validation failed"
    router.post(SANDBOXES_URL).respond(422, json=body)

    result = invoke(["sandbox", "create", "demo"])

    assert "Input should be a valid string" in result.stderr
    assert PLAIN_NAME_RULE not in result.stderr
