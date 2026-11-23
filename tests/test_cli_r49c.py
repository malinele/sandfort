"""CLI round 49 (batch 3): usage polish.

* Any bad ``--wait-timeout`` value (also a non-number) gets the one usage wording, exit 2.
* The typer dependency is pinned below the release that changes the help layout.
* A long label, env or ``--expires-at`` value is cut inside the message, so the reason stays.
* ``key create --max-sandboxes`` without ``--label`` is a local usage error naming ``--label``.
* The relayed missing scopes stay a pure array; the cut remainder is a numeric field next to it.
"""

import json
import re
import sys
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.sandboxes import MAX_RELAYED_SCOPES, USAGE_MESSAGE_CHARS  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOXES_URL = "/v1/sandboxes"
STATUS_BODY = {
    "success": True,
    "data": {"status": "ok", "version": "0.1.0", "build_sha": "4871ea2f0c9d1b3a5e7f8091"},
    "error": None,
    "meta": None,
}
RANGE_WORDING = "must be a finite number greater than 0"
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
LONG_VALUE = "x" * 5000


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def usage_text(result: Any, as_json: bool) -> str:
    """The usage message as the user sees it: the json ``error.message``, else the output."""
    if not as_json:
        return " ".join(re.sub(r"[│╭╮╰╯─]", " ", str(result.output)).split())
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "USAGE_ERROR"
    return str(error["message"])


@pytest.fixture(autouse=True)
def profile_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    return tmp_path / "cfg" / config.PROFILE_FILENAME


@pytest.fixture
def router() -> Iterator[Any]:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        mock.get("/v1/status").respond(200, json=STATUS_BODY)
        yield mock


# 1) --wait-timeout: one wording for every bad value --------------------------------------------


@BOTH_MODES
@pytest.mark.parametrize("value", ["abc", "1.5s", "", "infinity", "inf", "nan", "0", "-2"])
@pytest.mark.parametrize("command", [["start", SID], ["create", "demo"]])
def test_every_bad_wait_timeout_gets_the_one_wording(
    router: Any, command: list[str], value: str, as_json: bool
) -> None:
    any_request = router.route().respond(500)

    result = invoke(["sandbox", *command, "--wait", f"--wait-timeout={value}"], as_json=as_json)

    assert result.exit_code == 2, result.output
    shown = usage_text(result, as_json)
    assert RANGE_WORDING in shown and "--wait-timeout" in shown
    assert "input should be" not in shown.lower() and "is not a valid" not in shown.lower()
    assert "'--wait-timeout'" not in shown
    assert "Traceback" not in result.output
    assert any_request.call_count == 0


@BOTH_MODES
def test_a_non_numeric_wait_timeout_without_wait_names_both_requirements(
    router: Any, as_json: bool
) -> None:
    result = invoke(["sandbox", "start", SID, "--wait-timeout=abc"], as_json=as_json)

    assert result.exit_code == 2
    shown = usage_text(result, as_json)
    assert "requires --wait" in shown and RANGE_WORDING in shown


def test_a_valid_wait_timeout_still_reaches_the_command(router: Any) -> None:
    config.save_profile(BASE, KEY)
    start = router.post(f"{SANDBOXES_URL}/{SID}/start").respond(500)

    result = invoke(["sandbox", "start", SID, "--wait", "--wait-timeout", "2.5"])

    assert result.exit_code != 2
    assert start.call_count >= 1


# 2) typer pin ----------------------------------------------------------------------------------


def test_the_cli_package_pins_typer_below_the_next_release() -> None:
    metadata = tomllib.loads((ROOT / "cli" / "pyproject.toml").read_text())
    typer_specs = [d for d in metadata["project"]["dependencies"] if d.startswith("typer")]

    assert len(typer_specs) == 1
    assert "<" in typer_specs[0]


# 3) long values keep their reason --------------------------------------------------------------


@BOTH_MODES
@pytest.mark.parametrize("option", ["--label", "--env"])
def test_a_long_pair_value_keeps_its_reason(option: str, as_json: bool) -> None:
    result = invoke(["sandbox", "create", "demo", option, LONG_VALUE], as_json=as_json)

    assert result.exit_code == 2
    shown = usage_text(result, as_json)
    assert "expected KEY=VALUE" in shown
    assert LONG_VALUE not in shown
    if as_json:
        assert len(shown) < USAGE_MESSAGE_CHARS


@BOTH_MODES
def test_a_long_expires_at_value_keeps_its_reason(as_json: bool) -> None:
    result = invoke(
        ["key", "create", "k", "--scope", "sandboxes:read", "--expires-at", LONG_VALUE],
        as_json=as_json,
    )

    assert result.exit_code == 2
    shown = usage_text(result, as_json)
    assert "expected ISO 8601" in shown
    assert LONG_VALUE not in shown


def test_a_short_value_is_still_echoed_whole() -> None:
    result = invoke(["sandbox", "create", "demo", "--label", "oops"])

    assert result.exit_code == 2
    assert "'oops'" in result.output


# 4) key create: a sandbox cap needs a label ------------------------------------------------------


@BOTH_MODES
def test_a_sandbox_cap_without_a_label_is_a_local_usage_error(router: Any, as_json: bool) -> None:
    any_request = router.route().respond(500)

    result = invoke(
        ["key", "create", "k", "--scope", "sandboxes:read", "--max-sandboxes", "3"],
        as_json=as_json,
    )

    assert result.exit_code == 2, result.output
    shown = usage_text(result, as_json)
    assert "--label" in shown and "--max-sandboxes" in shown
    assert "sandbox_labels" not in shown and "max_sandboxes" not in shown
    assert any_request.call_count == 0


# 5) scope remainder as a separate numeric field --------------------------------------------------


def forbidden(scopes: list[str]) -> dict[str, Any]:
    error = {
        "code": "FORBIDDEN",
        "message": "no",
        "details": {"missing_scopes": scopes},
        "request_id": "req_r49c_0123456789",
    }
    return {"success": False, "data": None, "error": error, "meta": None}


def login_args(*extra: str) -> list[str]:
    return ["login", "--base-url", BASE, "--api-key", KEY, *extra]


def test_the_scopes_array_stays_pure_and_the_remainder_is_numeric(router: Any) -> None:
    scopes = [f"scope_{number}:read" for number in range(3000)]
    router.get(SANDBOXES_URL).respond(403, json=forbidden(scopes))

    result = invoke(login_args("--verify-key"), as_json=True)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["missing_scopes"] == scopes[:MAX_RELAYED_SCOPES]
    assert payload["missing_scopes_beyond_cap"] == 3000 - MAX_RELAYED_SCOPES
    assert isinstance(payload["missing_scopes_beyond_cap"], int)


def test_the_text_line_keeps_the_human_note(router: Any) -> None:
    scopes = [f"scope_{number}:read" for number in range(3000)]
    router.get(SANDBOXES_URL).respond(403, json=forbidden(scopes))

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 0
    assert "scope_19:read, and 2980 more" in result.stdout


def test_a_list_within_the_cap_has_a_zero_remainder(router: Any) -> None:
    router.get(SANDBOXES_URL).respond(403, json=forbidden(["a:read", "b:read"]))

    result = invoke(login_args("--verify-key"), as_json=True)

    payload = json.loads(result.stdout)
    assert payload["missing_scopes"] == ["a:read", "b:read"]
    assert payload["missing_scopes_beyond_cap"] == 0


def test_the_require_verified_error_details_carry_the_same_shape(router: Any) -> None:
    scopes = [f"scope_{number}:read" for number in range(25)]
    router.get(SANDBOXES_URL).respond(403, json=forbidden(scopes))

    result = invoke(login_args("--require-verified"), as_json=True)

    assert result.exit_code == 1
    error = json.loads(result.stdout)["error"]
    assert error["details"]["missing_scopes"] == scopes[:MAX_RELAYED_SCOPES]
    assert error["details"]["missing_scopes_beyond_cap"] == 5
    assert "and 5 more" in error["message"]
