"""CLI and SDK round 53, batch x: three findings from an i18n tester.

1. The text error line writes non-string ``details`` values with their real characters (a
   Cyrillic or Thai env name is not a ``\\uXXXX`` escape); the json error is unchanged.
2. A sandbox name that matches nothing is sanitised before it is placed in the message, so a lone
   ESC in the input cannot swallow the closing quote or part of the template.
3. ``except CONTEXT_GONE_ERRORS as exc`` can read ``exc.state`` under ``mypy --strict``.
"""

import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SDK_SRC = ROOT / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from mypy import api as mypy_api  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import CONTEXT_GONE_ERRORS, NoContainer, NotFound  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
RUNNER = CliRunner()
EMPTY_LIST = {"success": True, "data": [], "error": None, "meta": None}
CYRILLIC_ENV = "ПЕРЕМЕННАЯ"
THAI_ENV = "ตัวแปร"
CLOSING = "pass an id (sbx_...) or the name of an existing sandbox"


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def mock() -> Iterator[respx.MockRouter]:
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        yield router


def error_reply(details: dict[str, Any]) -> httpx.Response:
    body = {
        "success": False,
        "data": None,
        "error": {
            "code": "VALIDATION_ERROR",
            "message": "bad environment",
            "details": details,
            "request_id": "req_1",
        },
        "meta": None,
    }
    return httpx.Response(422, json=body)


# 1. non-ASCII details values in the text error line ------------------------------------------


@pytest.mark.parametrize("name", [CYRILLIC_ENV, THAI_ENV], ids=["cyrillic", "thai"])
def test_text_error_shows_non_ascii_detail_values_as_real_characters(
    mock: respx.MockRouter, name: str
) -> None:
    mock.get("/v1/sandboxes").mock(return_value=error_reply({"env": [name], "count": 1}))

    result = invoke(["sandbox", "list"])

    assert result.exit_code == 1
    assert f'["{name}"]' in result.stderr
    assert "\\u" not in result.stderr


def test_text_error_keeps_non_ascii_keys_of_a_nested_detail(mock: respx.MockRouter) -> None:
    mock.get("/v1/sandboxes").mock(return_value=error_reply({"env": {CYRILLIC_ENV: 1}}))

    result = invoke(["sandbox", "list"])

    assert f'{{"{CYRILLIC_ENV}":1}}' in result.stderr
    assert "\\u" not in result.stderr


def test_text_error_detail_values_are_still_sanitised(mock: respx.MockRouter) -> None:
    hostile = f"{CYRILLIC_ENV}\x1b]0;x\x07\x1b[31m"
    mock.get("/v1/sandboxes").mock(return_value=error_reply({"env": [hostile]}))

    result = invoke(["sandbox", "list"])

    assert CYRILLIC_ENV in result.stderr
    assert "\x1b" not in result.stderr
    assert "\x07" not in result.stderr


def test_text_error_keeps_a_lone_surrogate_off_the_terminal(mock: respx.MockRouter) -> None:
    body = json.dumps(
        {
            "success": False,
            "data": None,
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "bad",
                "details": {"env": ["a\\ud800b"]},
                "request_id": "req_1",
            },
            "meta": None,
        }
    )
    mock.get("/v1/sandboxes").mock(
        return_value=httpx.Response(422, content=body, headers={"content-type": "application/json"})
    )

    result = invoke(["sandbox", "list"])

    assert result.exit_code == 1
    assert "Traceback" not in result.output


def test_json_error_is_unchanged_for_non_ascii_details(mock: respx.MockRouter) -> None:
    mock.get("/v1/sandboxes").mock(return_value=error_reply({"env": [THAI_ENV]}))

    result = invoke(["sandbox", "list"], as_json=True)

    document = json.loads(result.stdout)
    assert document["error"]["details"] == {"env": [THAI_ENV]}
    assert "\\u" in result.stdout  # print_json keeps its default ASCII escaping


# 2. the not-found name message --------------------------------------------------------------


def test_name_miss_with_a_lone_escape_keeps_the_quote_and_the_template(
    mock: respx.MockRouter,
) -> None:
    mock.get("/v1/sandboxes").mock(return_value=httpx.Response(200, json=EMPTY_LIST))

    result = invoke(["sandbox", "get", "web\x1b"])

    assert result.exit_code == 1
    line = " ".join(result.stderr.split())
    assert "\x1b" not in result.stderr
    assert f"no sandbox named 'web'; {CLOSING}" in line


def test_name_miss_with_a_lone_escape_in_json_keeps_the_template(mock: respx.MockRouter) -> None:
    mock.get("/v1/sandboxes").mock(return_value=httpx.Response(200, json=EMPTY_LIST))

    result = invoke(["sandbox", "get", "web\x1b"], as_json=True)

    message = json.loads(result.stdout)["error"]["message"]
    assert message == f"no sandbox named 'web'; {CLOSING}"


def test_name_miss_keeps_a_non_ascii_name(mock: respx.MockRouter) -> None:
    mock.get("/v1/sandboxes").mock(return_value=httpx.Response(200, json=EMPTY_LIST))

    result = invoke(["sandbox", "get", THAI_ENV])

    assert f"no sandbox named '{THAI_ENV}'; {CLOSING}" in " ".join(result.stderr.split())


# 3. CONTEXT_GONE_ERRORS and the state attribute -----------------------------------------------

DOCUMENTED_PATTERN = """\
from sandfort_sdk import CONTEXT_GONE_ERRORS


def run(call: object) -> str | None:
    try:
        raise RuntimeError
    except CONTEXT_GONE_ERRORS as exc:
        return exc.state
    except RuntimeError:
        return None
"""


def test_both_context_gone_errors_expose_state_at_runtime() -> None:
    assert CONTEXT_GONE_ERRORS == (NoContainer, NotFound)
    stopped = NoContainer("stopped", details={"state": "stopped"})
    deleted = NotFound("gone")

    assert stopped.state == "stopped"
    assert deleted.state is None


def test_documented_except_and_read_state_pattern_passes_mypy_strict(tmp_path: Path) -> None:
    snippet = tmp_path / "snippet.py"
    snippet.write_text(DOCUMENTED_PATTERN)
    previous = os.environ.get("MYPYPATH")
    os.environ["MYPYPATH"] = str(SDK_SRC)
    try:
        stdout, stderr, status = mypy_api.run(
            ["--strict", "--no-incremental", "--cache-dir", os.devnull, str(snippet)]
        )
    finally:
        if previous is None:
            os.environ.pop("MYPYPATH", None)
        else:
            os.environ["MYPYPATH"] = previous

    assert status == 0, stdout + stderr
