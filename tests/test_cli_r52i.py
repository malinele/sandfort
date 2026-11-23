"""CLI round 52, batch i: the blank sandbox reference sweep.

A blank (empty or whitespace-only) sandbox reference is the shared usage error of round 52 on
``exec``, ``snapshot create``, ``cp`` and ``shell``: exit 2, ``Invalid value for <sandbox>:
must not be empty``, one ``USAGE_ERROR`` object with ``"source": "client"`` under ``--json``,
no request sent and no traceback. ``shell`` finds it before the interactive-terminal check.
An empty cp reference (``:/path``) is a local path by the scp rule, so ``cp`` is covered with
a whitespace-only reference.
"""

import json
import re
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.shell_cmd import NO_TERMINAL  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
USAGE = 2
PLACEHOLDER = "<sandbox>"
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
BLANKS = pytest.mark.parametrize("blank", ["", "   "], ids=["empty", "whitespace"])
TRACEBACK_MARKERS = ("Traceback", 'File "', "ValueError", "httpx.", "not a Sandfort envelope")
NOT_FOUND = {
    "success": False,
    "data": None,
    "error": {"code": "NOT_FOUND", "message": "gone", "details": {}, "request_id": "req_1"},
    "meta": None,
}


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def flat(text: str) -> str:
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def router() -> Iterator[Any]:
    """Every request is answered with a NOT_FOUND envelope and counted."""
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        mock.route().mock(return_value=httpx.Response(404, json=NOT_FOUND))
        yield mock


def assert_usage_error(result: Any, router: Any, as_json: bool) -> None:
    assert result.exit_code == USAGE, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert router.calls.call_count == 0
    for stream in (result.stdout, result.stderr):
        assert not any(marker in stream for marker in TRACEBACK_MARKERS), stream
    assert NO_TERMINAL not in flat(result.output)
    expected = f"Invalid value for {PLACEHOLDER}: must not be empty"
    if as_json:
        payload = json.loads(result.stdout)  # exactly one document
        assert list(payload) == ["error"]
        assert result.stderr.strip() == ""
        error = payload["error"]
        assert error["code"] == "USAGE_ERROR" and error["source"] == "client"
        assert expected in flat(str(error["message"]))
    else:
        assert result.stdout.strip() == ""
        assert expected in flat(result.stderr)


# blank sandbox reference -> args ---------------------------------------------------------------

REF_CASES: dict[str, Callable[[str], list[str]]] = {
    "exec": lambda b: ["exec", b, "--", "true"],
    "snapshot-create": lambda b: ["snapshot", "create", b, "snap1"],
    "shell": lambda b: ["shell", b],
}


@BOTH_MODES
@BLANKS
@pytest.mark.parametrize("case", list(REF_CASES))
def test_a_blank_sandbox_reference_is_a_local_usage_error(
    router: Any, as_json: bool, blank: str, case: str
) -> None:
    result = invoke(REF_CASES[case](blank), as_json=as_json)

    assert_usage_error(result, router, as_json)


CP_CASES: dict[str, Callable[[str], list[str]]] = {
    "cp-upload": lambda b: ["cp", "local.txt", f"{b}:/w/a.txt"],
    "cp-download": lambda b: ["cp", f"{b}:/w/a.txt", "out.txt"],
}


@BOTH_MODES
@pytest.mark.parametrize("case", list(CP_CASES))
def test_a_whitespace_only_cp_sandbox_reference_is_a_local_usage_error(
    router: Any, as_json: bool, case: str
) -> None:
    result = invoke(CP_CASES[case]("   "), as_json=as_json)

    assert_usage_error(result, router, as_json)


# control cases: one valid reference per command -----------------------------------------------


def control_args(case: str, tmp_path: Path) -> list[str]:
    upload_source = tmp_path / "local.txt"
    upload_source.write_text("data")
    return {
        "exec": ["exec", "sbx_1", "--", "true"],
        "snapshot-create": ["snapshot", "create", "sbx_1", "snap1"],
        "cp-upload": ["cp", str(upload_source), "sbx_1:/w/a.txt"],
        "cp-download": ["cp", "sbx_1:/w/a.txt", str(tmp_path / "out.txt")],
    }[case]


@pytest.mark.parametrize("case", ["exec", "snapshot-create", "cp-upload", "cp-download"])
def test_a_valid_sandbox_reference_still_reaches_the_server(
    router: Any, case: str, tmp_path: Path
) -> None:
    result = invoke(control_args(case, tmp_path))

    assert result.exit_code != USAGE, result.output
    assert router.calls.call_count >= 1
    assert "must not be empty" not in result.output


def test_a_valid_shell_reference_gets_to_the_terminal_check(router: Any) -> None:
    result = invoke(["shell", "sbx_1"])

    assert result.exit_code != USAGE, result.output
    assert NO_TERMINAL in flat(result.output)
    assert "must not be empty" not in result.output
    assert router.calls.call_count == 0
