"""CLI round 53, batch p: cp argument checks, the name-miss prefix and the preview port help.

``cp`` refuses, before any request: a blank local path (usage error, exit 2, ``Invalid value
for <source>/<destination>: must not be empty``), an empty or blank remote path in either
direction (the same usage error since round 53v), and not exactly one ``<sandbox>:<path>`` endpoint
(now a usage error with the old message). A recursive download into a path whose parent is a
regular file gets the single-file ``destination X is not a directory`` wording. A sandbox name
that matches nothing starts its text line with ``NOT_FOUND:`` like an id miss; the json message
carries no prefix (the code is its own field). ``preview --help`` states the port range.
"""

import json
import os
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config, cp_dir  # noqa: E402
from sandfort_cli.cmd_cmd import MAX_PORT, MIN_PREVIEW_PORT  # noqa: E402
from sandfort_cli.cp_cmd import ENDPOINT_ERROR  # noqa: E402
from sandfort_cli.cp_dir import EMPTY_REMOTE_MESSAGE  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.output import CliError, error_payload  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
MISSING_NAME = "ghost"
USAGE = 2
PLATFORM_ERROR = 125
EXIT_FAILURE = 1
ENOTDIR = 20
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
BLANKS = pytest.mark.parametrize("blank", ["", "   "], ids=["empty", "whitespace"])
RECURSIVE = pytest.mark.parametrize("recursive", [False, True], ids=["file", "recursive"])
TRACEBACK_MARKERS = ("Traceback", 'File "', "Errno", "httpx.")
NAME_MISS = (
    f"no sandbox named '{MISSING_NAME}'; pass an id (sbx_...) or the name of an existing sandbox"
)
NOT_FOUND_ENVELOPE = {
    "success": False,
    "data": None,
    "error": {"code": "NOT_FOUND", "message": "gone", "details": {}, "request_id": "req_1"},
    "meta": None,
}
EMPTY_LIST_ENVELOPE = {"success": True, "data": [], "error": None, "meta": None}


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def flat(text: str) -> str:
    """Text without the box-drawing frame, whitespace collapsed."""
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


def recursive_flag(recursive: bool) -> list[str]:
    return ["-r"] if recursive else []


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def router() -> Iterator[Any]:
    """Sandbox ids answer NOT_FOUND, the sandbox list is empty; every request is counted."""
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        mock.get("/v1/sandboxes").mock(return_value=httpx.Response(200, json=EMPTY_LIST_ENVELOPE))
        mock.route().mock(return_value=httpx.Response(404, json=NOT_FOUND_ENVELOPE))
        yield mock


@pytest.fixture
def workdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """An empty current directory, so a copy that lands in ``.`` would be seen."""
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    return work


class NoRequestSandbox:
    """A sandbox whose fs must not be used: the guards come first."""

    @property
    def fs(self) -> Any:
        raise AssertionError("no transfer may start")


def assert_no_traceback(result: Any) -> None:
    for stream in (result.stdout, result.stderr):
        assert not any(marker in stream for marker in TRACEBACK_MARKERS), stream


def assert_usage_error(result: Any, router: Any, expected: str, *, as_json: bool) -> None:
    """Exit 2, nothing sent; one USAGE_ERROR document (json) or the usage frame (text)."""
    assert result.exit_code == USAGE, result.output
    assert router.calls.call_count == 0
    assert_no_traceback(result)
    assert "copied" not in result.output
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


def json_error(result: Any) -> dict[str, Any]:
    payload = json.loads(result.stdout)
    assert list(payload) == ["error"]
    error: dict[str, Any] = payload["error"]
    return error


# 1) a blank local path is a usage error -------------------------------------------------------


@BOTH_MODES
@BLANKS
@RECURSIVE
def test_a_download_to_a_blank_local_path_is_a_usage_error(
    router: Any, workdir: Path, as_json: bool, blank: str, recursive: bool
) -> None:
    args = ["cp", *recursive_flag(recursive), f"{SID}:/w/a.txt", blank]

    result = invoke(args, as_json=as_json)

    assert_usage_error(
        result, router, "Invalid value for <destination>: must not be empty", as_json=as_json
    )
    assert list(workdir.iterdir()) == []


@BOTH_MODES
@BLANKS
@RECURSIVE
def test_an_upload_from_a_blank_local_path_is_a_usage_error(
    router: Any, workdir: Path, as_json: bool, blank: str, recursive: bool
) -> None:
    (workdir / "present.txt").write_text("data")
    args = ["cp", *recursive_flag(recursive), blank, f"{SID}:/w/a.txt"]

    result = invoke(args, as_json=as_json)

    assert_usage_error(
        result, router, "Invalid value for <source>: must not be empty", as_json=as_json
    )
    assert "is not a regular file" not in result.output


# 2) an empty remote path is a usage error in both directions (since round 53v) -----------------


@BOTH_MODES
@BLANKS
@RECURSIVE
def test_a_download_from_an_empty_remote_path_is_refused_before_any_request(
    router: Any, tmp_path: Path, as_json: bool, blank: str, recursive: bool
) -> None:
    destination = tmp_path / "out"
    args = ["cp", *recursive_flag(recursive), f"{SID}:{blank}", str(destination)]

    result = invoke(args, as_json=as_json)

    assert_usage_error(
        result, router, "Invalid value for <source>: must not be empty", as_json=as_json
    )
    assert not destination.exists()


@BOTH_MODES
@BLANKS
@RECURSIVE
def test_an_upload_to_an_empty_remote_path_is_refused_the_same_way(
    router: Any, tmp_path: Path, as_json: bool, blank: str, recursive: bool
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a").write_text("alpha")
    source = tree if recursive else tree / "a"
    args = ["cp", *recursive_flag(recursive), str(source), f"{SID}:{blank}"]

    result = invoke(args, as_json=as_json)

    assert_usage_error(
        result, router, "Invalid value for <destination>: must not be empty", as_json=as_json
    )


def test_the_post_lookup_dir_download_guard_refuses_an_empty_remote_path(tmp_path: Path) -> None:
    with pytest.raises(CliError) as caught:
        cp_dir.download_dir(NoRequestSandbox(), "", tmp_path / "out")  # type: ignore[arg-type]

    assert str(caught.value) == EMPTY_REMOTE_MESSAGE
    assert "source" not in error_payload(caught.value)["error"]


# 3) not exactly one sandbox-path endpoint is a usage error -------------------------------------


@BOTH_MODES
@pytest.mark.parametrize(
    ("source", "destination"),
    [("a.txt", "b.txt"), (f"{SID}:/a", f"{SID}:/b")],
    ids=["neither", "both"],
)
def test_not_exactly_one_remote_endpoint_is_a_usage_error_with_the_same_message(
    router: Any, as_json: bool, source: str, destination: str
) -> None:
    result = invoke(["cp", source, destination], as_json=as_json)

    assert_usage_error(result, router, ENDPOINT_ERROR, as_json=as_json)
    if as_json:
        assert json_error(result)["message"] == ENDPOINT_ERROR


# 4) a recursive download under a regular file gets the clean wording ---------------------------


@BOTH_MODES
@pytest.mark.parametrize("depth", ["child", "grandchild", "itself"])
def test_a_recursive_download_under_a_regular_file_says_it_is_not_a_directory(
    router: Any, tmp_path: Path, as_json: bool, depth: str
) -> None:
    blocker = tmp_path / "plain.txt"
    blocker.write_text("not a directory")
    destination = {
        "child": blocker / "out",
        "grandchild": blocker / "out" / "deeper",
        "itself": blocker,
    }[depth]

    result = invoke(["cp", "-r", f"{SID}:/w/dir", str(destination)], as_json=as_json)

    expected = f"destination {blocker} is not a directory"
    assert result.exit_code == USAGE, result.output
    assert router.calls.call_count == 0
    assert_no_traceback(result)
    if as_json:
        error = json_error(result)
        assert error["message"] == expected
        assert error["source"] == "client"
    else:
        assert result.stderr.strip() == f"error: {expected}"
    assert blocker.read_text() == "not a directory"


def test_the_single_file_download_uses_the_same_wording(router: Any, tmp_path: Path) -> None:
    blocker = tmp_path / "plain.txt"
    blocker.write_text("x")

    result = invoke(["cp", f"{SID}:/w/a.txt", str(blocker / "out.txt")])

    assert result.stderr.strip() == f"error: destination {blocker} is not a directory"


def test_the_post_lookup_dir_download_guard_names_the_file_in_the_way(tmp_path: Path) -> None:
    blocker = tmp_path / "plain.txt"
    blocker.write_text("x")

    with pytest.raises(CliError) as caught:
        cp_dir.download_dir(NoRequestSandbox(), "/w/dir", blocker / "out")  # type: ignore[arg-type]

    assert str(caught.value) == f"destination {blocker} is not a directory"
    assert "source" not in error_payload(caught.value)["error"]


def test_a_file_appearing_after_the_check_still_gets_the_clean_wording(tmp_path: Path) -> None:
    blocker = tmp_path / "late.txt"
    blocker.write_text("x")

    with pytest.raises(CliError) as caught:
        cp_dir.make_destination(blocker / "out")

    assert str(caught.value) == f"destination {blocker} is not a directory"
    assert os.strerror(ENOTDIR) not in str(caught.value)


def test_a_recursive_download_into_a_missing_directory_still_reaches_the_server(
    router: Any, tmp_path: Path
) -> None:
    result = invoke(["cp", "-r", f"{SID}:/w/dir", str(tmp_path / "new" / "out")])

    assert router.calls.call_count >= 1
    assert "is not a directory" not in result.output


# 5) a name miss carries the NOT_FOUND prefix in text mode --------------------------------------


@pytest.mark.parametrize(
    ("args", "exit_code"),
    [
        (["sandbox", "get", MISSING_NAME], EXIT_FAILURE),
        (["cp", f"{MISSING_NAME}:/w/a.txt", "out.txt"], PLATFORM_ERROR),
        (["preview", MISSING_NAME, "3000"], PLATFORM_ERROR),
    ],
    ids=["sandbox-get", "cp", "preview"],
)
def test_a_name_miss_starts_with_not_found_like_an_id_miss(
    router: Any, workdir: Path, args: list[str], exit_code: int
) -> None:
    result = invoke(args)

    assert result.exit_code == exit_code, result.output
    assert result.stderr.startswith(f"error: NOT_FOUND: {NAME_MISS}")
    assert "NOT_FOUND: NOT_FOUND" not in result.stderr


def test_an_id_miss_has_the_same_prefix(router: Any) -> None:
    result = invoke(["sandbox", "get", SID])

    assert result.exit_code == EXIT_FAILURE
    assert result.stderr.startswith("error: NOT_FOUND: ")


def test_a_json_name_miss_keeps_the_code_in_its_own_field(router: Any) -> None:
    result = invoke(["sandbox", "get", MISSING_NAME], as_json=True)

    error = json_error(result)
    assert result.exit_code == EXIT_FAILURE
    assert error["code"] == "NOT_FOUND"
    assert error["message"] == NAME_MISS
    assert "source" not in error


# 6) preview help states the port range ---------------------------------------------------------


def test_preview_help_states_the_port_range_the_client_enforces() -> None:
    result = invoke(["preview", "--help"])

    assert result.exit_code == 0
    assert f"Port in the sandbox, from {MIN_PREVIEW_PORT} to {MAX_PORT}." in flat(result.output)


@pytest.mark.parametrize("port", [str(MIN_PREVIEW_PORT - 1), str(MAX_PORT + 1)])
def test_a_port_outside_the_stated_range_is_refused(router: Any, port: str) -> None:
    result = invoke(["preview", SID, port])

    assert result.exit_code == USAGE
    assert f"from {MIN_PREVIEW_PORT} to {MAX_PORT}" in flat(result.stderr)
    assert router.calls.call_count == 0
