"""CLI round 53, batch v: blank remote path in ``cp``, preview token matching, build-log fidelity.

* ``cp`` with an empty, whitespace-only or invisible-only REMOTE path (the part after
  ``<sandbox>:``) is a usage error like a blank local path: exit 2, one ``USAGE_ERROR`` document
  under ``--json``, no request, in both directions.
* ``preview`` text output puts the token back into the url by the known parameter name
  (``sandfort_preview_token``), never by comparing values. When the sanitiser would alter the
  token (or the url cannot carry it), the exact token is printed on its own ``token:`` line;
  ``--json`` is unchanged.
* ``snapshot build`` log lines are program output: dangerous terminal sequences are removed,
  nothing is masked, whitespace and indentation are kept, no length cut.
"""

import json
import re
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import cmd_cmd, config, snapshot  # noqa: E402
from sandfort_cli.cmd_cmd import TOKEN_PARAM, preview_url, preview_view  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.output import shown  # noqa: E402
from sandfort_sdk import BuildLogEvent  # noqa: E402
from sandfort_sdk.models import PreviewInfo  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
USAGE = 2
RUNNER = CliRunner()
EXPIRES = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
PLAIN_TOKEN = "pvt_AbC123xyz"
# Key-shaped: the sanitiser masks it, so it is "altered" and must never be spliced into a url.
ALTERED_TOKEN = "sf_" + "A" * 24
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
BLANK_REMOTE_PATHS = pytest.mark.parametrize(
    "blank", ["", "   ", "\t", "​"], ids=["empty", "spaces", "tab", "zero-width"]
)
RECURSIVE = pytest.mark.parametrize("recursive", [False, True], ids=["file", "recursive"])
EMPTY_LIST_ENVELOPE = {"success": True, "data": [], "error": None, "meta": None}


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def flat(text: str) -> str:
    """Text without the box-drawing frame, whitespace collapsed."""
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def router() -> Iterator[Any]:
    """Every request is counted; the sandbox list is empty, anything else is a 404."""
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        mock.get("/v1/sandboxes").mock(return_value=httpx.Response(200, json=EMPTY_LIST_ENVELOPE))
        mock.route().mock(return_value=httpx.Response(404, json={"success": False}))
        yield mock


# 1) a blank remote path is a usage error in both directions -----------------------------------


def assert_usage_error(result: Any, router: Any, expected: str, *, as_json: bool) -> None:
    assert result.exit_code == USAGE, result.output
    assert router.calls.call_count == 0
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


@BOTH_MODES
@BLANK_REMOTE_PATHS
@RECURSIVE
def test_a_download_from_a_blank_remote_path_is_a_usage_error(
    router: Any, tmp_path: Path, as_json: bool, blank: str, recursive: bool
) -> None:
    destination = tmp_path / "out"
    args = ["cp", *(["-r"] if recursive else []), f"{SID}:{blank}", str(destination)]

    result = invoke(args, as_json=as_json)

    assert_usage_error(
        result, router, "Invalid value for <source>: must not be empty", as_json=as_json
    )
    assert not destination.exists()


@BOTH_MODES
@BLANK_REMOTE_PATHS
@RECURSIVE
def test_an_upload_to_a_blank_remote_path_is_a_usage_error(
    router: Any, tmp_path: Path, as_json: bool, blank: str, recursive: bool
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a").write_text("alpha")
    source = tree if recursive else tree / "a"
    args = ["cp", *(["-r"] if recursive else []), str(source), f"{SID}:{blank}"]

    result = invoke(args, as_json=as_json)

    assert_usage_error(
        result, router, "Invalid value for <destination>: must not be empty", as_json=as_json
    )


# 2) preview: the token is found by its parameter name -----------------------------------------


class FakeSandbox:
    state = "started"

    def __init__(self, url: str, token: str) -> None:
        self._info = PreviewInfo(url=url, token=token, port=3000, expires_at=EXPIRES)

    def preview(self, port: int, *, ttl_seconds: int | None = None) -> PreviewInfo:
        return self._info


def serve_preview(monkeypatch: pytest.MonkeyPatch, url: str, token: str) -> None:
    sandbox = FakeSandbox(url, token)

    @contextmanager
    def opened() -> Iterator[Any]:
        yield SimpleNamespace(get=lambda sandbox_id: sandbox)

    monkeypatch.setattr(cmd_cmd, "open_client", opened)


def preview_run(*, as_json: bool = False) -> Any:
    result = invoke(["preview", SID, "3000"], as_json=as_json)
    assert result.exit_code == 0, result.output
    return result


def test_the_token_is_put_back_by_parameter_name_not_by_the_first_equal_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = f"http://3000-{SID}.preview.test/?a={PLAIN_TOKEN}&{TOKEN_PARAM}={PLAIN_TOKEN}"
    serve_preview(monkeypatch, url, PLAIN_TOKEN)

    text = preview_run().stdout
    document = json.loads(preview_run(as_json=True).stdout)

    for printed in (text.strip(), document["url"]):
        assert f"{TOKEN_PARAM}={PLAIN_TOKEN}" in printed
        assert f"a={PLAIN_TOKEN}" not in printed  # the other pair stays masked
    assert text.count("\n") == 1  # the url alone: it carries the token, no extra line
    assert document["token"] == PLAIN_TOKEN


def test_a_url_that_cannot_carry_the_token_gets_the_exact_token_on_its_own_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = f"http://3000-{SID}.preview.test/?other={PLAIN_TOKEN}"
    serve_preview(monkeypatch, url, PLAIN_TOKEN)

    lines = preview_run().stdout.splitlines()

    assert f"other={PLAIN_TOKEN}" not in lines[0]
    assert lines[1] == f"token: {PLAIN_TOKEN}"
    assert len(lines) == 2


def test_an_altered_token_is_shown_exactly_in_text_and_json_and_never_spliced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert shown(ALTERED_TOKEN, KEY) != ALTERED_TOKEN  # the premise: the sanitiser alters it
    url = f"http://3000-{SID}.preview.test/?{TOKEN_PARAM}={ALTERED_TOKEN}"
    serve_preview(monkeypatch, url, ALTERED_TOKEN)

    lines = preview_run().stdout.splitlines()
    document = json.loads(preview_run(as_json=True).stdout)

    assert ALTERED_TOKEN not in lines[0]  # the url line is the masked one
    assert lines[1] == f"token: {ALTERED_TOKEN}"
    assert document["token"] == ALTERED_TOKEN
    assert ALTERED_TOKEN not in document["url"]  # json url unchanged: masked


def test_a_token_with_control_characters_is_never_printed_raw_in_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "pvt_ab\x1b[31mcd"
    url = f"http://3000-{SID}.preview.test/?{TOKEN_PARAM}={token}"
    serve_preview(monkeypatch, url, token)

    result = preview_run()
    document = json.loads(preview_run(as_json=True).stdout)

    assert "\x1b" not in result.stdout and "\x1b" not in result.stderr
    assert document["token"] == token


def test_preview_view_reports_whether_the_url_carries_the_token() -> None:
    carrying = f"http://h.test/?{TOKEN_PARAM}={PLAIN_TOKEN}&x=1"

    url, carried = preview_view(carrying, PLAIN_TOKEN, KEY)
    other, other_carried = preview_view(f"http://h.test/?q={PLAIN_TOKEN}", PLAIN_TOKEN, KEY)

    assert carried and url == preview_url(carrying, PLAIN_TOKEN, KEY)
    assert f"{TOKEN_PARAM}={PLAIN_TOKEN}" in url and "x=1" not in url
    assert not other_carried and PLAIN_TOKEN not in other


# 3) snapshot build log lines are program output -----------------------------------------------


class FakeLogStream:
    def __init__(self, events: list[BuildLogEvent]) -> None:
        self._events = events

    def __enter__(self) -> "FakeLogStream":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def __iter__(self) -> Iterator[BuildLogEvent]:
        return iter(self._events)


def follow(lines: list[str], *, echo: bool = True) -> BuildLogEvent:
    final = BuildLogEvent(kind="state", state="ready", snapshot_id="snap_1")
    events = [BuildLogEvent(kind="log", line=line, index=i) for i, line in enumerate(lines)]
    client = SimpleNamespace(
        snapshots=SimpleNamespace(follow_build_logs=lambda _id: FakeLogStream([*events, final]))
    )
    return snapshot.follow_build(client, SimpleNamespace(id="snap_1"), echo_lines=echo)  # type: ignore[arg-type]


def test_build_log_lines_lose_dangerous_sequences_but_keep_whitespace_and_content(
    capsys: pytest.CaptureFixture[str],
) -> None:
    follow(["    step \x1b]0;title\x07done  ", "\x1b]52;c;ZXZpbA==\x07payload"])

    assert capsys.readouterr().out == "    step done  \npayload\n"


def test_build_log_lines_are_not_masked(capsys: pytest.CaptureFixture[str]) -> None:
    secret_like = "sf_" + "B" * 24
    line = f"fetching https://user:pw@host.test/a?token=abc with {secret_like}"

    follow([line])

    assert capsys.readouterr().out == line + "\n"


def test_build_log_lines_are_not_cut(capsys: pytest.CaptureFixture[str]) -> None:
    line = "x" * 20000

    follow([line])

    assert capsys.readouterr().out == line + "\n"


def test_json_mode_prints_no_build_log_lines(capsys: pytest.CaptureFixture[str]) -> None:
    follow(["line one"], echo=False)

    assert capsys.readouterr().out == ""
