"""CLI round 51, batch 8: review follow-up.

* A name miss carries the request id of the list reply that showed it, in the json error and in
  the text line's tail.
* ``cmd logs`` relays program output through the same dangerous-sequence strip as ``exec``.
* The url fragment mask keeps a closing parenthesis on its own, without the output module.
* Low cleanups: the empty-name hint names ``<name>``, a non-object ``details`` keeps the error
  type of its actual status, a cut inside a nested list is counted, and ``rm --json`` still
  prints the processed refs when an unexpected exception stops the loop.
"""

import json
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SDK_SRC = ROOT / "sdk" / "python" / "src"
CLI_SRC = ROOT / "cli" / "src"
sys.path.insert(0, str(SDK_SRC))
sys.path.insert(0, str(CLI_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import cmd_cmd, config, sandboxes  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.output import describe_error, error_payload, relay_value  # noqa: E402
from sandfort_cli.sanitise import MAX_RELAYED_ENTRIES  # noqa: E402
from sandfort_sdk import ApiError, Conflict, InternalError, NotFound, SandboxInfo  # noqa: E402
from sandfort_sdk.models import LogEvent  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SANDBOXES_URL = "/v1/sandboxes"
LIST_REQUEST_ID = "req_list_r51h"
USAGE_EXIT = 2
RUNNER = CliRunner()
# A clipboard write (OSC 52) and a colour (CSI): the first must go, the second stays.
CLIPBOARD = "\x1b]52;c;cHduZWQ=\x07"
RED = "\x1b[31m"
RESET = "\x1b[0m"


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


class FakeTerminal:
    def require_interactive(self) -> None:
        return None


def invoke(args: list[str], *, as_json: bool = True) -> Any:
    app = create_app(FakeTerminal())  # type: ignore[arg-type]
    return RUNNER.invoke(app, (["--json"] if as_json else []) + args)


def flat(text: str) -> str:
    return " ".join(text.replace("│", " ").split())


# 1) a name miss carries the list reply's request id ------------------------------------------


@pytest.mark.parametrize("as_json", [True, False], ids=["json", "text"])
def test_a_name_miss_carries_the_request_id_of_the_list_reply(as_json: bool) -> None:
    empty = {"success": True, "data": [], "error": None, "meta": None}
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        router.get(SANDBOXES_URL).respond(
            200, json=empty, headers={"x-request-id": LIST_REQUEST_ID}
        )
        result = invoke(["snapshot", "create", "missing", "snap1"], as_json=as_json)

    assert result.exit_code == 1
    if as_json:
        error = json.loads(result.stdout)["error"]
        assert error["code"] == "NOT_FOUND"
        assert error["request_id"] == LIST_REQUEST_ID
    else:
        line = result.stderr.strip()
        assert line.startswith("error: NOT_FOUND: no sandbox named 'missing'")
        assert line.endswith(f"(request id {LIST_REQUEST_ID})")


# 2) cmd logs strips the dangerous sequences ---------------------------------------------------


class FakeProcess:
    def __init__(self, events: list[LogEvent]) -> None:
        self.events = events

    @contextmanager
    def follow_logs(self, session_id: str, command_id: str) -> Iterator[list[LogEvent]]:
        yield self.events


class FakeSandbox:
    def __init__(self, events: list[LogEvent]) -> None:
        self.process = FakeProcess(events)


def test_the_logs_follower_strips_clipboard_writes_from_both_streams(
    capsys: pytest.CaptureFixture[str],
) -> None:
    events = [
        LogEvent("stdout", 0, f"ok {CLIPBOARD}done\n"),
        LogEvent("stderr", 10, f"{RED}red{RESET} \x9d52;c;eA==\x9c\n"),
        LogEvent("exit", 20, exit_code=3, state="exited"),
    ]

    code = cmd_cmd.follow_to_exit_code(FakeSandbox(events), "ses", "cmd")  # type: ignore[arg-type]

    # click drops CSI colours itself when the stream is not a terminal, so only the text and
    # the absence of the string sequences are visible here.
    out = capsys.readouterr()
    assert code == 3
    assert out.out == "ok done\n"
    assert out.err == "red \n"
    for leaked in ("\x1b]", "\x9d", "52;c", "cHduZWQ", "eA=="):
        assert leaked not in out.out + out.err


# 3) the fragment mask keeps the parenthesis without the output module -------------------------


def test_the_fragment_mask_keeps_a_closing_paren_without_the_output_module(
    tmp_path: Path,
) -> None:
    code = (
        f"import sys; sys.path[:0] = [{str(SDK_SRC)!r}, {str(CLI_SRC)!r}]\n"
        "from sandfort_cli.sanitise import sanitise_text\n"
        "print(sanitise_text('unexpected extra argument (http://h.test/p#tok_secret)'))\n"
        "print('sandfort_cli.output' in sys.modules)\n"
    )

    done = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, cwd=tmp_path, check=False
    )

    assert done.returncode == 0, done.stderr
    assert done.stdout.splitlines() == [
        "unexpected extra argument (http://h.test/p#***)",
        "False",
    ]


# 4) low cleanups ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [["volume", "create", " "], ["snapshot", "create", "sbx_x", " "]],
    ids=["volume", "snapshot"],
)
def test_the_empty_name_hint_names_the_angle_placeholder(args: list[str]) -> None:
    result = invoke(args, as_json=False)

    shown = flat(result.stderr)
    assert result.exit_code == USAGE_EXIT
    assert "Invalid value for <name>: must not be empty" in shown
    assert "NAME" not in shown


def envelope_response(status: int, code: str, details: object) -> httpx.Response:
    error = {"code": code, "message": "nope", "details": details, "request_id": "req_1"}
    body = {"success": False, "data": None, "error": error, "meta": None}
    return httpx.Response(status, json=body)


@pytest.mark.parametrize(
    ("status", "code", "kind"),
    [(404, "NOT_FOUND", NotFound), (409, "CONFLICT", Conflict), (500, "WEIRD", ApiError)],
)
def test_a_non_object_details_keeps_the_type_of_its_actual_status(
    status: int, code: str, kind: type[ApiError]
) -> None:
    built = config.raw_details_error(envelope_response(status, code, ["a", "b"]))

    assert built is not None
    assert type(built) is kind
    assert built.status_code == status
    assert built.code == code
    assert built.details == ["a", "b"]
    assert built.request_id == "req_1"


def test_a_cut_inside_a_nested_list_is_counted_in_json_and_text() -> None:
    rows = [list(range(MAX_RELAYED_ENTRIES + 7)), ["short"]]
    exc = InternalError("boom", code="E", details={"rows": rows})

    cleaned, omitted = relay_value(rows, "")
    in_json = error_payload(exc)["error"]["details"]
    in_text = describe_error(exc)

    assert cleaned == [list(range(MAX_RELAYED_ENTRIES)), ["short"]]
    assert omitted == 7
    assert in_json["rows_beyond_cap"] == 7
    assert "and 7 more" in in_text and "rows_beyond_cap" not in in_text


class Deleted:
    def __init__(self, sandbox_id: str) -> None:
        self.info = SandboxInfo.from_payload(
            {"id": sandbox_id, "name": "demo", "state": "destroying"}
        )


class ExplodingClient:
    """Deletes the first sandbox, then fails with an error no handler expects."""

    def __init__(self) -> None:
        self.deleted: list[str] = []

    def delete(self, sandbox_id: str) -> Deleted:
        if self.deleted:
            raise RuntimeError("unexpected")
        self.deleted.append(sandbox_id)
        return Deleted(sandbox_id)


def test_rm_json_still_prints_the_processed_refs_after_an_unexpected_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = ExplodingClient()

    @contextmanager
    def opened() -> Iterator[ExplodingClient]:
        yield fake

    monkeypatch.setattr(sandboxes, "open_client", opened)

    result = invoke(["sandbox", "rm", "sbx_first", "sbx_second"])

    assert isinstance(result.exception, RuntimeError)
    document = json.loads(result.stdout)
    assert [entry["id"] for entry in document] == ["sbx_first"]
