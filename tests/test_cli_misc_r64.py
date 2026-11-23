"""CLI review r64: sanitiser residuals, login error sources, profile mode warning, plain error
names, U+FFFC refused as a name."""

import json
import re
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
import typer  # noqa: E402
from sandfort_cli import config, login_key  # noqa: E402
from sandfort_cli.error_hints import plain_error_names  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.output import describe_error, error_payload, reject_empty_name  # noqa: E402
from sandfort_cli.sanitise import mask_fragments, mask_queries, sanitise_text  # noqa: E402
from sandfort_sdk.exceptions import TransportError  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
TOKEN = "Zq7Kx9Wp3RtN8vB2mYc4HdF6"
KEY = "sf_live_Zq7Kx9Wp3RtN8vB2mYc4HdF6"
USAGE = 2
RUNNER = CliRunner()
LOGIN = ["login", "--base-url", BASE, "--no-verify"]


def invoke(args: list[str], *, input_text: str | None = None, as_json: bool = False) -> Any:
    argv = (["--json"] if as_json else []) + args
    return RUNNER.invoke(create_app(None), argv, input=input_text)


def flat(text: str) -> str:
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    for name in (config.BASE_URL_ENV, config.API_KEY_ENV, config.API_KEY_FILE_ENV):
        monkeypatch.delenv(name, raising=False)
    config._warned_profile_paths.clear()


def masked(line: str) -> str:
    return sanitise_text(line, api_key="", limit=10_000)


# 1a) one ASCII symbol between a CJK word and a host ------------------------------------------

ASCII_SYMBOLS = list("!$%&)+\\]^}")


@pytest.mark.parametrize("symbol", ASCII_SYMBOLS)
@pytest.mark.parametrize("marker", ["?token=", "#access_token=", "?a=1&token="])
def test_a_host_after_a_cjk_word_and_one_ascii_symbol_is_masked(symbol: str, marker: str) -> None:
    line = f"你好{symbol}host.test{marker}{TOKEN}"

    assert TOKEN not in masked(line)
    assert "host.test" in masked(line)


def test_the_reviewed_cjk_line_is_masked() -> None:
    assert masked(f"你好!host.test?token={TOKEN}") == "你好!host.test?token=***"


# 1b) the # form after IDNA dots, connectors and angle brackets -------------------------------

FRAGMENT_LEADS = ["｡", "．", "‥", "﹏", "＜", "＞", "﹤", "﹥", "。"]


@pytest.mark.parametrize("lead", FRAGMENT_LEADS)
@pytest.mark.parametrize("prefix", ["你好", "abc", "x", "你好，"])
def test_a_fragment_after_these_marks_is_masked(lead: str, prefix: str) -> None:
    line = f"{prefix}{lead}host.test#access_token={TOKEN}&state=ok"

    for result in (masked(line), mask_fragments(line)):
        assert TOKEN not in result
        assert "host" in result


@pytest.mark.parametrize("dot", ["｡", "．", "‥", "。"])
def test_an_idna_dot_inside_a_host_after_a_sentence_comma_keeps_the_host(dot: str) -> None:
    line = f"你好，host{dot}test#tok={TOKEN}"

    assert TOKEN not in masked(line)
    assert TOKEN not in mask_fragments(line)
    assert TOKEN not in mask_queries(line.replace("#", "?"))


def test_ordinary_prose_with_these_marks_is_not_masked() -> None:
    assert masked("你好！再见") == "你好！再见"
    assert masked("a＜b ＞ c") == "a＜b ＞ c"


@pytest.mark.parametrize("unit", ["你好!a。b#", "!?x。#", "。,", "＜＞﹏a.b#c?d=1"])
def test_the_new_separators_keep_the_time_linear(unit: str) -> None:
    def seconds(size: int) -> float:
        text = unit * (size // len(unit))
        started = time.perf_counter()
        masked(text)
        return time.perf_counter() - started

    seconds(2000)
    small, large = seconds(20_000), seconds(80_000)
    assert large < max(0.5, small * 12)


# 1c) any Unicode space inside a key ----------------------------------------------------------

SPACES = [" ", " ", " ", " ", "　", " ", " ", " ", "\t"]


@pytest.mark.parametrize("space", SPACES, ids=lambda char: f"U+{ord(char):04X}")
@pytest.mark.parametrize("at", [3, 10, 20])
def test_a_space_inside_the_callers_key_does_not_leak_it(space: str, at: int) -> None:
    line = f"error {KEY[:at]}{space}{KEY[at:]} end"

    result = sanitise_text(line, api_key=KEY, limit=1000)

    assert result == "error *** end"
    assert KEY[at:] not in result


# 2) login error texts ------------------------------------------------------------------------


def test_key_stdin_with_empty_stdin_names_stdin_not_key_file() -> None:
    result = invoke([*LOGIN, "--key-stdin"], input_text="")

    text = flat(result.stderr)
    assert result.exit_code == USAGE
    assert "--key-stdin was given but stdin holds no api key" in text
    assert "--key-file" not in text


def test_key_stdin_with_empty_stdin_in_json_mode_names_stdin() -> None:
    result = invoke([*LOGIN, "--key-stdin"], input_text="", as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == USAGE
    assert "stdin holds no api key" in error["message"]
    assert "--key-file" not in error["message"]


@pytest.mark.parametrize("flag", [["--key-stdin"], []], ids=["flag", "implicit"])
def test_a_malformed_stdin_key_names_stdin_in_a_full_sentence(flag: list[str]) -> None:
    result = invoke([*LOGIN, *flag], input_text="sf_a b\n")

    text = flat(result.stderr)
    assert result.exit_code == USAGE
    assert f"the api key read from stdin {config.MALFORMED_KEY_MESSAGE}" in text
    assert "--api-key" not in text
    assert "sf_a b" not in result.output


def test_a_stdin_key_that_is_not_text_names_stdin() -> None:
    result = RUNNER.invoke(create_app(None), LOGIN, input=b"sf_secret\xff\xfe\n")

    text = flat(result.stderr)
    assert result.exit_code == USAGE
    assert f"the api key read from stdin {config.MALFORMED_KEY_MESSAGE}" in text
    assert "--api-key" not in text


def test_a_malformed_key_in_the_environment_names_the_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(config.API_KEY_ENV, "sf_a b")
    monkeypatch.setattr(login_key, "stdin_is_tty", lambda: True)

    result = invoke(LOGIN)

    text = flat(result.stderr)
    assert result.exit_code == USAGE
    assert f"the api key in {config.API_KEY_ENV} {config.MALFORMED_KEY_MESSAGE}" in text
    assert "--api-key" not in text


def test_a_malformed_key_in_the_key_file_names_the_option(tmp_path: Path) -> None:
    path = tmp_path / "key.txt"
    path.write_text("sf_a b\n")
    path.chmod(0o600)

    result = invoke([*LOGIN, "--key-file", str(path)])

    text = flat(result.stderr)
    assert result.exit_code == USAGE
    assert f"the api key in the --key-file file {config.MALFORMED_KEY_MESSAGE}" in text


def test_a_malformed_key_in_the_key_file_variable_names_the_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "key.txt"
    path.write_text("sf_a b\n")
    path.chmod(0o600)
    monkeypatch.setenv(config.API_KEY_FILE_ENV, str(path))
    monkeypatch.setattr(login_key, "stdin_is_tty", lambda: True)

    result = invoke(LOGIN)

    text = flat(result.stderr)
    assert result.exit_code == USAGE
    assert config.API_KEY_FILE_ENV in text
    assert f"the api key in the file named by {config.API_KEY_FILE_ENV} " in text


# 3) a profile that others can read -----------------------------------------------------------


def write_profile(mode: int) -> Path:
    path = config.save_profile(BASE, "sf_profile_key_value_123")
    path.chmod(mode)
    return path


def test_a_profile_with_mode_644_warns_once_with_the_chmod_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = write_profile(0o644)

    first = config.resolve_settings()
    config.resolve_settings()

    err = capsys.readouterr().err
    assert first.base_url == BASE  # the profile is used
    assert err.count("warning:") == 1
    assert f"chmod 600 {path}" in err
    assert "mode 644" in err
    assert "sf_profile_key_value_123" not in err


def test_a_profile_with_mode_600_does_not_warn(capsys: pytest.CaptureFixture[str]) -> None:
    write_profile(0o600)

    config.resolve_settings()

    assert capsys.readouterr().err == ""


def test_the_profile_warning_reaches_stderr_of_a_command() -> None:
    write_profile(0o640)
    with respx.mock(base_url=BASE) as router:
        router.get("/v1/sandboxes").mock(
            return_value=httpx.Response(200, json={"data": [], "next_cursor": None})
        )
        result = invoke(["sandbox", "list"])

    assert "chmod 600" in result.stderr
    assert "chmod 600" not in result.stdout


# 4) plain words instead of Python class names ------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "plain"),
    [
        ("cannot read /tmp/x: IsADirectoryError", "cannot read /tmp/x: is a directory"),
        (
            "reading the response stream failed: RemoteProtocolError: peer closed connection",
            "reading the response stream failed: the server broke the connection: "
            "peer closed connection",
        ),
        ("request failed: ReadTimeout", "request failed: timed out waiting for the server"),
        ("httpx.ConnectError: boom", "could not connect to the server: boom"),
        ("a sandbox named MyCustomError", "a sandbox named MyCustomError"),
    ],
)
def test_python_class_names_become_plain_words(raw: str, plain: str) -> None:
    assert plain_error_names(raw) == plain


def test_an_error_line_and_json_error_have_no_class_names() -> None:
    exc = TransportError("reading the response stream failed: RemoteProtocolError: peer closed")

    line = describe_error(exc)
    message = error_payload(exc)["error"]["message"]

    for shown in (line, message):
        assert "RemoteProtocolError" not in shown
        assert "peer closed" in shown


def test_a_cli_error_with_a_class_name_is_plain() -> None:
    from sandfort_cli.output import CliError

    assert "IsADirectoryError" not in describe_error(CliError("cannot read x: IsADirectoryError"))


# 5) U+FFFC is an invisible name --------------------------------------------------------------


@pytest.mark.parametrize("name", ["￼", "￼￼", " ￼ ", "​￼"])
def test_a_name_of_only_the_object_replacement_character_is_refused(name: str) -> None:
    with pytest.raises(typer.BadParameter):
        reject_empty_name(name)


def test_the_object_replacement_character_is_refused_before_a_request() -> None:
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        router.route().mock(return_value=httpx.Response(404, json={}))
        write_profile(0o600)
        result = invoke(["sandbox", "rm", "￼"])

        assert router.calls.call_count == 0
    assert result.exit_code == USAGE
