"""CLI round 48: hardening of the shared sanitiser.

* The sanitiser runs in bounded time on hostile text (the raw text is cut before any pattern).
* Missing scopes are capped, Unicode tag characters are stripped, a control character inside a
  url password cannot leave a password prefix, the url-encoded api key is masked.
* A negative port is an invalid url (nothing sent); a long url in a json usage error does not
  cut away the reason; probe failures go through the sanitiser; the ``--require-verified`` 403
  error carries the server code.
"""

import json
import re
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote, quote_plus

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.sandboxes import (  # noqa: E402
    BARE_USERINFO_RE,
    MASK,
    MAX_ECHOED_URL_CHARS,
    MAX_RAW_CHARS,
    MAX_RELAYED_CHARS,
    MAX_RELAYED_SCOPES,
    USERINFO_ANYWHERE_RE,
    probe_failure,
    sanitise_text,
)
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
STATUS_URL = "/v1/status"
SANDBOXES_URL = "/v1/sandboxes"
BUILD_SHA = "4871ea2f0c9d1b3a5e7f8091a2b3c4d5e6f70812"
REQUEST_ID = "req_r48_0123456789"
STATUS_BODY = {
    "success": True,
    "data": {"status": "ok", "version": "0.1.0", "build_sha": BUILD_SHA},
    "error": None,
    "meta": None,
}
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
# Generous so a slow CI runner cannot flake; the bounded work takes milliseconds.
TIME_BUDGET_S = 1.0


def envelope(code: str, message: str, *, details: dict[str, Any] | None = None) -> dict[str, Any]:
    error = {
        "code": code,
        "message": message,
        "details": details or {},
        "request_id": REQUEST_ID,
    }
    return {"success": False, "data": None, "error": error, "meta": None}


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def login_args(*extra: str, base: str = BASE, key: str = KEY) -> list[str]:
    return ["login", "--base-url", base, "--api-key", key, *extra]


def failure_output(result: Any, as_json: bool) -> str:
    """Where a failed login reports: the json object on stdout, else stderr."""
    return str(result.stdout if as_json else result.stderr)


@pytest.fixture(autouse=True)
def profile_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    return tmp_path / "cfg" / config.PROFILE_FILENAME


@pytest.fixture
def router() -> Iterator[Any]:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        mock.get(STATUS_URL).respond(200, json=STATUS_BODY)
        yield mock


# 1) bounded running time ---------------------------------------------------------------------

HOSTILE_SHAPES = {
    "single-run": "a" * 200_000,
    "colon-pairs": "a:" * 100_000,
    "at-pairs": "a@" * 100_000,
    "colon-at": "@a:" * 70_000,
    "scheme-run": "http://" + "a" * 200_000,
    "scheme-repeat": "://" * 70_000,
    "query-run": "?" * 200_000,
    "osc-run": "\x1b]" * 100_000,
    "digit-letter": "a1" * 100_000,
    "userinfo-long": "http://u:" + "p" * 200_000,
    # The passes added since round 48: percent-decoding, url-ish query context, string
    # sequences that never end and the matching view through combining marks.
    "percent-run": "%" * 200_000,
    "percent-escapes": "%25" * 70_000,
    "percent-key-escapes": "sf%5F" + "%41" * 70_000,
    "word-question-word": "a?b" * 70_000,
    "word-question-pairs": "x?k=" * 50_000,
    "string-introducers": "\x1bP" * 100_000,
    "c1-introducers": "\x9d\x90" * 100_000,
    # Round 54: three views per mask (as written, matching, displayed), span widening over
    # terminal sequences, word-based query and fragment masks across breaks, masks until stable.
    "hidden-in-key-run": "sf_live_ab12cd34_Qw3r​" * 9_000,
    "sequence-in-key-run": "sf_live_ab12\x1b[0mcd34" * 10_000,
    "esc-question-run": "h.t/p\x1b?k=v" * 20_000,
    "esc-hash-run": "h.t/p\x1b#f" * 25_000,
    "osc-at-hash-in-password": "http://u:p\t\x1b]x@y# \x07" * 10_000,
    "idn-question-run": "ä.ö?" * 50_000,
    "joiner-question-run": "a‍?" * 70_000,
    "hash-run": "#" * 200_000,
    "host-hash-pairs": "a.b#" * 50_000,
    "query-across-breaks": "h.t?k=v\t" * 25_000,
    "lone-surrogates": "\ud800" * 200_000,
    "open-string-escapes": "\x1b]?k\x1b" * 40_000,
    "mark-run": "́" * 200_000,
    "marked-word-run": "á" * 100_000,
}


@pytest.mark.parametrize("text", list(HOSTILE_SHAPES.values()), ids=list(HOSTILE_SHAPES))
def test_sanitising_a_huge_hostile_string_finishes_within_the_budget(text: str) -> None:
    started = time.perf_counter()
    result = sanitise_text(text, base_url=BASE, api_key=KEY)
    elapsed = time.perf_counter() - started

    assert elapsed < TIME_BUDGET_S
    assert len(result) <= MAX_RELAYED_CHARS


def test_the_200000_character_single_run_is_cut_before_the_patterns_run() -> None:
    started = time.perf_counter()
    result = sanitise_text("x" * 200_000)
    elapsed = time.perf_counter() - started

    assert elapsed < TIME_BUDGET_S
    assert result.endswith("…") and len(result) == MAX_RELAYED_CHARS


def test_a_cut_raw_text_ends_in_an_ellipsis_even_when_little_survives() -> None:
    text = "ok " + "​" * (MAX_RAW_CHARS * 2)

    assert sanitise_text(text) == "ok…"
    assert sanitise_text("​" * (MAX_RAW_CHARS * 2)) == ""


@pytest.mark.parametrize("separator", ["", " see "], ids=["glued", "spaced"])
def test_a_credential_url_cut_by_the_raw_cut_leaves_no_password_prefix(separator: str) -> None:
    url = "http://admin:hunter2secretpassword" + "x" * 60 + "@host.test/x"
    padding = "\u200b" * (MAX_RAW_CHARS - len(separator) - 30)
    text = "failed" + padding + separator + url

    result = sanitise_text(text, base_url=BASE)

    assert "hunter" not in result and "admin" not in result and "secret" not in result
    # Glued to the padding, the whole token goes; spaced, the words before the url survive.
    assert result == ("failed see…" if separator else "")


def test_a_credential_url_cut_across_a_line_break_leaves_no_password_prefix() -> None:
    url = "http://admin:hunter2\nsecretpassword" + "x" * 60 + "@host.test/x"
    text = "failed " + "\u200b" * (MAX_RAW_CHARS - 40) + url

    result = sanitise_text(text, base_url=BASE)

    assert "hunter" not in result and "secret" not in result and "admin" not in result


def test_a_cut_that_lands_after_a_plain_word_keeps_it() -> None:
    text = "failed plainword " + "y" * (MAX_RAW_CHARS * 2)

    result = sanitise_text(text)

    assert result.startswith("failed plainword y")


def test_an_api_key_cut_in_half_by_the_raw_cut_leaves_no_prefix() -> None:
    text = "​" * (MAX_RAW_CHARS - 6) + KEY

    result = sanitise_text(text, api_key=KEY)

    assert "sf_" not in result


@pytest.mark.parametrize(
    "pattern", [BARE_USERINFO_RE, USERINFO_ANYWHERE_RE], ids=["bare", "scheme"]
)
@pytest.mark.parametrize("text", list(HOSTILE_SHAPES.values()), ids=list(HOSTILE_SHAPES))
def test_the_userinfo_patterns_alone_are_linear_on_hostile_text(pattern: Any, text: str) -> None:
    started = time.perf_counter()
    pattern.sub("", text)

    assert time.perf_counter() - started < TIME_BUDGET_S


@pytest.mark.parametrize(
    ("text", "gone", "kept"),
    [
        ("see http://admin:hunter2@host.test:80/x", "hunter2", "host.test:80/x"),
        ("see 1http://admin:hunter2@host.test/x", "hunter2", "host.test/x"),
        ("see //admin:hunter2@host.test/x", "hunter2", "host.test/x"),
        ("see admin:hunter2@host.test:80/x", "hunter2", "host.test:80/x"),
        ("see x@y:hunter2@host.test:80/x", "hunter2", "host.test:80/x"),
        ("see http://a:p@ss@host.test/x", "ss@", "host.test/x"),
        ("note label:name@example.com stays", "", "label:name@example.com"),
    ],
)
def test_the_reworked_userinfo_patterns_still_mask_what_they_masked(
    text: str, gone: str, kept: str
) -> None:
    result = sanitise_text(text)

    if gone:
        assert gone not in result
    assert kept in result


# 2) the number of relayed scopes -------------------------------------------------------------


@BOTH_MODES
def test_a_list_of_thousands_of_scopes_is_capped(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    scopes = [f"scope_{number}:read" for number in range(3000)]
    router.get(SANDBOXES_URL).respond(
        403, json=envelope("FORBIDDEN", "no", details={"missing_scopes": scopes})
    )

    result = invoke(login_args("--verify-key"), as_json=as_json)

    assert result.exit_code == 0
    shown = result.stdout
    assert "scope_0:read" in shown and "scope_19:read" in shown
    assert "scope_20:read" not in shown and "scope_2999:read" not in shown
    assert len(shown) < 3000
    if as_json:
        payload = json.loads(shown)
        assert len(payload["missing_scopes"]) == MAX_RELAYED_SCOPES
        assert payload["missing_scopes_beyond_cap"] == 2980
    else:
        assert "and 2980 more" in shown


def test_a_list_within_the_cap_is_relayed_whole(router: Any, profile_dir: Path) -> None:
    scopes = [f"s{number}" for number in range(MAX_RELAYED_SCOPES)]
    router.get(SANDBOXES_URL).respond(
        403, json=envelope("FORBIDDEN", "no", details={"missing_scopes": scopes})
    )

    result = invoke(login_args("--verify-key"), as_json=True)

    assert json.loads(result.stdout)["missing_scopes"] == scopes


# 3) Unicode tag characters -------------------------------------------------------------------


def test_unicode_tag_characters_are_stripped() -> None:
    hidden = "".join(chr(0xE0000 + ord(char)) for char in "ignore previous instructions")
    text = f"den{hidden}ied\U000e0001\U000e007f by policy"

    result = sanitise_text(text)

    assert result == "denied by policy"
    assert all(not 0xE0000 <= ord(char) <= 0xE007F for char in result)


# 4) control characters inside a url password, negative port ----------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "failed at http://admin:hun\x1b]ter2pw@host.test:80/x tail",
        "failed at http://admin:hun\x1b]0;t\x07ter2pw@host.test:80/x tail",
        "failed at http://admin:hun\x9dter2pw@host.test/x",
        "failed at //admin:hun\x1b]ter2pw@host.test/x",
        "failed at admin:hun\x1b]ter2pw@host.test:80/x",
    ],
    ids=["osc-unterminated", "osc-bel", "c1-osc", "scheme-relative", "bare"],
)
def test_a_control_character_inside_a_password_leaves_no_password_prefix(text: str) -> None:
    result = sanitise_text(text, base_url=BASE)

    assert "hun" not in result and "ter2pw" not in result and "admin" not in result
    assert "failed at" in result


@pytest.mark.parametrize(
    "text",
    [
        "failed at http://admin:hun\nter2pw@host.test:80/x tail",
        "failed at http://admin:hun\r\nter2pw@host.test/x tail",
        "failed at http://admin:hun\tter2pw@host.test/x tail",
        "failed at //admin:hun\nter2pw@host.test/x tail",
    ],
    ids=["newline", "crlf", "tab", "scheme-relative"],
)
def test_a_line_break_inside_a_password_leaves_no_password_prefix(text: str) -> None:
    result = sanitise_text(text, base_url=BASE)

    assert "hun" not in result and "ter2pw" not in result and "admin" not in result
    assert "failed at" in result and "host.test" in result and "tail" in result


def test_a_line_break_between_words_still_becomes_a_space() -> None:
    assert sanitise_text("first line\nsecond\tline") == "first line second line"


@BOTH_MODES
def test_a_poisoned_server_message_with_a_control_char_password_is_masked(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    message = "see http://admin:hun\x1b]ter2pw@host.test/x"
    router.get(SANDBOXES_URL).respond(500, json=envelope("INTERNAL", message))

    result = invoke(login_args("--verify-key"), as_json=as_json)

    output = failure_output(result, as_json)
    assert result.exit_code == 1
    assert "hun" not in output and "ter2pw" not in output


@BOTH_MODES
@pytest.mark.parametrize(
    "url",
    [
        "http://sandfort.test:-1",
        "http://sandfort.test:-80/path",
        "https://sandfort.test:-65536",
        "http://[::1]:-5",
        "http://user:pw8@sandfort.test:-9",
    ],
    ids=["minus-one", "minus-with-path", "large", "ipv6", "userinfo"],
)
def test_a_negative_port_is_an_invalid_url_and_nothing_is_sent(
    router: Any, profile_dir: Path, as_json: bool, url: str
) -> None:
    result = invoke(login_args(base=url), as_json=as_json)

    output = failure_output(result, as_json)
    assert result.exit_code == 2
    assert router.calls.call_count == 0
    assert not profile_dir.exists()
    flat_output = " ".join(re.sub(r"[│╭╮╰╯─]", " ", output).split())
    assert "is not a valid url" in flat_output and "port out of range" in flat_output
    assert "did not answer" not in output and "pw8" not in output
    if as_json:
        error = json.loads(output)["error"]
        assert error["source"] == "client" and error["code"] == "USAGE_ERROR"


# 5) the url-encoded api key ------------------------------------------------------------------

ODD_KEY = "sf_a+b/c=de&f%g"


def lower_hex(text: str) -> str:
    return re.sub(r"%[0-9A-F]{2}", lambda match: match.group(0).lower(), text)


@pytest.mark.parametrize(
    "form",
    [
        ODD_KEY,
        quote(ODD_KEY),
        quote(ODD_KEY, safe=""),
        quote_plus(ODD_KEY),
        lower_hex(quote(ODD_KEY, safe="")),
    ],
    ids=["exact", "quote", "quote-all", "quote-plus", "lower-hex"],
)
def test_the_url_encoded_form_of_the_api_key_is_masked(form: str) -> None:
    result = sanitise_text(f"denied for token {form} today", api_key=ODD_KEY)

    assert result == f"denied for token {MASK} today"


def percent_5f(text: str) -> str:
    return text.replace("_", "%5F")


@pytest.mark.parametrize(
    "form",
    [
        percent_5f(KEY),
        lower_hex(percent_5f(KEY)),
        "".join(f"%{byte:02X}" for byte in KEY.encode()),
        "".join(f"%{byte:02x}" for byte in KEY.encode()),
    ],
    ids=["underscore-5F", "underscore-5f", "every-byte", "every-byte-lower"],
)
def test_the_fully_percent_encoded_key_is_masked(form: str) -> None:
    result = sanitise_text(f"denied for token {form} today", api_key=KEY)

    assert result == f"denied for token {MASK} today"


def test_a_key_with_unreserved_punctuation_is_masked_fully_encoded() -> None:
    key = "sf_a-b.c~d_e"
    form = "sf%5Fa%2Db%2Ec%7Ed%5Fe"

    assert sanitise_text(f"token={form} denied", api_key=key) == f"token={MASK} denied"


def test_the_url_encoded_key_is_masked_in_a_relayed_message(router: Any, profile_dir: Path) -> None:
    encoded = quote(ODD_KEY, safe="")
    router.get(SANDBOXES_URL).respond(
        500, json=envelope("INTERNAL", f"bad request GET /x?token={encoded}")
    )

    result = invoke(login_args("--verify-key", key=ODD_KEY))

    assert result.exit_code == 1
    assert encoded not in result.stderr and "a%2Bb" not in result.stderr


# 6) a long url in a json usage error ---------------------------------------------------------


def test_a_long_url_in_a_json_usage_error_keeps_the_reason() -> None:
    url = "ftp://" + "h" * 1000 + ".example.test/path"

    result = invoke(login_args(base=url), as_json=True)

    assert result.exit_code == 2
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "USAGE_ERROR"
    assert "unsupported scheme, it must start with http:// or https://" in error["message"]
    assert "nothing was sent, check the url" in error["message"]
    assert "h" * (MAX_ECHOED_URL_CHARS + 1) not in error["message"]
    assert "…" in error["message"]


def test_a_short_url_in_a_json_usage_error_is_echoed_whole() -> None:
    result = invoke(login_args(base="ftp://files.example.test/x"), as_json=True)

    message = json.loads(result.stdout)["error"]["message"]
    assert "ftp://files.example.test/x" in message and "…" not in message


# 7) probe failures go through the sanitiser --------------------------------------------------


@BOTH_MODES
def test_a_url_with_control_characters_is_a_usage_error_echoed_stripped(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    url = f"{BASE}/a\x1b[31mred\x07b?token={KEY}"

    result = invoke(login_args(base=url), as_json=as_json)

    output = " ".join(re.sub(r"[│╭╮╰╯─]", " ", failure_output(result, as_json)).split())
    assert result.exit_code == 2
    assert router.calls.call_count == 0
    assert all(char not in result.output for char in "\x1b\x07")
    assert KEY not in result.output
    assert "is not a valid url" in output and "nothing was sent" in output


def test_a_did_not_answer_message_is_sanitised() -> None:
    url = f"{BASE}/p?token={KEY}"
    reason = f"connect failed \x1b[31mred\x1b[0m for {url} key {KEY}\nsecond line"

    error = probe_failure(url, reason, never_sent=True, api_key=KEY)

    text = str(error)
    assert "did not answer" in text
    assert all(char not in text for char in "\x1b\n")
    assert KEY not in text and "token=sf" not in text
    assert "connect failed" in text and "second line" in text


def test_an_invalid_url_message_is_sanitised() -> None:
    url = f"http://user:pw9@host.test/\x1b]0;t\x07x?k={KEY}"
    reason = f"Invalid port \x9b31m in {url}"

    error = probe_failure(url, reason, never_sent=True, invalid=True, api_key=KEY)

    text = str(error)
    assert "is not a valid url" in text and "nothing was sent" in text
    assert all(char not in text for char in "\x1b\x9b\x07")
    assert KEY not in text and "pw9" not in text


def test_a_transport_error_reason_with_the_key_is_masked_in_text_mode(
    router: Any, profile_dir: Path
) -> None:
    router.get(STATUS_URL).mock(
        side_effect=httpx.ConnectError(f"refused \x1b[31m{KEY}\x1b[0m\r\nline two")
    )

    result = invoke(login_args())

    assert result.exit_code == 1
    assert KEY not in result.stderr and "\x1b" not in result.stderr
    assert "refused" in result.stderr


# 8) --require-verified 403 carries the server code -------------------------------------------


@BOTH_MODES
def test_require_verified_403_details_carry_the_server_code(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    router.get(SANDBOXES_URL).respond(
        403,
        json=envelope("FORBIDDEN", "no", details={"missing_scopes": ["sandboxes:read"]}),
    )

    result = invoke(login_args("--require-verified"), as_json=as_json)

    assert result.exit_code == 1
    assert not profile_dir.exists()
    if as_json:
        details = json.loads(result.stdout)["error"]["details"]
        assert details["server_code"] == "FORBIDDEN"
        assert details["key_status"] == "limited-scope"
        assert details["missing_scopes"] == ["sandboxes:read"]
        assert details["request_id"] == REQUEST_ID
    else:
        assert "missing scope(s): sandboxes:read" in " ".join(result.stderr.split())


def test_require_verified_403_server_code_is_sanitised(router: Any, profile_dir: Path) -> None:
    router.get(SANDBOXES_URL).respond(403, json=envelope(f"BAD\x1b]0;t\x07CODE {KEY}", "no"))

    result = invoke(login_args("--require-verified"), as_json=True)

    details = json.loads(result.stdout)["error"]["details"]
    assert details["server_code"] == f"BADCODE {MASK}"
    assert KEY not in result.stdout and "\x1b" not in result.stdout


def test_require_verified_non_envelope_403_has_no_server_code(
    router: Any, profile_dir: Path
) -> None:
    router.get(SANDBOXES_URL).respond(403, text="<html>login</html>")

    result = invoke(login_args("--require-verified"), as_json=True)

    details = json.loads(result.stdout)["error"]["details"]
    assert details["key_status"] == "not-checked"
    assert "server_code" not in details
