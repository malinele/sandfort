"""CLI round 49, batch 2: closing the gaps BETWEEN the steps of the text sanitiser.

* The tail-drop (partial key, partial url after the raw cut) runs after the control and invisible
  characters are stripped, and also drops a trailing token holding a double slash.
* The raw userinfo masking treats the same whitespace class as the flattening step.
* A deeply nested json body is a non-envelope body, never a traceback.
* The caller's key is matched against partly percent-encoded forms; any key-shaped token from the
  server is masked.
* An echoed url longer than the raw bound is shortened with the ellipsis; a host longer than a
  hostname can be is rejected on every path.
* The limited-scope and strict 403 paths carry a request id from the envelope's meta or from the
  response header when the error has none.
"""

import json
import re
import sys
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
from sandfort_cli.output import ELLIPSIS, flatten_text  # noqa: E402
from sandfort_cli.sandboxes import (  # noqa: E402
    MASK,
    MAX_ECHOED_URL_CHARS,
    MAX_HOST_CHARS,
    MAX_RAW_CHARS,
    USERINFO_ACROSS_BREAKS_RE,
    drop_partial_url,
    echo_url,
    sanitise_text,
)
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
STATUS_URL = "/v1/status"
SANDBOXES_URL = "/v1/sandboxes"
BUILD_SHA = "4871ea2f0c9d1b3a5e7f8091a2b3c4d5e6f70812"
STATUS_BODY = {
    "success": True,
    "data": {"status": "ok", "version": "0.1.0", "build_sha": BUILD_SHA},
    "error": None,
    "meta": None,
}
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
TRACEBACK_MARKERS = ("Traceback", "RecursionError", "httpx.", 'File "')
JSON_HEADERS = {"content-type": "application/json"}
NESTED_BODY = b"[" * 200_000 + b"]" * 200_000
STRICT = "--require-verified"


def envelope(
    code: str,
    message: str,
    *,
    error_id: str | None = None,
    meta_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    error = {"code": code, "message": message, "details": details or {}, "request_id": error_id}
    meta = {"request_id": meta_id} if meta_id else None
    return {"success": False, "data": None, "error": error, "meta": meta}


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def login_args(*extra: str, base: str = BASE, key: str = KEY) -> list[str]:
    return ["login", "--base-url", base, "--api-key", key, *extra]


def flat(text: str) -> str:
    """``text`` without Rich box borders and line folds, for substring checks."""
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


def failure_message(result: Any, as_json: bool) -> str:
    """The failure text: the json error message on stdout, else the flattened stderr."""
    if as_json:
        return str(json.loads(result.stdout)["error"]["message"])
    return flat(str(result.stderr))


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


def cut_after(prefix: str, tail: str) -> str:
    """``prefix`` + invisible padding + ``tail`` where the raw cut lands inside ``tail``."""
    padding = "​" * (MAX_RAW_CHARS - len(prefix) - 1 - 24)
    return f"{prefix}{padding} {tail}"


# 1) the tail-drop runs after the strip, and covers a double slash -----------------------------


def test_an_escape_plus_space_inside_userinfo_at_the_cut_leaves_no_password_prefix() -> None:
    url = "http://admin:hun\x1b ter2secretpassword" + "x" * 60 + "@host.test/x"

    result = sanitise_text(cut_after("failed", url), base_url=BASE)

    assert "hun" not in result and "admin" not in result and "ter2" not in result


def test_a_scheme_relative_token_without_a_colon_at_the_cut_is_dropped() -> None:
    url = "//hunter2secretuser" + "x" * 60 + "@host.test/x"

    result = sanitise_text(cut_after("failed", url), base_url=BASE)

    assert "hunter" not in result and "//" not in result
    assert result.startswith("failed")


INTERLEAVERS = {
    "zero-width": "​",
    "bom": "﻿",
    "tag-char": "\U000e0001",
    "nul": "\x00",
    "bel": "\x07",
    "csi-sequence": "\x1b[0m",
    "osc-sequence": "\x1b]0;t\x07",
}


@pytest.mark.parametrize("filler", list(INTERLEAVERS.values()), ids=list(INTERLEAVERS))
def test_a_key_interleaved_with_hidden_characters_across_the_cut_leaves_no_prefix(
    filler: str,
) -> None:
    interleaved = filler.join(KEY) + filler
    padding = "​" * (MAX_RAW_CHARS - len(filler) * 8 - 8 - len("denied "))
    text = f"denied {padding}{interleaved}"
    assert len(text) > MAX_RAW_CHARS  # the raw cut lands inside the key

    result = sanitise_text(text, api_key=KEY)

    assert "sf_" not in result and "sf_te" not in result
    assert result.startswith("denied")


@pytest.mark.parametrize("filler", list(INTERLEAVERS.values()), ids=list(INTERLEAVERS))
def test_a_whole_key_interleaved_with_hidden_characters_is_masked(filler: str) -> None:
    result = sanitise_text(f"bad {filler.join(KEY)} now", api_key=KEY)

    assert result == f"bad {MASK} now"


def test_the_tail_token_with_a_complete_authority_is_kept() -> None:
    text = "failed at " + BASE + "/" + "p" * 50

    assert drop_partial_url(text) == text


@pytest.mark.parametrize(
    "tail",
    ["//user", "http://host:80", "user:pa", "http://a/b:http://user:pa", "x:y//z/w"],
    ids=["double-slash", "authority-port", "colon", "glued-urls", "colon-prefix"],
)
def test_the_tail_token_without_a_complete_authority_is_dropped(tail: str) -> None:
    assert drop_partial_url(f"failed at {tail}") == "failed at "


# 2) one whitespace class for the raw masking and the flattening --------------------------------

WHITESPACE = [char for char in map(chr, range(0x10000)) if char.isspace() and char != " "]


def test_the_raw_userinfo_pattern_and_the_flattening_step_agree_on_whitespace() -> None:
    assert len(WHITESPACE) >= 20
    for char in WHITESPACE:
        assert flatten_text(f"a{char}b") == "a b", repr(char)
        assert USERINFO_ACROSS_BREAKS_RE.match(f"http://u{char}p@h"), repr(char)


@pytest.mark.parametrize("char", ["\x0b", "\x0c", "\x1f", "\x85", "\xa0", " ", " "])
@pytest.mark.parametrize(
    "template",
    [
        "failed at http://admin:hun{c}ter2pw@host.test:80/x tail",
        "failed at //admin:hun{c}ter2pw@host.test/x tail",
    ],
    ids=["scheme", "scheme-relative"],
)
def test_a_separator_inside_a_password_is_removed(char: str, template: str) -> None:
    result = sanitise_text(template.format(c=char), base_url=BASE)

    assert "hun" not in result and "ter2pw" not in result and "admin" not in result
    assert "failed at" in result and "host.test" in result and "tail" in result


@BOTH_MODES
@pytest.mark.parametrize("char", ["\x0b", " "], ids=["vertical-tab", "paragraph-separator"])
def test_a_poisoned_server_message_with_a_separator_in_the_password_is_masked(
    router: Any, profile_dir: Path, as_json: bool, char: str
) -> None:
    message = f"see http://admin:hun{char}ter2pw@host.test/x"
    router.get(SANDBOXES_URL).respond(500, json=envelope("INTERNAL", message))

    result = invoke(login_args("--verify-key"), as_json=as_json)

    output = str(result.stdout if as_json else result.stderr)
    assert result.exit_code == 1
    assert "hun" not in output and "ter2pw" not in output and "admin" not in output


# 3) a deeply nested json body is a non-envelope body ------------------------------------------


@BOTH_MODES
def test_a_deeply_nested_status_body_is_not_a_status_document(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    router.get(STATUS_URL).respond(200, content=NESTED_BODY, headers=JSON_HEADERS)

    result = invoke(login_args(), as_json=as_json)

    output = str(result.stdout if as_json else result.stderr)
    assert result.exit_code == 1
    assert "the reply is not a status document" in flat(output)
    assert not any(marker in output for marker in TRACEBACK_MARKERS)
    assert not profile_dir.exists()


@BOTH_MODES
def test_a_deeply_nested_403_body_is_not_the_server_envelope(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    router.get(SANDBOXES_URL).respond(403, content=NESTED_BODY, headers=JSON_HEADERS)

    result = invoke(login_args("--verify-key"), as_json=as_json)

    assert result.exit_code == 0, result.output
    assert not any(marker in result.output for marker in TRACEBACK_MARKERS)
    assert profile_dir.exists()
    if as_json:
        assert json.loads(result.stdout)["key_status"] == "not-checked"
    else:
        assert "did not come from the server's API" in flat(result.stdout)


@BOTH_MODES
def test_a_deeply_nested_403_body_fails_the_strict_login_like_a_proxy_page(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    router.get(SANDBOXES_URL).respond(403, content=NESTED_BODY, headers=JSON_HEADERS)

    result = invoke(login_args(STRICT), as_json=as_json)

    output = str(result.stdout if as_json else result.stderr)
    assert result.exit_code == 1
    assert "did not come from the server's API" in flat(output)
    assert not any(marker in output for marker in TRACEBACK_MARKERS)
    assert not profile_dir.exists()


@BOTH_MODES
def test_a_deeply_nested_500_body_is_a_plain_failure(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    router.get(SANDBOXES_URL).respond(500, content=NESTED_BODY, headers=JSON_HEADERS)

    result = invoke(login_args("--verify-key"), as_json=as_json)

    output = str(result.stdout if as_json else result.stderr)
    assert result.exit_code == 1
    assert "HTTP 500" in flat(output)
    assert not any(marker in output for marker in TRACEBACK_MARKERS)
    assert not profile_dir.exists()


# 4) the key is matched against partly encoded forms; foreign key-shaped tokens ----------------

MIXED_FORMS = {
    "one-underscore": "sf%5Ftest_key_do_not_print",
    "mixed-case-hex": "sf%5Ftest_key%5fdo_not_print",
    "first-char": "%73f_test_key_do_not_print",
    "last-char": "sf_test_key_do_not_prin%74",
    "lower-and-upper": "%73%66%5f%74est_key_do_not_pri%6et",
}


@pytest.mark.parametrize("form", list(MIXED_FORMS.values()), ids=list(MIXED_FORMS))
def test_a_partly_or_mixed_case_encoded_key_is_masked(form: str) -> None:
    result = sanitise_text(f"denied for token {form} today", api_key=KEY)

    assert result == f"denied for token {MASK} today"


@pytest.mark.parametrize("form", list(MIXED_FORMS.values()), ids=list(MIXED_FORMS))
def test_a_partly_encoded_key_cut_in_half_by_the_raw_cut_leaves_no_prefix(form: str) -> None:
    half = form[: len(form) // 2]
    text = "denied " + "​" * (MAX_RAW_CHARS - 7 - len(half)) + form

    result = sanitise_text(text, api_key=KEY)

    assert "test" not in result and "sf_" not in result and "%5" not in result


FOREIGN_KEY = "sf_abcd1234_" + "A1b2C3d4" * 5 + "xyz"


def test_a_key_shaped_token_from_the_server_is_masked() -> None:
    result = sanitise_text(f"owner key {FOREIGN_KEY}, retry", api_key=KEY)

    assert result == f"owner key {MASK}, retry"


def test_short_sf_words_are_not_mistaken_for_keys() -> None:
    assert sanitise_text("the sf_ prefix and sf_short stay") == "the sf_ prefix and sf_short stay"


def test_a_foreign_key_tail_at_the_raw_cut_is_dropped() -> None:
    text = "denied " + "​" * (MAX_RAW_CHARS - 7 - 12) + FOREIGN_KEY

    result = sanitise_text(text)

    assert "sf_" not in result and "abcd" not in result


@BOTH_MODES
def test_a_key_shaped_token_in_a_relayed_message_is_masked(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    message = f"cannot use {FOREIGN_KEY} or {MIXED_FORMS['mixed-case-hex']}"
    router.get(SANDBOXES_URL).respond(500, json=envelope("INTERNAL", message))

    result = invoke(login_args("--verify-key"), as_json=as_json)

    output = str(result.stdout if as_json else result.stderr)
    assert result.exit_code == 1
    assert "abcd1234" not in output and "A1b2C3d4" not in output
    assert "do_not_print" not in output and "test_key" not in output


# 5) a long url echo ends with the ellipsis; a long host is rejected everywhere ----------------


def test_a_long_url_echo_is_shortened_with_the_ellipsis() -> None:
    shown = echo_url(BASE + "/" + "a" * (MAX_RAW_CHARS * 2), KEY)

    assert shown.endswith(ELLIPSIS) and len(shown) <= MAX_ECHOED_URL_CHARS
    assert shown.startswith(BASE)


def test_a_long_url_whose_authority_is_cut_off_echoes_the_ellipsis_not_nothing() -> None:
    assert echo_url("http://user:pw@" + "a" * (MAX_RAW_CHARS * 2), KEY) == ELLIPSIS


@BOTH_MODES
def test_a_long_url_in_an_invalid_url_message_is_shortened_before_the_reason(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    url = BASE + ":abc/" + "a" * (MAX_RAW_CHARS * 2)

    result = invoke(login_args("--no-verify", base=url), as_json=as_json)

    assert result.exit_code == 2
    message = failure_message(result, as_json)
    assert f"{ELLIPSIS} is not a valid url" in message and "invalid port" in message
    assert router.calls.call_count == 0
    assert not profile_dir.exists()


LONG_HOST = "http://" + "a" * (MAX_HOST_CHARS + 1) + ".test"


@BOTH_MODES
@pytest.mark.parametrize("extra", [(), ("--no-verify",)], ids=["verify", "no-verify"])
@pytest.mark.parametrize("host", [LONG_HOST, "http://" + "b" * 5000], ids=["long", "huge"])
def test_a_very_long_host_is_rejected_on_every_login_path(
    router: Any, profile_dir: Path, as_json: bool, extra: tuple[str, ...], host: str
) -> None:
    result = invoke(login_args(*extra, base=host), as_json=as_json)

    assert result.exit_code == 2, result.output
    message = failure_message(result, as_json)
    assert "is not a valid url" in message and f"longer than {MAX_HOST_CHARS}" in message
    assert router.calls.call_count == 0
    assert not profile_dir.exists()


def test_a_very_long_host_is_rejected_when_configured(
    monkeypatch: pytest.MonkeyPatch, router: Any
) -> None:
    monkeypatch.setenv(config.BASE_URL_ENV, LONG_HOST)
    monkeypatch.setenv(config.API_KEY_ENV, KEY)

    result = invoke(["sandbox", "list"], as_json=True)

    assert result.exit_code == 2
    assert f"longer than {MAX_HOST_CHARS}" in json.loads(result.stdout)["error"]["message"]
    assert router.calls.call_count == 0


def test_a_host_of_the_longest_valid_length_is_still_saved(router: Any, profile_dir: Path) -> None:
    host = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])
    assert len(host) == MAX_HOST_CHARS

    result = invoke(login_args("--no-verify", base=f"http://{host}"))

    assert result.exit_code == 0, result.output
    assert profile_dir.exists()


# 6) the 403 paths carry a request id from the meta or the header ------------------------------

ID_SOURCES = {
    "meta": ({"meta_id": "req-from-meta"}, {}, "req-from-meta"),
    "header": ({}, {"x-request-id": "req-from-header"}, "req-from-header"),
    "meta-beats-header": (
        {"meta_id": "req-from-meta"},
        {"x-request-id": "req-from-header"},
        "req-from-meta",
    ),
    "error-beats-both": (
        {"error_id": "req-from-error", "meta_id": "req-from-meta"},
        {"x-request-id": "req-from-header"},
        "req-from-error",
    ),
}


@BOTH_MODES
@pytest.mark.parametrize("case", list(ID_SOURCES))
def test_a_limited_scope_403_reports_the_request_id_from_any_level(
    router: Any, profile_dir: Path, as_json: bool, case: str
) -> None:
    ids, headers, expected = ID_SOURCES[case]
    body = envelope("FORBIDDEN", "missing scope", details={"missing_scopes": ["x:read"]}, **ids)
    router.get(SANDBOXES_URL).respond(403, json=body, headers=headers)

    result = invoke(login_args("--verify-key"), as_json=as_json)

    assert result.exit_code == 0, result.output
    if as_json:
        payload = json.loads(result.stdout)
        assert payload["key_status"] == "limited-scope" and payload["request_id"] == expected
    else:
        assert f"(request id {expected})" in flat(result.stdout)


@BOTH_MODES
@pytest.mark.parametrize("case", list(ID_SOURCES))
def test_a_strict_403_reports_the_request_id_from_any_level(
    router: Any, profile_dir: Path, as_json: bool, case: str
) -> None:
    ids, headers, expected = ID_SOURCES[case]
    router.get(SANDBOXES_URL).respond(
        403, json=envelope("FORBIDDEN", "missing scope", **ids), headers=headers
    )

    result = invoke(login_args(STRICT), as_json=as_json)

    assert result.exit_code == 1
    assert not profile_dir.exists()
    if as_json:
        error = json.loads(result.stdout)["error"]
        assert error["request_id"] == expected and error["details"]["request_id"] == expected
        assert f"(request id {expected})" in error["message"]
    else:
        assert f"(request id {expected})" in flat(result.stderr)


def test_a_header_request_id_is_sanitised_before_it_is_reported(
    router: Any, profile_dir: Path
) -> None:
    router.get(SANDBOXES_URL).respond(
        403,
        json=envelope("FORBIDDEN", "missing scope"),
        headers={"x-request-id": f"req-1 {KEY}"},
    )

    result = invoke(login_args("--verify-key"), as_json=True)

    assert result.exit_code == 0
    assert KEY not in result.stdout
    assert json.loads(result.stdout)["request_id"] == f"req-1 {MASK}"
