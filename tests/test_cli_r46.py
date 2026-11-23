"""CLI round 46: follow-ups on the ``sandfort login --verify-key`` flow.

* A failing or limited key check carries the server's error envelope (code, message, scopes,
  request id); a body that is not the envelope (a proxy page) is reported as an unchecked key.
* The json result has ``key_status`` (``verified``, ``limited-scope``, ``not-checked``) next to
  the unchanged ``key_verified``.
* Userinfo is removed from the saved profile url, fragments are masked in echoes, the scheme is
  case-insensitive, an unusable url is "not valid" (never "did not answer"), and ``--json``
  never prompts for a missing key.
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

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
STATUS_URL = "/v1/status"
SANDBOXES_URL = "/v1/sandboxes"
BUILD_SHA = "4871ea2f0c9d1b3a5e7f8091a2b3c4d5e6f70812"
BUILD_PREFIX = BUILD_SHA[:12]
REQUEST_ID = "req_r46_0123456789"
STATUS_BODY = {
    "success": True,
    "data": {"status": "ok", "version": "0.1.0", "build_sha": BUILD_SHA},
    "error": None,
    "meta": None,
}
RUNNER = CliRunner()


def envelope(code: str, message: str, *, details: dict[str, Any] | None = None) -> dict[str, Any]:
    """The server's error envelope, as ``sandfort.api.envelope.fail`` builds it."""
    error = {
        "code": code,
        "message": message,
        "details": details or {},
        "request_id": REQUEST_ID,
    }
    return {"success": False, "data": None, "error": error, "meta": None}


def invoke(args: list[str], *, as_json: bool = False, input_text: str | None = None) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args, input=input_text)


def flat(text: str) -> str:
    """``text`` without Rich box borders and line folds (a usage frame wraps long messages)."""
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


def login_args(*extra: str, base: str = BASE) -> list[str]:
    return ["login", "--base-url", base, "--api-key", KEY, *extra]


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


# --- the server's error envelope is carried through --------------------------------------------


def test_an_envelope_403_names_the_missing_scopes(router: Any, profile_dir: Path) -> None:
    body = envelope(
        "FORBIDDEN",
        "API key is missing required scope(s): sandboxes:read",
        details={"missing_scopes": ["sandboxes:read", "volumes:read"]},
    )
    router.get(SANDBOXES_URL).respond(403, json=body)

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 0, result.output
    assert "the server answered 403" in result.stdout
    assert "missing scope(s): sandboxes:read, volumes:read" in result.stdout
    assert f"(request id {REQUEST_ID})" in result.stdout
    assert "NOT verified" not in result.stdout
    assert json.loads(profile_dir.read_text()) == {"base_url": BASE, "api_key": KEY}


def test_an_envelope_403_is_limited_scope_in_both_json_fields(
    router: Any, profile_dir: Path
) -> None:
    router.get(SANDBOXES_URL).respond(403, json=envelope("FORBIDDEN", "no", details={}))

    result = invoke(login_args("--verify-key"), as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "profile": str(profile_dir),
        "key_verified": "limited-scope",
        "key_status": "limited-scope",
        "missing_scopes": [],
        "missing_scopes_beyond_cap": 0,
        "request_id": REQUEST_ID,
    }


def test_a_non_envelope_403_says_the_key_was_not_verified(router: Any, profile_dir: Path) -> None:
    router.get(SANDBOXES_URL).respond(403, text="<html><body>Forbidden by proxy</body></html>")

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 0, result.output
    assert "NOT verified" in result.stdout
    assert "did not come from the server's API" in result.stdout
    assert "lacks the sandbox read scope" not in result.stdout
    assert json.loads(profile_dir.read_text()) == {"base_url": BASE, "api_key": KEY}


def test_a_non_envelope_403_reports_not_checked_in_json(router: Any, profile_dir: Path) -> None:
    router.get(SANDBOXES_URL).respond(403, text="<html>Forbidden</html>")

    result = invoke(login_args("--verify-key"), as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "profile": str(profile_dir),
        "key_verified": False,
        "key_status": "not-checked",
    }


def test_an_envelope_401_carries_the_server_code_and_request_id_in_text(
    router: Any, profile_dir: Path
) -> None:
    router.get(SANDBOXES_URL).respond(401, json=envelope("UNAUTHORIZED", "invalid api key"))

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 1
    assert "rejected the api key" in result.stderr
    assert "UNAUTHORIZED" in result.stderr
    assert "invalid api key" in result.stderr
    assert result.stderr.count(REQUEST_ID) == 1
    assert KEY not in result.output
    assert not profile_dir.exists()


def test_an_envelope_401_carries_the_request_id_and_code_in_json(
    router: Any, profile_dir: Path
) -> None:
    router.get(SANDBOXES_URL).respond(401, json=envelope("UNAUTHORIZED", "invalid api key"))

    result = invoke(login_args("--verify-key"), as_json=True)

    assert result.exit_code == 1
    error = json.loads(result.stdout)["error"]
    assert error["request_id"] == REQUEST_ID
    assert error["details"] == {"server_code": "UNAUTHORIZED", "request_id": REQUEST_ID}
    assert "rejected the api key" in error["message"]
    assert "source" not in error
    assert not profile_dir.exists()


def test_a_401_without_an_envelope_keeps_empty_details(router: Any, profile_dir: Path) -> None:
    router.get(SANDBOXES_URL).respond(401, text="nope")

    result = invoke(login_args("--verify-key"), as_json=True)

    assert result.exit_code == 1
    error = json.loads(result.stdout)["error"]
    assert error["details"] == {}
    assert error["request_id"] is None


def test_a_422_quotes_the_server_message_and_does_not_say_retry(
    router: Any, profile_dir: Path
) -> None:
    router.get(SANDBOXES_URL).respond(
        422, json=envelope("VALIDATION_ERROR", "query parameter 'team' is not allowed")
    )

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 1
    assert "HTTP 422" in result.stderr
    assert "VALIDATION_ERROR: query parameter 'team' is not allowed" in result.stderr
    assert REQUEST_ID in result.stderr
    assert "check the base url" in result.stderr
    assert "retry" not in result.stderr
    assert not profile_dir.exists()


def test_a_500_still_suggests_a_retry(router: Any, profile_dir: Path) -> None:
    router.get(SANDBOXES_URL).respond(500, json=envelope("INTERNAL_ERROR", "boom"))

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 1
    assert "INTERNAL_ERROR: boom" in result.stderr
    assert "retry or login without --verify-key" in result.stderr


@pytest.mark.parametrize("status", [408, 429])
def test_a_408_or_429_gets_the_retry_advice(router: Any, profile_dir: Path, status: int) -> None:
    router.get(SANDBOXES_URL).respond(status, json=envelope("RATE_LIMITED", "slow down"))

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 1
    assert f"HTTP {status}" in result.stderr
    assert "retry or login without --verify-key" in result.stderr
    assert "check the base url" not in result.stderr
    assert not profile_dir.exists()


def test_a_redirect_on_the_verify_call_gets_the_redirect_hint(
    router: Any, profile_dir: Path
) -> None:
    router.get(SANDBOXES_URL).respond(302, headers={"Location": "https://sandfort.test/x"})

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 1
    assert "HTTP 302" in result.stderr
    assert "redirects are not followed" in result.stderr
    assert "final url" in result.stderr
    assert not profile_dir.exists()


def test_a_server_message_does_not_leak_a_url_secret(router: Any, profile_dir: Path) -> None:
    echo = envelope("VALIDATION_ERROR", f"bad request {BASE}{SANDBOXES_URL}?token=s3cret")
    router.get(SANDBOXES_URL).respond(422, json=echo)

    result = invoke(login_args("--verify-key", base=f"{BASE}?token=s3cret"))

    assert result.exit_code == 1
    assert "s3cret" not in result.output


def test_a_hash_reference_in_a_server_message_survives(router: Any, profile_dir: Path) -> None:
    router.get(SANDBOXES_URL).respond(422, json=envelope("VALIDATION_ERROR", "see issue #123"))

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 1
    assert "see issue #123" in result.stderr


def test_userinfo_in_the_middle_of_a_server_message_is_masked(
    router: Any, profile_dir: Path
) -> None:
    echo = envelope("UPSTREAM", "cannot reach http://alice:hunter2@internal.test/x#frag-secret")
    router.get(SANDBOXES_URL).respond(502, json=echo)

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 1
    for secret in ("alice", "hunter2", "frag-secret"):
        assert secret not in result.output
    assert "cannot reach http://internal.test/x#***" in result.stderr


def test_userinfo_in_a_transport_error_is_masked(router: Any, profile_dir: Path) -> None:
    router.get(SANDBOXES_URL).mock(
        side_effect=httpx.ConnectError("cannot reach http://alice:hunter2@other.test/path")
    )

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 1
    assert "hunter2" not in result.output
    assert "alice" not in result.output
    assert "cannot reach http://other.test/path" in result.stderr


# --- key_status ----------------------------------------------------------------------------------


def test_key_status_is_verified_after_a_2xx(router: Any, profile_dir: Path) -> None:
    router.get(SANDBOXES_URL).respond(200, json={"success": True, "data": []})

    result = invoke(login_args("--verify-key"), as_json=True)

    assert json.loads(result.stdout) == {
        "profile": str(profile_dir),
        "key_verified": True,
        "key_status": "verified",
    }


@pytest.mark.parametrize("extra", [[], ["--no-verify"]], ids=["default", "no-verify"])
def test_key_status_is_not_checked_without_a_key_check(
    router: Any, profile_dir: Path, extra: list[str]
) -> None:
    result = invoke(login_args(*extra), as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "profile": str(profile_dir),
        "key_verified": False,
        "key_status": "not-checked",
    }


# --- userinfo is removed from the saved profile ------------------------------------------------


def test_userinfo_is_stripped_from_the_saved_profile_with_one_note(
    router: Any, profile_dir: Path
) -> None:
    router.get(SANDBOXES_URL).respond(200, json={"success": True, "data": []})

    result = invoke(login_args("--verify-key", base="http://alice:hunter2@sandfort.test"))

    assert result.exit_code == 0, result.output
    saved = json.loads(profile_dir.read_text())
    assert saved == {"base_url": BASE, "api_key": KEY}
    assert "hunter2" not in profile_dir.read_text()
    assert "alice" not in profile_dir.read_text()
    assert result.stdout.count("userinfo was removed from the saved base url") == 1
    assert "hunter2" not in result.output
    assert "alice" not in result.output


def test_no_userinfo_note_without_userinfo(router: Any, profile_dir: Path) -> None:
    result = invoke(login_args())

    assert result.exit_code == 0, result.output
    assert "userinfo was removed" not in result.stdout


def test_userinfo_is_stripped_with_no_verify_too(profile_dir: Path) -> None:
    result = invoke(login_args("--no-verify", base="http://alice:hunter2@sandfort.test"))

    assert result.exit_code == 0, result.output
    assert json.loads(profile_dir.read_text())["base_url"] == BASE
    assert "userinfo was removed" in result.stdout


# --- fragment, scheme case, invalid urls ---------------------------------------------------------


def test_the_fragment_is_masked_in_echoed_urls(router: Any, profile_dir: Path) -> None:
    result = invoke(login_args(base=f"{BASE}?team=blue#frag-secret"))

    assert result.exit_code == 0, result.output
    assert "frag-secret" not in result.output
    assert "blue" not in result.output
    assert f"server {BASE}?team=***#***: build {BUILD_PREFIX}" in result.stdout


def test_the_fragment_is_masked_in_error_paths(router: Any, profile_dir: Path) -> None:
    router.get(STATUS_URL).respond(404)

    result = invoke(login_args(base=f"{BASE}#frag-secret"))

    assert result.exit_code == 1
    assert "frag-secret" not in result.output
    assert "#***" in result.stderr


@pytest.mark.parametrize("scheme", ["HTTP", "Http", "hTTp"])
def test_an_uppercase_or_mixed_case_scheme_is_accepted_and_normalised(
    router: Any, profile_dir: Path, scheme: str
) -> None:
    result = invoke(login_args(base=f"{scheme}://sandfort.test"))

    assert result.exit_code == 0, result.output
    assert f"server {BASE}: build {BUILD_PREFIX}" in result.stdout
    assert json.loads(profile_dir.read_text())["base_url"] == BASE


def test_a_missing_scheme_is_still_rejected(profile_dir: Path) -> None:
    result = invoke(login_args(base="sandfort.test"))

    assert result.exit_code == 2
    assert "must start with http:// or https://" in result.stderr
    assert not profile_dir.exists()


@pytest.mark.parametrize("base", ["http://[::1", "http://sandfort.test:abc"])
def test_an_unusable_url_is_not_valid_rather_than_unanswered(profile_dir: Path, base: str) -> None:
    result = invoke(login_args(base=base))

    assert result.exit_code == 2
    assert "is not a valid url" in flat(result.stderr)
    assert "did not answer" not in flat(result.stderr)
    assert "nothing was sent" in flat(result.stderr)
    assert not profile_dir.exists()


def test_an_unusable_url_is_a_client_error_in_json(profile_dir: Path) -> None:
    result = invoke(login_args(base="http://sandfort.test:abc"), as_json=True)

    assert result.exit_code == 2
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "USAGE_ERROR"
    assert error["source"] == "client"
    assert "is not a valid url" in error["message"]
    assert "did not answer" not in error["message"]


@pytest.mark.parametrize("flags", [[], ["--no-verify"]], ids=["verify", "no-verify"])
@pytest.mark.parametrize("base", ["http://user@", "http://user:pw@", "http://:8080"])
def test_a_url_with_no_host_is_not_valid(
    router: Any, profile_dir: Path, base: str, flags: list[str]
) -> None:
    result = invoke(login_args(*flags, base=base))

    assert result.exit_code == 2
    assert "is not a valid url" in flat(result.stderr)
    assert "nothing was sent" in flat(result.stderr)
    assert "pw" not in result.output
    assert not profile_dir.exists()


# --- defensive envelope parsing ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "status", "expected"),
    [
        (["not", "an", "object"], 403, "NOT verified"),
        ({"success": False, "error": "boom"}, 403, "the server answered 403"),
        ({"success": False, "error": {"details": ["x"]}}, 403, "the server answered 403"),
        (
            {"success": False, "error": {"details": {"missing_scopes": "volumes:read"}}},
            403,
            "the server answered 403",
        ),
        ([1, 2], 401, "rejected the api key"),
        ({"success": False, "error": "boom"}, 401, "rejected the api key"),
        ({"success": False, "error": {"details": 7}}, 500, "retry or login"),
    ],
    ids=[
        "403-list-body",
        "403-error-not-object",
        "403-details-not-dict",
        "403-scopes-not-list",
        "401-list-body",
        "401-error-not-object",
        "500-details-not-dict",
    ],
)
def test_a_malformed_envelope_degrades_gracefully(
    router: Any, profile_dir: Path, body: Any, status: int, expected: str
) -> None:
    router.get(SANDBOXES_URL).respond(status, json=body)

    result = invoke(login_args("--verify-key"))

    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Traceback" not in result.output
    assert expected in result.output
    assert "missing scope" not in result.output
    assert result.exit_code == (0 if status == 403 else 1)


# --- json mode never prompts ---------------------------------------------------------------------


def test_json_mode_without_an_api_key_is_one_json_usage_error(
    router: Any, profile_dir: Path
) -> None:
    result = invoke(["login", "--base-url", BASE], as_json=True)

    assert result.exit_code == 2
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "USAGE_ERROR"
    assert "--api-key" in error["message"]
    assert config.API_KEY_ENV in error["message"]
    assert "Api key" not in result.stdout
    assert router.calls.call_count == 0
    assert not profile_dir.exists()


def test_json_mode_without_a_base_url_is_one_json_usage_error(profile_dir: Path) -> None:
    result = invoke(["login", "--api-key", KEY], as_json=True)

    assert result.exit_code == 2
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "USAGE_ERROR"
    assert "--base-url" in error["message"]
    assert "Base url" not in result.stdout
    assert not profile_dir.exists()


def test_text_mode_still_prompts_for_a_missing_api_key(profile_dir: Path) -> None:
    result = invoke(["login", "--base-url", BASE, "--no-verify"], input_text=f"{KEY}\n")

    assert result.exit_code == 0, result.output
    assert "Api key" in result.stdout
    assert KEY not in result.stdout
    assert json.loads(profile_dir.read_text()) == {"base_url": BASE, "api_key": KEY}
