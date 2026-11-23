"""CLI round 45: three hardenings of the ``sandfort login`` probe.

* ``--verify-key`` makes one authenticated GET of the sandbox list with the key being saved:
  2xx prints a verified line, 403 saves with a limited-scope note, 401 fails the login.
  Without the flag the output says the key was NOT verified. With ``--no-verify`` it is a usage
  error.
* A malformed base url (an unclosed IPv6 bracket) is a clean client-side probe error.
* Userinfo in the base url is never sent (no Basic header), and echoed urls mask query values.
"""

import json
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
STATUS_BODY = {
    "success": True,
    "data": {"status": "ok", "version": "0.1.0", "build_sha": BUILD_SHA},
    "error": None,
    "meta": None,
}
RUNNER = CliRunner()


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


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
        yield mock


# --- --verify-key ----------------------------------------------------------------------------


def test_verify_key_prints_the_verified_line_after_one_authenticated_request(
    router: Any, profile_dir: Path
) -> None:
    status = router.get(STATUS_URL).respond(200, json=STATUS_BODY)
    listing = router.get(SANDBOXES_URL).respond(200, json={"success": True, "data": []})

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 0, result.output
    assert f"server {BASE}: build {BUILD_PREFIX}" in result.stdout
    assert "api key: verified" in result.stdout
    assert "NOT verified" not in result.stdout
    assert KEY not in result.output
    assert json.loads(profile_dir.read_text()) == {"base_url": BASE, "api_key": KEY}
    assert status.call_count == 1
    assert "authorization" not in status.calls.last.request.headers
    assert listing.call_count == 1
    assert listing.calls.last.request.headers["authorization"] == f"Bearer {KEY}"
    assert router.calls.call_count == 2
    assert router.calls[0].request.url.path == STATUS_URL
    assert router.calls[1].request.url.path == SANDBOXES_URL


def test_a_403_saves_the_profile_with_the_limited_scope_note(
    router: Any, profile_dir: Path
) -> None:
    router.get(STATUS_URL).respond(200, json=STATUS_BODY)
    router.get(SANDBOXES_URL).respond(403, json={"success": False})

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 0, result.output
    assert "the server answered 403" in result.stdout
    assert "the key is probably valid but lacks the sandbox read scope" in result.stdout
    assert "the key itself is valid" not in result.stdout
    assert json.loads(profile_dir.read_text()) == {"base_url": BASE, "api_key": KEY}


def test_a_401_fails_the_login_and_leaves_no_profile(router: Any, profile_dir: Path) -> None:
    router.get(STATUS_URL).respond(200, json=STATUS_BODY)
    router.get(SANDBOXES_URL).respond(401, json={"success": False})

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 1
    assert "rejected the api key" in result.stderr
    assert "HTTP 401" in result.stderr
    assert KEY not in result.output
    assert not profile_dir.exists()


def test_a_401_with_json_is_an_error_object_and_leaves_no_profile(
    router: Any, profile_dir: Path
) -> None:
    router.get(STATUS_URL).respond(200, json=STATUS_BODY)
    router.get(SANDBOXES_URL).respond(401)

    result = invoke(login_args("--verify-key"), as_json=True)

    assert result.exit_code == 1
    error = json.loads(result.stdout)["error"]
    assert "rejected the api key" in error["message"]
    assert "source" not in error
    assert not profile_dir.exists()


def test_a_failed_status_probe_sends_no_key_request(router: Any, profile_dir: Path) -> None:
    router.get(STATUS_URL).respond(404)
    listing = router.get(SANDBOXES_URL).respond(200, json={"data": []})

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 1
    assert "did not answer the status endpoint" in result.stderr
    assert listing.call_count == 0
    assert not profile_dir.exists()


def test_an_unexpected_key_check_status_does_not_save(router: Any, profile_dir: Path) -> None:
    router.get(STATUS_URL).respond(200, json=STATUS_BODY)
    router.get(SANDBOXES_URL).respond(500)

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 1
    assert "could not verify the api key" in result.stderr
    assert "HTTP 500" in result.stderr
    assert not profile_dir.exists()


def test_the_default_login_says_the_key_was_not_verified(router: Any, profile_dir: Path) -> None:
    router.get(STATUS_URL).respond(200, json=STATUS_BODY)
    listing = router.get(SANDBOXES_URL).respond(200, json={"data": []})

    result = invoke(login_args())

    assert result.exit_code == 0, result.output
    assert f"server {BASE}: build {BUILD_PREFIX}" in result.stdout
    assert "NOT verified" in result.stdout
    assert "--verify-key" in result.stdout
    assert listing.call_count == 0
    assert profile_dir.exists()


def test_json_login_keeps_stdout_to_one_object_with_the_profile_key(
    router: Any, profile_dir: Path
) -> None:
    router.get(STATUS_URL).respond(200, json=STATUS_BODY)

    result = invoke(login_args(), as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "profile": str(profile_dir),
        "key_verified": False,
        "key_status": "not-checked",
    }


def test_json_key_verified_is_true_after_a_2xx_verify(router: Any, profile_dir: Path) -> None:
    router.get(STATUS_URL).respond(200, json=STATUS_BODY)
    router.get(SANDBOXES_URL).respond(200, json={"data": []})

    result = invoke(login_args("--verify-key"), as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "profile": str(profile_dir),
        "key_verified": True,
        "key_status": "verified",
    }


def test_json_key_verified_is_limited_scope_after_a_403(router: Any, profile_dir: Path) -> None:
    router.get(STATUS_URL).respond(200, json=STATUS_BODY)
    # Only the server's own error envelope makes a 403 "limited-scope" (a bare 403 is a proxy).
    router.get(SANDBOXES_URL).respond(
        403, json={"success": False, "data": None, "error": {"code": "FORBIDDEN"}, "meta": None}
    )

    result = invoke(login_args("--verify-key"), as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "profile": str(profile_dir),
        "key_verified": "limited-scope",
        "key_status": "limited-scope",
        "missing_scopes": [],
        "missing_scopes_beyond_cap": 0,
        "request_id": None,
    }


def test_json_key_verified_is_false_with_no_verify(router: Any, profile_dir: Path) -> None:
    result = invoke(login_args("--no-verify"), as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "profile": str(profile_dir),
        "key_verified": False,
        "key_status": "not-checked",
    }
    assert router.calls.call_count == 0


def test_verify_key_together_with_no_verify_is_a_usage_error(
    router: Any, profile_dir: Path
) -> None:
    result = invoke(login_args("--verify-key", "--no-verify"))

    assert result.exit_code == 2
    assert "--verify-key" in result.output
    assert "--no-verify" in result.output
    assert router.calls.call_count == 0
    assert not profile_dir.exists()


@pytest.mark.parametrize(
    "flags", [["--verify-key", "--no-verify"], ["--no-verify", "--verify-key"]]
)
def test_the_flag_conflict_fails_before_any_prompt(
    flags: list[str], router: Any, profile_dir: Path
) -> None:
    result = RUNNER.invoke(
        create_app(None),
        ["login", "--api-key", KEY, *flags],
        input=f"{BASE}\n",
    )

    assert result.exit_code == 2
    assert "cannot be combined" in result.output
    assert "Base url" not in result.output
    assert router.calls.call_count == 0
    assert not profile_dir.exists()


# --- a malformed base url ---------------------------------------------------------------------


def test_an_unclosed_ipv6_bracket_is_a_clean_usage_error(profile_dir: Path) -> None:
    result = invoke(login_args(base="http://[::1"))

    assert result.exit_code == 2
    assert "is not a valid url" in result.stderr
    assert "check the url" in result.stderr
    assert "Traceback" not in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert KEY not in result.output
    assert not profile_dir.exists()


def test_an_unclosed_bracket_with_json_is_the_usage_error_object(profile_dir: Path) -> None:
    result = invoke(login_args(base="http://[::1"), as_json=True)

    assert result.exit_code == 2
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "USAGE_ERROR"
    assert error["source"] == "client"
    assert "check the url" in error["message"]
    assert not profile_dir.exists()


@pytest.mark.parametrize(
    "error",
    [httpx.UnsupportedProtocol("no host"), httpx.InvalidURL("bad url")],
    ids=["unsupported-protocol", "invalid-url"],
)
def test_never_sent_errors_carry_the_client_marker_in_json(
    router: Any, profile_dir: Path, error: Exception
) -> None:
    router.get(STATUS_URL).mock(side_effect=error)

    result = invoke(login_args(), as_json=True)

    assert result.exit_code == 1
    assert json.loads(result.stdout)["error"]["source"] == "client"
    assert not profile_dir.exists()


# --- userinfo is never sent -------------------------------------------------------------------


def test_userinfo_in_the_base_url_sends_no_authorization_header(
    router: Any, profile_dir: Path
) -> None:
    captured: list[dict[str, str]] = []

    def record(request: httpx.Request) -> httpx.Response:
        captured.append({name.lower(): value for name, value in request.headers.items()})
        return httpx.Response(200, json=STATUS_BODY)

    router.get(STATUS_URL).mock(side_effect=record)

    result = invoke(login_args(base="http://alice:hunter2@sandfort.test"))

    assert result.exit_code == 0, result.output
    assert len(captured) == 1
    assert "authorization" not in captured[0]
    assert "hunter2" not in result.output
    assert "alice" not in result.output
    assert f"server {BASE}: build {BUILD_PREFIX}" in result.stdout


def test_userinfo_is_stripped_from_the_requests_of_both_steps(router: Any) -> None:
    router.get(STATUS_URL).respond(200, json=STATUS_BODY)
    router.get(SANDBOXES_URL).respond(200, json={"data": []})

    result = invoke(login_args("--verify-key", base="http://alice:hunter2@sandfort.test"))

    assert result.exit_code == 0, result.output
    assert router.calls.call_count == 2
    for call in router.calls:
        assert call.request.url.userinfo == b""
    assert router.calls[0].request.headers.get("authorization") is None
    assert router.calls[1].request.headers["authorization"] == f"Bearer {KEY}"


# --- query values are masked ------------------------------------------------------------------


def test_query_values_are_masked_in_the_success_line(router: Any, profile_dir: Path) -> None:
    status = router.get(STATUS_URL).respond(200, json=STATUS_BODY)

    result = invoke(login_args(base=f"{BASE}?token=s3cret&team=blue"))

    assert result.exit_code == 0, result.output
    assert "s3cret" not in result.output
    assert "blue" not in result.output
    assert f"server {BASE}?token=***&team=***: build {BUILD_PREFIX}" in result.stdout
    assert status.calls.last.request.url.path == STATUS_URL
    assert status.calls.last.request.url.params["token"] == "s3cret"


def test_verify_key_keeps_the_base_url_query_and_adds_the_limit(
    router: Any, profile_dir: Path
) -> None:
    router.get(STATUS_URL).respond(200, json=STATUS_BODY)
    router.get(SANDBOXES_URL).respond(200, json={"data": []})

    result = invoke(login_args("--verify-key", base=f"{BASE}?token=s3cret&team=blue"))

    assert result.exit_code == 0, result.output
    assert router.calls.call_count == 2
    sent = router.calls[1].request.url
    assert sent.path == SANDBOXES_URL
    assert dict(sent.params.multi_items()) == {"token": "s3cret", "team": "blue", "limit": "1"}
    assert dict(router.calls[0].request.url.params.multi_items()) == {
        "token": "s3cret",
        "team": "blue",
    }


def test_query_values_are_masked_in_every_error_path(router: Any, profile_dir: Path) -> None:
    base = f"{BASE}?token=s3cret"
    router.get(STATUS_URL).mock(
        side_effect=httpx.ConnectError(f"cannot reach {base}/v1/status?token=s3cret")
    )

    text = invoke(login_args(base=base))
    as_json = invoke(login_args(base=base), as_json=True)

    for result in (text, as_json):
        assert result.exit_code == 1
        assert "s3cret" not in result.output
        assert "token=***" in result.output
        assert "did not answer the status endpoint" in result.output
    assert not profile_dir.exists()


def test_query_values_are_masked_when_the_key_is_rejected(router: Any, profile_dir: Path) -> None:
    router.get(STATUS_URL).respond(200, json=STATUS_BODY)
    router.get(SANDBOXES_URL).respond(401)

    result = invoke(login_args("--verify-key", base=f"{BASE}?token=s3cret"))

    assert result.exit_code == 1
    assert "s3cret" not in result.output
    assert "token=***" in result.stderr
    assert not profile_dir.exists()
