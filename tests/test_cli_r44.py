"""CLI round 44: ``sandfort login`` probes ``GET /v1/status`` before it saves the profile.

A base url that does not answer the status endpoint (connect error, non-2xx, a body that is not
the status document) fails the login with exit 1 and leaves the profile untouched. A good answer
saves the profile and prints ``server <base-url>: build <12-char prefix>``. ``--no-verify`` saves
without any request and says the url was not checked.
"""

import json
import sys
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
BUILD_SHA = "4871ea2f0c9d1b3a5e7f8091a2b3c4d5e6f70812"
BUILD_PREFIX = BUILD_SHA[:12]
RUNNER = CliRunner()


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def status_data(build_sha: str | None = BUILD_SHA) -> dict[str, Any]:
    return {
        "status": "ok",
        "version": "0.1.0",
        "build_sha": build_sha,
        "started_at": "2026-11-09T12:00:00Z",
        "notice": None,
    }


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def login_args(*extra: str) -> list[str]:
    return ["login", "--base-url", BASE, "--api-key", KEY, *extra]


@pytest.fixture(autouse=True)
def profile_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    return tmp_path / "cfg" / config.PROFILE_FILENAME


@pytest.fixture
def router() -> Any:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


# --- a status answer saves the profile -------------------------------------------------------


def test_a_status_answer_saves_the_profile_and_prints_the_build(
    router: Any, profile_dir: Path
) -> None:
    route = router.get(STATUS_URL).respond(200, json=envelope(status_data()))

    result = invoke(login_args())

    assert result.exit_code == 0, result.output
    assert f"server {BASE}: build {BUILD_PREFIX}" in result.stdout
    assert BUILD_SHA not in result.stdout
    assert KEY not in result.output
    assert json.loads(profile_dir.read_text()) == {"base_url": BASE, "api_key": KEY}
    assert route.call_count == 1
    assert "authorization" not in route.calls.last.request.headers


def test_a_status_without_a_build_still_logs_in(router: Any, profile_dir: Path) -> None:
    router.get(STATUS_URL).respond(200, json=envelope(status_data(None)))

    result = invoke(login_args())

    assert result.exit_code == 0, result.output
    assert f"server {BASE}: build unreported" in result.stdout
    assert profile_dir.exists()


def test_json_login_keeps_stdout_to_the_profile_object(router: Any, profile_dir: Path) -> None:
    router.get(STATUS_URL).respond(200, json=envelope(status_data()))

    result = invoke(login_args(), as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "profile": str(profile_dir),
        "key_verified": False,
        "key_status": "not-checked",
    }


# --- a url that does not answer is not saved -------------------------------------------------


def test_a_connect_error_fails_the_login_and_saves_nothing(router: Any, profile_dir: Path) -> None:
    router.get(STATUS_URL).mock(side_effect=httpx.ConnectError("name resolution failed"))

    result = invoke(login_args())

    assert result.exit_code == 1
    assert "did not answer the status endpoint" in result.stderr
    assert "name resolution failed" in result.stderr
    assert "check the url" in result.stderr
    assert KEY not in result.output
    assert not profile_dir.exists()


def test_a_404_fails_the_login_and_saves_nothing(router: Any, profile_dir: Path) -> None:
    router.get(STATUS_URL).respond(404, json={"detail": "Not Found"})

    result = invoke(login_args())

    assert result.exit_code == 1
    assert "did not answer the status endpoint" in result.stderr
    assert "HTTP 404" in result.stderr
    assert not profile_dir.exists()


@pytest.mark.parametrize(
    "reply",
    [
        httpx.Response(200, text="<html>welcome</html>"),
        httpx.Response(200, json=envelope({"status": "ok"})),
        httpx.Response(200, json=["not", "an", "object"]),
    ],
)
def test_a_body_that_is_not_the_status_shape_fails_the_login(
    router: Any, profile_dir: Path, reply: httpx.Response
) -> None:
    router.get(STATUS_URL).mock(return_value=reply)

    result = invoke(login_args())

    assert result.exit_code == 1
    assert "did not answer the status endpoint" in result.stderr
    assert not profile_dir.exists()


def test_a_failed_login_keeps_an_existing_profile(router: Any, profile_dir: Path) -> None:
    config.save_profile("http://old.test", "sf_old_key")
    before = profile_dir.read_text()
    router.get(STATUS_URL).respond(502)

    result = invoke(login_args())

    assert result.exit_code == 1
    assert "HTTP 502" in result.stderr
    assert profile_dir.read_text() == before


def test_json_connect_failure_is_the_client_error_object(router: Any, profile_dir: Path) -> None:
    router.get(STATUS_URL).mock(side_effect=httpx.ConnectError("connection refused"))

    result = invoke(login_args(), as_json=True)

    assert result.exit_code == 1
    error = json.loads(result.stdout)["error"]
    assert error["source"] == "client"
    assert "did not answer the status endpoint" in error["message"]
    assert "connection refused" in error["message"]
    assert KEY not in result.output
    assert not profile_dir.exists()


def test_json_http_failure_is_an_error_object_without_the_client_source(
    router: Any, profile_dir: Path
) -> None:
    router.get(STATUS_URL).respond(404)

    result = invoke(login_args(), as_json=True)

    assert result.exit_code == 1
    error = json.loads(result.stdout)["error"]
    assert "source" not in error
    assert "HTTP 404" in error["message"]
    assert not profile_dir.exists()


def test_userinfo_in_the_base_url_is_redacted_from_the_error(profile_dir: Path) -> None:
    secret_url = "http://alice:hunter2@sandfort.test"
    with respx.mock(assert_all_called=False) as mock:
        mock.get("http://sandfort.test/v1/status").mock(
            side_effect=httpx.ConnectError(f"cannot reach {secret_url}/v1/status")
        )

        text = invoke(["login", "--base-url", secret_url, "--api-key", KEY])
        as_json = invoke(["login", "--base-url", secret_url, "--api-key", KEY], as_json=True)

    for result in (text, as_json):
        assert result.exit_code == 1
        assert "hunter2" not in result.output
        assert "alice" not in result.output
        assert "did not answer the status endpoint" in result.output
    assert "http://sandfort.test" in text.stderr
    assert not profile_dir.exists()


def test_a_redirect_answer_says_redirects_are_not_followed(router: Any, profile_dir: Path) -> None:
    router.get(STATUS_URL).respond(301, headers={"location": "https://sandfort.test/v1/status"})

    result = invoke(login_args())

    assert result.exit_code == 1
    assert "HTTP 301" in result.stderr
    assert "redirects are not followed" in result.stderr
    assert "https" in result.stderr
    assert not profile_dir.exists()


# --- --no-verify -----------------------------------------------------------------------------


def test_no_verify_saves_without_any_request(router: Any, profile_dir: Path) -> None:
    result = invoke(login_args("--no-verify"))

    assert result.exit_code == 0, result.output
    assert f"server {BASE}: not checked" in result.stdout
    assert json.loads(profile_dir.read_text()) == {"base_url": BASE, "api_key": KEY}
    assert router.calls.call_count == 0


def test_no_verify_saves_even_when_the_server_would_not_answer(
    router: Any, profile_dir: Path
) -> None:
    router.get(STATUS_URL).mock(side_effect=httpx.ConnectError("down"))

    result = invoke(login_args("--no-verify"))

    assert result.exit_code == 0, result.output
    assert profile_dir.exists()
    assert router.calls.call_count == 0


# --- input validation still comes first ------------------------------------------------------


def test_bad_input_is_rejected_before_any_probe(router: Any, profile_dir: Path) -> None:
    scheme = invoke(["login", "--base-url", "sandfort.test", "--api-key", KEY])
    empty = invoke(["login", "--base-url", BASE, "--api-key", "   "])

    assert scheme.exit_code == 2
    assert empty.exit_code == 2
    assert router.calls.call_count == 0
    assert not profile_dir.exists()
