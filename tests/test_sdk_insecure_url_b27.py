"""B27 addendum: the SDK warns when an http:// base url to a remote host would send the key."""

import sys
import warnings
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import sandfort_sdk  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_sdk import AsyncClient, Client, InsecureBaseUrlWarning  # noqa: E402
from sandfort_sdk.insecure_url import insecure_host, warn_if_insecure_base_url  # noqa: E402

KEY = "sf_env_key_do_not_print"
REMOTE_HTTP = "http://sandfort.test"
LOOPBACK_HTTP = "http://127.0.0.1:8000"
INSECURE = [
    ("http://sandfort.test", "sandfort.test"),
    ("http://sandfort.test/", "sandfort.test"),
    ("HTTP://Sandfort.Test:8000", "sandfort.test"),
    ("http://10.0.0.5:8000", "10.0.0.5"),
    ("http://[2001:db8::1]:8000", "2001:db8::1"),
    ("http://user:pw@sandfort.test", "sandfort.test"),
    ("http://localhost.example", "localhost.example"),
]
SAFE = [
    "https://sandfort.test",
    "https://10.0.0.5",
    "http://localhost:8000",
    "http://LOCALHOST",
    "http://localhost.:8000",
    "http://127.0.0.1:8000",
    "http://127.1.2.3",
    "http://[::1]:8000",
    "",
    "sandfort.test",
    "http:///x",
    "http://[::1",
]
REMOTE_CLIENT_URLS = ["http://sandfort.test", "http://10.0.0.5:8000"]
QUIET_CLIENT_URLS = ["https://sandfort.test", "http://127.0.0.1:8000", "http://localhost:8000"]


def insecure(records: list[warnings.WarningMessage]) -> list[warnings.WarningMessage]:
    return [r for r in records if issubclass(r.category, InsecureBaseUrlWarning)]


def record(build: Callable[[], object]) -> list[warnings.WarningMessage]:
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        build()
    return insecure(records or [])


@pytest.mark.parametrize(("url", "host"), INSECURE)
def test_insecure_host_names_the_remote_host_of_an_http_url(url: str, host: str) -> None:
    assert insecure_host(url) == host


@pytest.mark.parametrize("url", SAFE)
def test_insecure_host_is_none_for_https_loopback_and_unusable_urls(url: str) -> None:
    assert insecure_host(url) is None


@pytest.mark.parametrize("url", REMOTE_CLIENT_URLS)
def test_client_warns_once_for_a_remote_http_url(url: str) -> None:
    found = record(lambda: Client(url, KEY).close())

    assert len(found) == 1
    w = found[0]
    assert "clear text" in str(w.message)
    assert KEY not in str(w.message)
    assert Path(w.filename).name == Path(__file__).name


@pytest.mark.parametrize("url", QUIET_CLIENT_URLS)
def test_client_is_quiet_for_https_and_loopback(url: str) -> None:
    assert record(lambda: Client(url, KEY).close()) == []


async def test_async_client_warns_once_for_a_remote_http_url() -> None:
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        client = AsyncClient(REMOTE_HTTP, KEY)
    await client.aclose()

    assert len(insecure(records or [])) == 1


async def test_async_client_is_quiet_for_loopback() -> None:
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        client = AsyncClient(LOOPBACK_HTTP, KEY)
    await client.aclose()

    assert insecure(records or []) == []


def test_message_names_the_host_and_never_the_userinfo() -> None:
    found = record(lambda: warn_if_insecure_base_url("http://user:pw@sandfort.test"))

    assert len(found) == 1
    text = str(found[0].message)
    assert "sandfort.test" in text
    assert "pw" not in text
    assert "user" not in text


def test_warning_is_a_user_warning_exported_from_the_package() -> None:
    assert issubclass(InsecureBaseUrlWarning, UserWarning)
    assert "InsecureBaseUrlWarning" in sandfort_sdk.__all__


def test_the_warning_can_be_turned_into_an_error() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error", InsecureBaseUrlWarning)
        with pytest.raises(InsecureBaseUrlWarning):
            Client(REMOTE_HTTP, KEY)


def test_the_warning_can_be_silenced() -> None:
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warnings.simplefilter("ignore", InsecureBaseUrlWarning)
        Client(REMOTE_HTTP, KEY).close()

    assert insecure(records or []) == []


def cli_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, base_url: str) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "no-profile"))
    monkeypatch.setenv(config.API_KEY_ENV, KEY)
    monkeypatch.setenv(config.BASE_URL_ENV, base_url)
    monkeypatch.delenv(config.API_KEY_FILE_ENV, raising=False)


def test_cli_open_client_emits_the_warning(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cli_environment(monkeypatch, tmp_path, REMOTE_HTTP)

    found = record(lambda: config.open_client().close())

    assert len(found) == 1


def test_cli_open_client_is_quiet_for_loopback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cli_environment(monkeypatch, tmp_path, LOOPBACK_HTTP)

    assert record(lambda: config.open_client().close()) == []
