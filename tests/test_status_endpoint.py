"""``GET /v1/status``: public version, build and operator notice (daemon-free, no key)."""

import os
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from typing import Any

import httpx
import pytest

from sandfort.api import openapi
from sandfort.api.app import create_app
from sandfort.api.routes import health
from sandfort.config import Settings

STATUS = "/v1/status"
NOTICE_MTIME = 1_700_000_000
NOTICE_MTIME_ISO = datetime.fromtimestamp(NOTICE_MTIME, UTC).isoformat()
TWO_KIB = 2048

Fetch = Callable[..., Awaitable[dict[str, Any]]]


def make_settings(**overrides: str) -> Settings:
    return Settings(
        driver="fake",
        database_url="sqlite+aiosqlite:///:memory:",
        api_key_pepper="test-pepper",
        **overrides,
    )


@pytest.fixture
async def fetch() -> AsyncIterator[Fetch]:
    """Build an app with the given settings and return the ``data`` of an unauthenticated GET."""
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    apps = []

    async def get(**overrides: str) -> dict[str, Any]:
        app = create_app(make_settings(**overrides))
        apps.append(app)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            response = await http.get(STATUS)
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        data: dict[str, Any] = body["data"]
        return data

    try:
        yield get
    finally:
        for app in apps:
            await app.state.engine.dispose()


def write_notice(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "notice.txt"
    path.write_bytes(content.encode())
    os.utime(path, (NOTICE_MTIME, NOTICE_MTIME))
    return path


async def test_status_needs_no_key_and_reports_the_fields(fetch: Fetch) -> None:
    data = await fetch()

    assert set(data) == {
        "status",
        "version",
        "build_sha",
        "image_sha",
        "build_matches_image",
        "started_at",
        "notice",
        "audit_public_key",
        "audit_key_fingerprint",
    }
    assert data["audit_public_key"] is None
    assert data["audit_key_fingerprint"] is None
    assert data["status"] == "ok"
    assert data["notice"] is None
    assert data["build_sha"] is None
    assert data["build_matches_image"] is None
    assert datetime.fromisoformat(data["started_at"]).tzinfo is not None


async def test_version_and_build_sha_come_from_settings_and_metadata(fetch: Fetch) -> None:
    data = await fetch(build_sha="4871ea2")

    assert data["build_sha"] == "4871ea2"
    assert data["version"] == health.package_version()


async def test_version_is_unknown_when_the_metadata_is_missing(
    fetch: Fetch, monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing(name: str) -> str:
        raise PackageNotFoundError(name)

    monkeypatch.setattr(health, "version", missing)

    assert (await fetch())["version"] == "unknown"


async def test_notice_comes_from_the_file_with_its_mtime(fetch: Fetch, tmp_path: Path) -> None:
    path = write_notice(tmp_path, "  Maintenance at 22:00 UTC.\n")

    data = await fetch(status_notice_file=str(path))

    assert data["status"] == "ok"
    expected = {"message": "Maintenance at 22:00 UTC.", "updated_at": NOTICE_MTIME_ISO}
    assert data["notice"] == expected


async def test_degraded_prefix_sets_the_status_and_is_stripped(
    fetch: Fetch, tmp_path: Path
) -> None:
    path = write_notice(tmp_path, "degraded: the node is draining\n")

    data = await fetch(status_notice_file=str(path))

    assert data["status"] == "degraded"
    assert data["notice"] == {"message": "the node is draining", "updated_at": NOTICE_MTIME_ISO}


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture(autouse=True)
def clear_notice_cache() -> None:
    health._NOTICE_CACHE.clear()


@pytest.fixture
def file_reads(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Paths passed to ``read_notice`` (full reads) during the test."""
    seen: list[str] = []
    original = health.read_notice

    def counting(notice_file: str) -> tuple[str, datetime] | None:
        seen.append(notice_file)
        return original(notice_file)

    monkeypatch.setattr(health, "read_notice", counting)
    return seen


@pytest.fixture
def stats(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Paths stat'ed by the cache during the test."""
    seen: list[str] = []
    original = health._mtime_ns

    def counting(notice_file: str) -> int | None:
        seen.append(notice_file)
        return original(notice_file)

    monkeypatch.setattr(health, "_mtime_ns", counting)
    return seen


def test_two_calls_within_the_window_read_the_file_once(
    tmp_path: Path, file_reads: list[str], stats: list[str]
) -> None:
    path = write_notice(tmp_path, "first")
    settings = make_settings(status_notice_file=str(path))
    clock = Clock()

    health.status_payload(settings, clock)
    path.write_text("degraded: second")  # not seen inside the window
    clock.now += 0.9
    second = health.status_payload(settings, clock)

    assert (second["status"], second["notice"]["message"]) == ("ok", "first")
    assert file_reads == [str(path)]
    assert len(stats) == 1  # the first call's stat; the second touched nothing


def test_an_unchanged_mtime_after_the_window_does_not_re_read(
    tmp_path: Path, file_reads: list[str], stats: list[str]
) -> None:
    path = write_notice(tmp_path, "first")
    settings = make_settings(status_notice_file=str(path))
    clock = Clock()

    health.status_payload(settings, clock)
    clock.now += 1.5
    again = health.status_payload(settings, clock)
    clock.now += 0.5  # the unchanged check restarted the window
    health.status_payload(settings, clock)

    assert again["notice"]["message"] == "first"
    assert file_reads == [str(path)]
    assert len(stats) == 2


def test_a_changed_file_shows_the_new_notice_after_the_window(
    tmp_path: Path, file_reads: list[str]
) -> None:
    path = write_notice(tmp_path, "first")
    settings = make_settings(status_notice_file=str(path))
    clock = Clock()

    first = health.status_payload(settings, clock)
    path.write_text("degraded: second")
    os.utime(path, (NOTICE_MTIME + 60, NOTICE_MTIME + 60))
    clock.now += 1.0
    second = health.status_payload(settings, clock)

    assert (first["status"], first["notice"]["message"]) == ("ok", "first")
    assert (second["status"], second["notice"]["message"]) == ("degraded", "second")
    updated = datetime.fromtimestamp(NOTICE_MTIME + 60, UTC).isoformat()
    assert second["notice"]["updated_at"] == updated
    assert file_reads == [str(path), str(path)]


def test_a_notice_appearing_after_the_window_is_picked_up(tmp_path: Path) -> None:
    settings = make_settings(status_notice_file=str(tmp_path / "notice.txt"))
    clock = Clock()

    assert health.status_payload(settings, clock)["notice"] is None
    write_notice(tmp_path, "now there is one")
    clock.now += 1.0

    assert health.status_payload(settings, clock)["notice"]["message"] == "now there is one"


@pytest.mark.parametrize("configured", ["", "missing.txt"])
async def test_no_file_means_no_notice(fetch: Fetch, tmp_path: Path, configured: str) -> None:
    path = str(tmp_path / configured) if configured else ""

    data = await fetch(status_notice_file=path)

    assert data["status"] == "ok"
    assert data["notice"] is None


async def test_an_empty_file_means_no_notice(fetch: Fetch, tmp_path: Path) -> None:
    path = write_notice(tmp_path, " \n\t\n")

    assert (await fetch(status_notice_file=str(path)))["notice"] is None


async def test_an_unreadable_path_is_logged_and_means_no_notice(
    fetch: Fetch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("WARNING", logger=health.__name__)

    data = await fetch(status_notice_file=str(tmp_path))  # a directory: reading it fails

    assert data["notice"] is None
    assert "status notice file unreadable" in caplog.text


async def test_an_oversize_file_is_truncated_to_2_kib(fetch: Fetch, tmp_path: Path) -> None:
    path = write_notice(tmp_path, "x" * (TWO_KIB * 3))

    data = await fetch(status_notice_file=str(path))

    assert data["notice"]["message"] == "x" * TWO_KIB


async def test_the_response_exposes_no_host_path_or_other_setting(
    fetch: Fetch, tmp_path: Path
) -> None:
    path = write_notice(tmp_path, "hello")

    data = await fetch(status_notice_file=str(path), build_sha="abc")

    assert str(tmp_path) not in repr(data)
    assert "test-pepper" not in repr(data)


def test_the_generated_spec_marks_status_open_and_sandbox_create_503() -> None:
    document = openapi.build_document(openapi.build_app())

    operation = document["paths"][STATUS]["get"]
    assert operation["security"] == []
    assert not openapi.AUTH_STATUSES & set(operation["responses"])
    assert document["paths"]["/v1/sandboxes"]["post"]["responses"]["503"] == openapi.RETRY_ERROR_REF


def test_the_settings_read_the_environment() -> None:
    settings = Settings.from_env(
        {"SANDFORT_BUILD_SHA": " abc123 ", "SANDFORT_STATUS_NOTICE_FILE": "/run/notice"}
    )

    assert (settings.build_sha, settings.status_notice_file) == ("abc123", "/run/notice")
    assert Settings.from_env({}).build_sha == ""
    assert Settings.from_env({}).status_notice_file == ""
