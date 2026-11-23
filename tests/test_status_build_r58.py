"""``/v1/status`` reports the build baked into the image next to the configured build_sha."""

import logging
from pathlib import Path

import pytest

from sandfort.api.routes import health
from sandfort.config import Settings

BAKED = "4871ea2f0c9d"
OTHER = "deadbeef0001"


def make_settings(build_file: Path | None, build_sha: str = "") -> Settings:
    return Settings(
        driver="fake",
        database_url="sqlite+aiosqlite:///:memory:",
        api_key_pepper="test-pepper",
        build_sha=build_sha,
        build_sha_file=str(build_file) if build_file is not None else "",
    )


@pytest.fixture(autouse=True)
def fresh_cache() -> None:
    health._IMAGE_SHA_CACHE.clear()


def test_default_build_file_path_and_env_name() -> None:
    assert Settings().build_sha_file == "/app/BUILD_SHA"
    env = {"SANDFORT_BUILD_SHA_FILE": " /srv/BUILD "}
    assert Settings.from_env(env).build_sha_file == "/srv/BUILD"


def test_matching_values_report_true(tmp_path: Path) -> None:
    path = tmp_path / "BUILD_SHA"
    path.write_text(f"{BAKED}\n")

    data = health.status_payload(make_settings(path, build_sha=BAKED))

    assert data["build_sha"] == BAKED
    assert data["image_sha"] == BAKED
    assert data["build_matches_image"] is True


def test_differing_values_report_false_and_warn_once(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "BUILD_SHA"
    path.write_text(BAKED)
    settings = make_settings(path, build_sha=OTHER)

    with caplog.at_level(logging.WARNING, logger=health.logger.name):
        first = health.status_payload(settings)
        second = health.status_payload(settings)

    assert first["build_matches_image"] is False
    assert second["build_matches_image"] is False
    warnings = [r for r in caplog.records if "differs" in r.getMessage()]
    assert len(warnings) == 1
    assert BAKED in warnings[0].getMessage()


def test_missing_file_gives_null_image_sha_and_match(tmp_path: Path) -> None:
    data = health.status_payload(make_settings(tmp_path / "absent", build_sha=OTHER))

    assert data["build_sha"] == OTHER
    assert data["image_sha"] is None
    assert data["build_matches_image"] is None


def test_empty_file_counts_as_missing(tmp_path: Path) -> None:
    path = tmp_path / "BUILD_SHA"
    path.write_text("  \n")

    data = health.status_payload(make_settings(path, build_sha=OTHER))

    assert data["image_sha"] is None
    assert data["build_matches_image"] is None


def test_baked_value_without_configured_build_sha(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "BUILD_SHA"
    path.write_text(BAKED)

    with caplog.at_level(logging.WARNING, logger=health.logger.name):
        data = health.status_payload(make_settings(path))

    assert data["build_sha"] is None
    assert data["image_sha"] == BAKED
    assert data["build_matches_image"] is None
    assert not caplog.records


def test_file_is_read_once(tmp_path: Path) -> None:
    path = tmp_path / "BUILD_SHA"
    path.write_text(BAKED)
    settings = make_settings(path, build_sha=BAKED)
    health.status_payload(settings)

    path.write_text(OTHER)

    assert health.status_payload(settings)["image_sha"] == BAKED


def test_unreadable_path_is_null(tmp_path: Path) -> None:
    # A directory is not a readable file: an OSError other than FileNotFoundError.
    data = health.status_payload(make_settings(tmp_path, build_sha=OTHER))

    assert data["image_sha"] is None
    assert data["build_matches_image"] is None
