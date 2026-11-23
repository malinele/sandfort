"""M5: the docker client has an empty credential store; the image policy has a registry allowlist.

The operator's registry logins (the server user's Docker config) must not serve tenant pulls, and
an operator can restrict the registries a user image reference may name.
"""

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from sandfort import admin_doctor
from sandfort.config import Settings
from sandfort.drivers.docker import client as docker_client
from sandfort.errors import Unprocessable
from sandfort.services.image_builds import ImageBuildService
from sandfort.services.image_policy import (
    ALLOWED_REGISTRIES_ENV,
    allowed_registries_from_env,
    check_user_image_reference,
    image_registry,
)

OPERATOR_CONFIG = "/home/operator/.docker"


@pytest.fixture
def seen_configs(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Swap docker-py for a fake whose factories record ``DOCKER_CONFIG`` and the config file."""
    seen: list[dict[str, Any]] = []

    def record(kind: str) -> str:
        directory = os.environ.get("DOCKER_CONFIG")
        content = None
        if directory is not None and (Path(directory) / "config.json").is_file():
            content = json.loads((Path(directory) / "config.json").read_text())
        seen.append({"kind": kind, "dir": directory, "content": content})
        return kind

    module = SimpleNamespace(
        from_env=lambda **_: record("from_env"),
        DockerClient=lambda **_: record("DockerClient"),
    )
    monkeypatch.setattr(docker_client, "load_docker_module", lambda: module)
    monkeypatch.setenv("DOCKER_CONFIG", OPERATOR_CONFIG)
    monkeypatch.delenv(docker_client.USER_CONFIG_ENV, raising=False)
    return seen


def test_client_is_built_with_an_empty_isolated_credential_store(
    seen_configs: list[dict[str, Any]],
) -> None:
    assert docker_client.make_client() == "from_env"
    assert docker_client.make_client("unix:///tmp/docker.sock") == "DockerClient"

    assert [entry["kind"] for entry in seen_configs] == ["from_env", "DockerClient"]
    for entry in seen_configs:
        assert entry["dir"] != OPERATOR_CONFIG
        assert Path(entry["dir"]).name.startswith(docker_client.ISOLATED_CONFIG_PREFIX)
        assert entry["content"] == {}
    assert seen_configs[0]["dir"] == seen_configs[1]["dir"]


def test_the_operator_docker_config_is_restored_after_the_client_is_built(
    seen_configs: list[dict[str, Any]],
) -> None:
    docker_client.make_client()
    assert os.environ["DOCKER_CONFIG"] == OPERATOR_CONFIG


def test_docker_config_stays_unset_when_it_was_unset(
    seen_configs: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DOCKER_CONFIG")
    docker_client.make_client()
    assert seen_configs[0]["dir"] is not None
    assert "DOCKER_CONFIG" not in os.environ


def test_the_isolated_directory_is_private(seen_configs: list[dict[str, Any]]) -> None:
    docker_client.make_client()
    assert (Path(seen_configs[0]["dir"]).stat().st_mode & 0o077) == 0


def test_an_explicit_setting_allows_the_user_config(
    seen_configs: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(docker_client.USER_CONFIG_ENV, "true")
    docker_client.make_client()
    docker_client.make_client(use_user_config=True)
    assert [entry["dir"] for entry in seen_configs] == [OPERATOR_CONFIG, OPERATOR_CONFIG]


def test_the_argument_overrides_the_setting(
    seen_configs: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(docker_client.USER_CONFIG_ENV, "1")
    docker_client.make_client(use_user_config=False)
    assert seen_configs[0]["dir"] != OPERATOR_CONFIG


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "maybe"])
def test_only_explicit_true_values_allow_the_user_config(value: str) -> None:
    environ = {docker_client.USER_CONFIG_ENV: value}
    assert docker_client.user_docker_config_allowed(environ) is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", " yes ", "on"])
def test_true_values_allow_the_user_config(value: str) -> None:
    environ = {docker_client.USER_CONFIG_ENV: value}
    assert docker_client.user_docker_config_allowed(environ) is True


@pytest.mark.parametrize(
    ("reference", "registry"),
    [
        ("python:3.12-slim", "docker.io"),
        ("library/python:3.12", "docker.io"),
        ("team/app@sha256:" + "ab" * 32, "docker.io"),
        ("docker.io/library/python", "docker.io"),
        ("index.docker.io/library/python", "docker.io"),
        ("registry-1.docker.io/library/python", "docker.io"),
        ("GHCR.io/org/app:1", "ghcr.io"),
        ("registry.example.com:5000/team/app:1", "registry.example.com:5000"),
        ("localhost/app", "localhost"),
        ("localhost:5000/app", "localhost:5000"),
    ],
)
def test_image_registry_follows_dockers_resolution_rule(reference: str, registry: str) -> None:
    assert image_registry(reference) == registry


@pytest.mark.parametrize(
    "reference",
    ["python:3.12", "ghcr.io/org/app:1", "registry.example.com:5000/a/b", "localhost:5000/x"],
)
def test_any_registry_is_accepted_by_default(
    reference: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(ALLOWED_REGISTRIES_ENV, raising=False)
    check_user_image_reference(reference)


@pytest.mark.parametrize("reference", ["python:3.12", "library/python", "docker.io/library/python"])
def test_a_listed_registry_is_accepted(reference: str) -> None:
    check_user_image_reference(reference, ["docker.io", "ghcr.io"])


def test_an_unlisted_registry_is_refused_with_the_policy_422() -> None:
    with pytest.raises(Unprocessable) as raised:
        check_user_image_reference("evil.example.com/team/app:1", ["docker.io"])
    assert raised.value.status == 422
    assert "evil.example.com" in raised.value.message


def test_hub_names_are_refused_when_docker_hub_is_not_listed() -> None:
    with pytest.raises(Unprocessable):
        check_user_image_reference("python:3.12", ["ghcr.io"])


def test_registry_matching_ignores_case_and_hub_aliases() -> None:
    check_user_image_reference("GHCR.io/org/app", ["ghcr.IO"])
    check_user_image_reference("python", ["index.docker.io"])


def test_a_lookalike_registry_is_not_a_match() -> None:
    with pytest.raises(Unprocessable):
        check_user_image_reference("ghcr.io.evil.test/org/app", ["ghcr.io"])


def test_the_shape_rules_still_apply_with_an_allowlist() -> None:
    with pytest.raises(Unprocessable):
        check_user_image_reference("sha256:" + "ab" * 32, ["docker.io"])
    with pytest.raises(Unprocessable):
        check_user_image_reference("ghcr.io/org/sandfort-snapshot:snap_1", ["ghcr.io"])


def test_an_empty_list_means_any_registry() -> None:
    check_user_image_reference("evil.example.com/app", [])


def test_the_allowlist_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ALLOWED_REGISTRIES_ENV, " docker.io , GHCR.io ,, ")
    assert allowed_registries_from_env() == frozenset({"docker.io", "ghcr.io"})
    check_user_image_reference("ghcr.io/org/app")
    with pytest.raises(Unprocessable):
        check_user_image_reference("quay.io/org/app")


def test_an_explicit_list_overrides_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ALLOWED_REGISTRIES_ENV, "docker.io")
    check_user_image_reference("quay.io/org/app", ["quay.io"])


@pytest.mark.parametrize("value", ["", " ", ",,"])
def test_a_blank_environment_value_means_any_registry(value: str) -> None:
    assert allowed_registries_from_env({ALLOWED_REGISTRIES_ENV: value}) is None
    assert allowed_registries_from_env({}) is None


# -- the build service enforces the allowlist; settings own the policy ----------------------


class StoreReachedError(Exception):
    """Raised by the stub unit of work: the build got past the registry check."""


def _build_service(allowed: list[str]) -> ImageBuildService:
    def refuse_store() -> Any:
        raise StoreReachedError

    clock: Any = SimpleNamespace(now=lambda: None)
    driver: Any = SimpleNamespace(name="stub")
    return ImageBuildService(refuse_store, driver, clock, allowed_registries=allowed)


def _payload(base_image: str) -> dict[str, Any]:
    return {"base_image": base_image, "files": []}


async def test_a_build_from_a_foreign_registry_is_refused_with_the_policy_422() -> None:
    service = _build_service(["docker.io"])
    with pytest.raises(Unprocessable) as raised:
        await service.build("org_1", None, _payload("evil.example.com/team/base:1"))
    assert raised.value.status == 422
    assert "evil.example.com" in raised.value.message


async def test_a_build_from_an_allowed_registry_passes_the_check() -> None:
    service = _build_service(["docker.io", "ghcr.io"])
    for base in ("python:3.12-slim", "ghcr.io/org/base:1"):
        with pytest.raises(StoreReachedError):
            await service.build("org_1", None, _payload(base))


def test_a_scheme_in_the_allowlist_setting_is_refused_at_settings_load() -> None:
    with pytest.raises(ValueError, match="ALLOWED_REGISTRIES.*scheme"):
        Settings.from_env({ALLOWED_REGISTRIES_ENV: "docker.io, https://ghcr.io"})


def test_the_allowlist_setting_is_normalized_once() -> None:
    settings = Settings.from_env({ALLOWED_REGISTRIES_ENV: " Docker.IO , ghcr.io ,, "})
    assert settings.allowed_registries == ("docker.io", "ghcr.io")
    assert Settings.from_env({}).allowed_registries == ()


def test_the_doctor_lists_the_registry_allowlist_and_the_build_network() -> None:
    open_results = {r.name: r for r in admin_doctor.evaluate(Settings(), None)}
    assert "any registry" in open_results["allowed registries"].detail
    assert "daemon default" in open_results["build network"].detail

    settings = Settings(allowed_registries=("docker.io", "ghcr.io"), build_network="build-net")
    results = {r.name: r for r in admin_doctor.evaluate(settings, None)}
    assert results["allowed registries"].status is admin_doctor.Status.PASS
    assert "docker.io, ghcr.io" in results["allowed registries"].detail
    assert "build-net" in results["build network"].detail
