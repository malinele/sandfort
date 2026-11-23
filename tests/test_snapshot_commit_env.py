"""A snapshot committed from a sandbox must not carry the sandbox's env values.

``commit_container`` passes a commit ``conf`` whose ``Env`` is the base image's, plus ``KEY=``
for every key the container added (docker's commit merge can blank a key, not remove it). Unit
tests cover the env computation and the conf the commit receives; one test needs a real daemon.
"""

import contextlib
import uuid
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest

from sandfort.drivers.docker import images, lanes
from sandfort.drivers.docker.client import make_client
from sandfort.drivers.docker.commit_env import base_image_id, commit_env, config_env, env_key
from sandfort.drivers.errors import DriverError

BASE_PATH = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
BASE_ENV = [BASE_PATH, "LANG=C.UTF-8"]
CONTAINER_ENV = [
    "PATH=/evil/bin:/usr/bin",
    "LANG=C.UTF-8",
    "SECRET_TOKEN=abc",
    "HTTPS_PROXY=http://sandbox:signed.token@egress:3128",
    "QUERY=a=b=c",
]
BASE_ID = "sha256:" + "cd" * 32
COMMITTED_ID = "sha256:" + "ef" * 32
ALPINE = "alpine:3.20"


@pytest.fixture(autouse=True)
def default_lanes() -> Iterator[None]:
    lanes.configure_thread_limit()
    yield
    lanes.configure_thread_limit()


# --- env computation -------------------------------------------------------------------


def test_added_keys_are_blanked() -> None:
    env = commit_env(BASE_ENV, CONTAINER_ENV)
    assert "SECRET_TOKEN=" in env
    assert "HTTPS_PROXY=" in env
    assert not any("abc" in entry or "signed.token" in entry for entry in env)


def test_overridden_keys_get_the_base_value() -> None:
    env = commit_env(BASE_ENV, CONTAINER_ENV)
    assert [entry for entry in env if env_key(entry) == "PATH"] == [BASE_PATH]


def test_base_keys_are_unchanged_and_come_first() -> None:
    env = commit_env(BASE_ENV, CONTAINER_ENV)
    assert env[: len(BASE_ENV)] == BASE_ENV
    assert env == [*BASE_ENV, "SECRET_TOKEN=", "HTTPS_PROXY=", "QUERY="]


def test_a_value_with_equals_signs_is_split_on_the_first_one() -> None:
    assert env_key("QUERY=a=b=c") == "QUERY"
    assert commit_env([], ["QUERY=a=b=c"]) == ["QUERY="]
    assert commit_env(["QUERY=x=y"], ["QUERY=a=b=c"]) == ["QUERY=x=y"]


def test_duplicate_and_bare_container_entries_are_blanked_once() -> None:
    assert commit_env([], ["A=1", "A=2", "BARE", "=junk"]) == ["A=", "BARE="]


def test_empty_inputs() -> None:
    assert commit_env([], []) == []
    assert commit_env(BASE_ENV, []) == BASE_ENV


def test_config_env_and_base_image_id_read_inspect_payloads() -> None:
    assert config_env({}) == []
    assert config_env({"Config": {"Env": None}}) == []
    assert config_env({"Config": {"Env": BASE_ENV}}) == BASE_ENV
    assert base_image_id({"Image": BASE_ID, "Config": {"Image": ALPINE}}) == BASE_ID
    assert base_image_id({"Config": {"Image": ALPINE}}) == ALPINE
    assert base_image_id({}) == ""


# --- commit_container with a fake docker client -----------------------------------------


class FakeCommitApi:
    """The low-level calls ``commit_container`` makes; ``commits`` records commit kwargs."""

    def __init__(self, container: dict[str, Any]) -> None:
        self.container = container
        self.commits: list[dict[str, Any]] = []
        self.inspected_images: list[str] = []

    def inspect_container(self, ref: str) -> dict[str, Any]:
        return self.container

    def inspect_image(self, ref: str) -> dict[str, Any]:
        self.inspected_images.append(ref)
        if ref == BASE_ID:
            return {"Id": BASE_ID, "Config": {"Env": BASE_ENV}}
        return {"Id": COMMITTED_ID, "RootFS": {"Layers": ["a", "b"]}}

    def commit(self, container: str, **kwargs: Any) -> dict[str, Any]:
        self.commits.append({"container": container, **kwargs})
        return {"Id": COMMITTED_ID}


async def test_commit_receives_the_sanitized_conf() -> None:
    api = FakeCommitApi({"Image": BASE_ID, "Config": {"Image": ALPINE, "Env": CONTAINER_ENV}})
    client = SimpleNamespace(api=api)

    result = await images.commit_container(client, "ctr1", "sandfort-snapshot:snap_1")

    assert (result.digest, result.layer_count) == (COMMITTED_ID, 2)
    assert api.inspected_images == [BASE_ID, COMMITTED_ID]
    [call] = api.commits
    assert call["container"] == "ctr1"
    assert (call["repository"], call["tag"], call["pause"]) == (
        "sandfort-snapshot",
        "snap_1",
        True,
    )
    assert call["conf"] == {"Env": [*BASE_ENV, "SECRET_TOKEN=", "HTTPS_PROXY=", "QUERY="]}


async def test_commit_falls_back_to_the_config_image_reference() -> None:
    api = FakeCommitApi({"Config": {"Image": BASE_ID, "Env": ["SECRET_TOKEN=abc"]}})

    await images.commit_container(SimpleNamespace(api=api), "ctr1", "sandfort-snapshot:snap_1")

    assert api.commits[0]["conf"] == {"Env": [*BASE_ENV, "SECRET_TOKEN="]}


async def test_commit_without_a_base_image_is_refused_before_committing() -> None:
    api = FakeCommitApi({"Config": {"Env": ["SECRET_TOKEN=abc"]}})

    with pytest.raises(DriverError, match="names no base image"):
        await images.commit_container(SimpleNamespace(api=api), "ctr1", "sandfort-snapshot:s")

    assert api.commits == []


# --- real Docker -----------------------------------------------------------------------


@pytest.mark.docker
async def test_committed_image_holds_no_sandbox_env_value() -> None:
    docker = pytest.importorskip("docker")
    try:
        client = make_client()
        client.ping()
        client.images.get(ALPINE)
    except Exception as exc:
        pytest.skip(f"no Docker daemon with {ALPINE}: {exc}")
    base_env = client.api.inspect_image(ALPINE)["Config"].get("Env") or []
    base_path = next(entry for entry in base_env if env_key(entry) == "PATH")
    reference = f"sandfort-snapshot-test:commit-env-{uuid.uuid4().hex[:8]}"
    container = client.api.create_container(
        ALPINE,
        command=["sleep", "60"],
        environment={"SECRET_TOKEN": "abc", "PATH": "/evil/bin:/usr/bin:/bin"},
    )
    try:
        client.api.start(container["Id"])
        await images.commit_container(client, container["Id"], reference)
        committed = client.api.inspect_image(reference)["Config"].get("Env") or []
        output = client.containers.run(
            reference, ["/bin/sh", "-c", 'printf "[%s]" "$SECRET_TOKEN"'], remove=True
        )
    finally:
        client.api.remove_container(container["Id"], v=True, force=True)
        with contextlib.suppress(docker.errors.NotFound):
            client.api.remove_image(reference, force=True)
    assert "SECRET_TOKEN=" in committed
    assert "SECRET_TOKEN=abc" not in committed
    assert [entry for entry in committed if env_key(entry) == "PATH"] == [base_path]
    assert output.strip() == b"[]"
