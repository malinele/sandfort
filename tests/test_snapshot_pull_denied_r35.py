"""Round 35, second review: registering a snapshot the registry refuses leaks no daemon text.

``POST /v1/snapshots`` pulls the image through ``pull_image_digest``. The fake driver's pull is
replaced by the Docker driver's own helper on the fake docker-py client from the Docker driver
unit tests, so the daemon text goes through the real classification and the real API error
mapping; the answer must carry the fixed sentence and none of the daemon's words.
"""

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from sandfort.domain.org import Scope
from sandfort.drivers.docker import images
from sandfort.drivers.fake import FakeDriver
from test_api_sandboxes import add_org, migrated_app, seed_key, send
from test_docker_driver_unit import daemon_error, failing_pull_client

errors = pytest.importorskip("docker.errors")

SNAPSHOTS = "/v1/snapshots"
SCOPES = frozenset({Scope.SNAPSHOTS_READ, Scope.SNAPSHOTS_WRITE})
IMAGE = "registry.example/team/app:1"
ECR_DENIAL = (
    "Head https://123456789012.dkr.ecr.eu-west-1.amazonaws.com/v2/team/app/manifests/1: "
    "denied: User: arn:aws:sts::123456789012:assumed-role/pull-role/i-0abc is not authorized "
    "to perform: ecr:BatchGetImage"
)
CONTAINERD_DENIAL = (
    f'failed to resolve reference "{IMAGE}": failed to authorize: failed to fetch anonymous '
    "token: unexpected status from GET request to https://auth.example.net/token?scope=x: "
    "403 Forbidden"
)
GHCR_BARE_DENIED = 'Head "https://ghcr.io/v2/team/app/manifests/1": denied'
DAEMON_WORDS = (
    "arn:",
    "123456789012",
    "amazonaws",
    "pull-role",
    "BatchGetImage",
    "auth.example.net",
    "ghcr.io",
    "403",
    "Forbidden",
    "Head",
)
REFUSED = f"the registry refused to pull {IMAGE}; check the image name and the registry access"


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    async with migrated_app(tmp_path) as application:
        yield application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
async def key(app: FastAPI) -> str:
    org_id = await add_org(app, "snapdenied-r35")
    return await seed_key(app, org_id, SCOPES)


def fail_pulls_with(app: FastAPI, monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    """Make the fake driver's pin-pull run the Docker helper against a failing daemon."""
    driver = app.state.driver
    assert isinstance(driver, FakeDriver)
    docker_client = failing_pull_client(daemon_error(errors.APIError, 500, text))

    async def pull_image_digest(reference: str) -> str:
        return await images.pull_image_digest(docker_client, reference)

    monkeypatch.setattr(driver, "pull_image_digest", pull_image_digest)


@pytest.mark.parametrize("text", [ECR_DENIAL, CONTAINERD_DENIAL, GHCR_BARE_DENIED])
async def test_register_refused_by_the_registry_answers_the_fixed_sentence(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    monkeypatch: pytest.MonkeyPatch,
    text: str,
) -> None:
    fail_pulls_with(app, monkeypatch, text)
    body = await send(client, "POST", SNAPSHOTS, key, status=502, json={"image": IMAGE})
    assert body["error"]["code"] == "DRIVER_ERROR"
    assert body["error"]["message"] == REFUSED
    # The random request id can contain digits such as "403" by chance; inspect only the
    # error code, message and details.
    inspected = {name: value for name, value in body["error"].items() if name != "request_id"}
    raw = str(inspected)
    for word in DAEMON_WORDS:
        assert word not in raw
    listed = await send(client, "GET", SNAPSHOTS, key, status=200)
    assert listed["data"] == []  # nothing was registered


async def test_register_with_an_unclassified_identity_leak_answers_could_not_pull(
    app: FastAPI, client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fail_pulls_with(app, monkeypatch, "throttled for arn:aws:iam::123456789012:role/pull")
    body = await send(client, "POST", SNAPSHOTS, key, status=502, json={"image": IMAGE})
    assert body["error"]["message"] == f"could not pull {IMAGE}"
    assert "arn:" not in str(body)
    assert "123456789012" not in str(body)
