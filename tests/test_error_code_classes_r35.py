"""Round 35: image failures get their own driver classes and error codes (retryable or not).

The daemon text classifiers run on the fake docker-py client from the Docker driver unit tests
(``failing_pull_client`` and ``create_client_with_failing_pull``). The job failure mapping runs
through ``driver_error_code`` and through the API on the fake driver with a temp SQLite
database, the way the round-34 error-code tests stage a failing ``create``.
"""

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from sandfort.api.schemas.sandboxes import SandboxResponse
from sandfort.domain.org import Scope
from sandfort.domain.sandbox import (
    ERROR_CODES,
    ERROR_IMAGE_ACCESS_DENIED,
    ERROR_IMAGE_NOT_FOUND,
    ERROR_INTERNAL,
    ERROR_INVALID_IMAGE_REFERENCE,
    ERROR_REGISTRY_TLS_ERROR,
    ERROR_REGISTRY_UNREACHABLE,
    ERROR_START_FAILED,
    ERROR_TIMEOUT,
    IMAGE_PULL_ERROR_CODES,
)
from sandfort.drivers.base import InstanceInfo, SandboxSpec
from sandfort.drivers.docker.client import GENERIC_DRIVER_MESSAGE, clean_message
from sandfort.drivers.docker.containers import create_container
from sandfort.drivers.docker.images import pull_image, pull_image_digest
from sandfort.drivers.errors import (
    DriverAccessDenied,
    DriverConflict,
    DriverError,
    DriverInvalidReference,
    DriverNotFound,
    DriverRegistryTlsError,
    DriverRegistryUnreachable,
    DriverTimeout,
)
from sandfort.drivers.fake import FakeDriver
from sandfort.services.sandbox_jobs import driver_error_code
from test_api_sandboxes import BASE, add_org, migrated_app, seed_key, send
from test_docker_driver_unit import (
    REGISTRY_UNREACHABLE,
    SETTINGS,
    FakeClient,
    create_client_with_failing_pull,
    daemon_error,
    failing_pull_client,
    make_spec,
)

errors = pytest.importorskip("docker.errors")

PULL_HELPERS = [pull_image, pull_image_digest]
REF = "registry.example/team/app:1"
NETWORK_TEXTS = (
    'failed to resolve reference "registry.example/team/app:1": dial tcp: lookup '
    "registry.example on 127.0.0.53:53: server misbehaving",
    "net/http: TLS handshake timeout",
    "dial tcp 10.0.0.1:443: i/o timeout",
    "dial tcp 10.0.0.1:443: connect: connection refused",
    "lookup registry.example: no such host",
    "Temporary failure in name resolution",
)
ACCESS_DENIED_TEXTS = (
    "denied: requested access to the resource is denied",
    "unauthorized: authentication required",
    "Head https://registry.example/v2/team/app/manifests/1: unauthorized",
    'failed to resolve reference "registry.example/team/app:1": failed to authorize: '
    "failed to fetch anonymous token: unexpected status: 401 Unauthorized",
    "error from registry: denied: access forbidden",
)
INVALID_REFERENCE_TEXTS = (
    "invalid reference format",
    "invalid reference format: repository name must be lowercase",
    "Error response from daemon: invalid reference format",
)
ACCESS_DENIED_MESSAGE = (
    "the registry refused to pull {ref}; check the image name and the registry access"
)
PULL_DENIED_SENTENCE = (
    "pull access denied for team/app, repository does not exist or may require 'docker login'"
)
READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})


# -- class hierarchy -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "cls", [DriverRegistryUnreachable, DriverAccessDenied, DriverInvalidReference]
)
def test_new_classes_are_driver_errors_with_a_ref(cls: type[DriverError]) -> None:
    exc = cls("could not pull", ref=REF)
    assert isinstance(exc, DriverError)
    assert not isinstance(exc, DriverNotFound | DriverTimeout | DriverConflict)
    assert exc.ref == REF
    assert exc.message == "could not pull"


# -- daemon text -> class (pull) -------------------------------------------------------------


@pytest.mark.parametrize("helper", PULL_HELPERS)
@pytest.mark.parametrize("text", NETWORK_TEXTS)
async def test_registry_network_text_raises_registry_unreachable(helper: Any, text: str) -> None:
    client = failing_pull_client(daemon_error(errors.APIError, 500, text))
    with pytest.raises(DriverRegistryUnreachable) as caught:
        await helper(client, REF)
    assert str(caught.value) == REGISTRY_UNREACHABLE.format(ref=REF)
    assert caught.value.ref == REF
    assert "127.0.0.53" not in str(caught.value)


@pytest.mark.parametrize("helper", PULL_HELPERS)
@pytest.mark.parametrize("text", ACCESS_DENIED_TEXTS)
async def test_registry_refusal_text_raises_access_denied(helper: Any, text: str) -> None:
    failure = daemon_error(errors.APIError, 500, text)
    client = failing_pull_client(failure)
    with pytest.raises(DriverAccessDenied) as caught:
        await helper(client, REF)
    assert type(caught.value) is DriverAccessDenied
    assert str(caught.value) == ACCESS_DENIED_MESSAGE.format(ref=REF)  # never the daemon text
    assert clean_message(failure) not in str(caught.value)
    assert "https://" not in str(caught.value)
    assert caught.value.ref == REF


@pytest.mark.parametrize("helper", PULL_HELPERS)
@pytest.mark.parametrize("text", INVALID_REFERENCE_TEXTS)
async def test_unparsable_reference_text_raises_invalid_reference(helper: Any, text: str) -> None:
    client = failing_pull_client(daemon_error(errors.APIError, 400, text))
    with pytest.raises(DriverInvalidReference) as caught:
        await helper(client, "Team/App:1")
    assert str(caught.value) == "invalid image reference Team/App:1: invalid reference format"
    assert "lowercase" not in str(caught.value)
    assert caught.value.ref == "Team/App:1"


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_pull_denial_sentence_is_still_a_clean_not_found(helper: Any) -> None:
    text = PULL_DENIED_SENTENCE + ": denied: requested access to the resource is denied"
    client = failing_pull_client(daemon_error(errors.APIError, 500, text))
    with pytest.raises(DriverNotFound) as caught:
        await helper(client, REF)
    assert type(caught.value) is DriverNotFound
    assert str(caught.value) == f"no such image or snapshot: {REF}"


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_missing_image_is_still_a_clean_not_found(helper: Any) -> None:
    client = failing_pull_client(daemon_error(errors.NotFound, 404, f"No such image: {REF}"))
    with pytest.raises(DriverNotFound) as caught:
        await helper(client, REF)
    assert type(caught.value) is DriverNotFound
    assert str(caught.value) == f"no such image or snapshot: {REF}"


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_unknown_daemon_text_stays_a_plain_driver_error(helper: Any) -> None:
    client = failing_pull_client(daemon_error(errors.APIError, 500, "the daemon is overloaded"))
    with pytest.raises(DriverError) as caught:
        await helper(client, REF)
    assert type(caught.value) is DriverError
    assert str(caught.value) == f"could not pull {REF}"


# -- daemon text -> class (create) -----------------------------------------------------------


async def test_create_with_an_unparsable_reference_raises_invalid_reference() -> None:
    spec = make_spec(image="Team/App:1")
    client = FakeClient()
    client.create_results = [daemon_error(errors.APIError, 400, "invalid reference format")]
    with pytest.raises(DriverInvalidReference) as caught:
        await create_container(client, spec, SETTINGS)
    assert str(caught.value) == "invalid image reference Team/App:1: invalid reference format"
    assert caught.value.ref == "Team/App:1"
    assert [call[0] for call in client.calls].count("pull") == 0


async def test_create_inline_pull_refusal_raises_access_denied() -> None:
    spec = make_spec()
    text = ACCESS_DENIED_TEXTS[0]
    client = create_client_with_failing_pull(daemon_error(errors.APIError, 500, text))
    with pytest.raises(DriverAccessDenied) as caught:
        await create_container(client, spec, SETTINGS)
    assert str(caught.value) == ACCESS_DENIED_MESSAGE.format(ref=spec.image)
    assert caught.value.ref == spec.image


async def test_create_inline_pull_network_failure_raises_registry_unreachable() -> None:
    spec = make_spec()
    client = create_client_with_failing_pull(daemon_error(errors.APIError, 500, NETWORK_TEXTS[0]))
    with pytest.raises(DriverRegistryUnreachable) as caught:
        await create_container(client, spec, SETTINGS)
    assert str(caught.value) == REGISTRY_UNREACHABLE.format(ref=spec.image)


async def test_create_unrelated_daemon_error_carries_the_fixed_sentence() -> None:
    client = FakeClient()
    client.create_results = [daemon_error(errors.APIError, 500, "the daemon is overloaded")]
    with pytest.raises(DriverError) as caught:
        await create_container(client, make_spec(), SETTINGS)
    assert type(caught.value) is DriverError
    assert caught.value.message == GENERIC_DRIVER_MESSAGE
    assert "overloaded" not in caught.value.message


# -- class -> code ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (DriverRegistryUnreachable("x", ref=REF), ERROR_REGISTRY_UNREACHABLE),
        (DriverAccessDenied("x", ref=REF), ERROR_IMAGE_ACCESS_DENIED),
        (DriverInvalidReference("x", ref=REF), ERROR_INVALID_IMAGE_REFERENCE),
        (DriverNotFound("x", ref=REF), ERROR_IMAGE_NOT_FOUND),
        (DriverNotFound("x", ref="vol"), ERROR_START_FAILED),
        (DriverTimeout("x", ref=REF), ERROR_TIMEOUT),
        (DriverError("x", ref=REF), ERROR_START_FAILED),
        (DriverConflict("x", ref=REF), ERROR_START_FAILED),
    ],
)
def test_driver_error_code_picks_the_code_from_the_type(exc: DriverError, code: str) -> None:
    assert driver_error_code(exc, fallback=ERROR_START_FAILED, image=REF) == code


def test_new_codes_do_not_depend_on_the_image_ref_or_message() -> None:
    exc = DriverAccessDenied("registry said no", ref="something-else")
    assert driver_error_code(exc, fallback=ERROR_INTERNAL) == ERROR_IMAGE_ACCESS_DENIED


def test_new_codes_are_distinct_and_documented() -> None:
    assert set(IMAGE_PULL_ERROR_CODES) == {
        ERROR_REGISTRY_UNREACHABLE,
        ERROR_REGISTRY_TLS_ERROR,
        ERROR_IMAGE_ACCESS_DENIED,
        ERROR_INVALID_IMAGE_REFERENCE,
    }
    assert set(IMAGE_PULL_ERROR_CODES) <= set(ERROR_CODES)
    description = SandboxResponse.model_fields["error_code"].description or ""
    for code in IMAGE_PULL_ERROR_CODES:
        assert code in description
    assert "registry_unreachable (retryable" in description
    assert "registry_tls_error (not retryable" in description
    assert "image_access_denied (not retryable" in description
    assert "invalid_image_reference (not retryable" in description


# -- through the job failure path ------------------------------------------------------------


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
    org_id = await add_org(app, "errcode-r35")
    return await seed_key(app, org_id, READ_WRITE)


@pytest.mark.parametrize(
    ("make_exc", "code"),
    [
        (lambda image: DriverRegistryUnreachable("no answer", ref=image), "registry_unreachable"),
        (lambda image: DriverRegistryTlsError("bad cert", ref=image), "registry_tls_error"),
        (lambda image: DriverAccessDenied("denied", ref=image), "image_access_denied"),
        (lambda image: DriverInvalidReference("bad", ref=image), "invalid_image_reference"),
        (lambda image: DriverNotFound("missing", ref=image), "image_not_found"),
        (lambda image: DriverError("boom", ref=image), "start_failed"),
    ],
)
async def test_failed_create_records_the_code(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    monkeypatch: pytest.MonkeyPatch,
    make_exc: Any,
    code: str,
) -> None:
    driver = app.state.driver
    assert isinstance(driver, FakeDriver)

    async def failing_create(spec: SandboxSpec) -> InstanceInfo:
        raise make_exc(spec.image)

    monkeypatch.setattr(driver, "create", failing_create)
    body = await send(client, "POST", BASE, key, status=201, json={"snapshot": REF})
    created: dict[str, Any] = body["data"]
    assert created["state"] == "error"
    assert created["error_code"] == code
    fetched = await send(client, "GET", f"{BASE}/{created['id']}", key, status=200)
    assert fetched["data"]["error_code"] == code
