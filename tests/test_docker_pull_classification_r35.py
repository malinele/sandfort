"""Round 35 review: structural pull-failure matching and a fixed tenant-facing reason.

The classifier must not read the image reference the daemon echoes as a denial marker, must
decide a transport failure before the anchored access-denied phrases, and the exception for a
registry refusal or an unparsable reference must not carry the daemon's own text (second review:
the exception itself is tenant-safe, so the reset service and every other path are too).
"""

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from sandfort.domain.org import Scope
from sandfort.drivers.base import InstanceInfo, SandboxSpec
from sandfort.drivers.docker.client import DISK_FULL_MESSAGE
from sandfort.drivers.docker.containers import create_container
from sandfort.drivers.docker.images import classify_pull_failure, pull_image, pull_image_digest
from sandfort.drivers.errors import (
    DriverAccessDenied,
    DriverConflict,
    DriverError,
    DriverInvalidReference,
    DriverNotFound,
    DriverRegistryUnreachable,
    DriverTimeout,
)
from sandfort.drivers.fake import FakeDriver
from sandfort.services.sandbox_jobs import failure_reason
from test_api_sandboxes import BASE, add_org, migrated_app, seed_key, send
from test_docker_driver_unit import (
    DISK_FULL_RAW,
    REGISTRY_UNREACHABLE,
    SETTINGS,
    FakeClient,
    daemon_error,
    failing_pull_client,
    make_spec,
)

errors = pytest.importorskip("docker.errors")

PULL_HELPERS = [pull_image, pull_image_digest]
REF = "registry.example/team/app:1"
FORBIDDEN_REF = "forbidden/x:1"
ECR_DENIAL = (
    "Head https://ecr/v2/x: denied: User: arn:aws:sts::123456789012:assumed-role/h "
    "is not authorized"
)
READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})


def refused(reference: str) -> str:
    return (
        f"the registry refused to pull {reference}; check the image name and the registry access"
    )


# -- the image reference is not evidence ----------------------------------------------------


@pytest.mark.parametrize("helper", PULL_HELPERS)
@pytest.mark.parametrize(
    "text",
    [
        'failed to resolve reference "docker.io/forbidden/x:1": dial tcp: lookup '
        "registry-1.docker.io: no such host",
        "Get registry-1.docker.io/forbidden/x:1: dial tcp: lookup registry-1.docker.io: "
        "no such host",
        "forbidden/x:1: dial tcp 10.0.0.1:443: i/o timeout",
        "forbidden/x:1: dial tcp 10.0.0.1:443: connect: connection refused",
    ],
)
async def test_network_failure_for_a_reference_named_forbidden_is_unreachable(
    helper: Any, text: str
) -> None:
    client = failing_pull_client(daemon_error(errors.APIError, 500, text))
    with pytest.raises(DriverRegistryUnreachable) as caught:
        await helper(client, FORBIDDEN_REF)
    assert str(caught.value) == REGISTRY_UNREACHABLE.format(ref=FORBIDDEN_REF)
    assert caught.value.ref == FORBIDDEN_REF


@pytest.mark.parametrize("word", ["forbidden", "unauthorized", "denied", "access-denied"])
def test_a_denial_word_in_the_reference_alone_is_not_a_refusal(word: str) -> None:
    reference = f"acme/{word}-fruit:1.0"
    exc = DriverError(f"the daemon could not handle {reference}: the daemon is overloaded")
    classified = classify_pull_failure(exc, reference)
    assert type(classified) is DriverError
    assert str(classified) == f"could not pull {reference}"


def test_transport_failure_in_the_daemon_words_wins_over_an_access_denied_phrase() -> None:
    # The dial failure is in the daemon's own words, BEFORE any registry echo (round 69): a
    # token fetch that could not dial. Transport words inside a registry's answered body do
    # not unclassify it; see test_pull_body_network_text_r69.py.
    exc = DriverError("failed to authorize: dial tcp 10.0.0.1:443: i/o timeout")
    assert type(classify_pull_failure(exc, REF)) is DriverRegistryUnreachable


@pytest.mark.parametrize(
    "text",
    [
        "Head https://r.example/v2/x/manifests/1: context deadline exceeded",
        "Get https://r.example/v2/: net/http: request canceled (Client.Timeout exceeded while "
        "awaiting headers)",
        "CONTEXT DEADLINE EXCEEDED",
    ],
)
def test_deadline_and_header_timeouts_are_registry_unreachable(text: str) -> None:
    classified = classify_pull_failure(DriverError(text), REF)
    assert type(classified) is DriverRegistryUnreachable


@pytest.mark.parametrize(
    "text",
    [
        "denied: requested access to the resource is denied",
        "unauthorized: authentication required",
        "error from registry: denied: access forbidden",
        "failed to authorize: unexpected status: 401 Unauthorized",
        "unexpected status: 403 Forbidden",
        "Head: unauthorized",
    ],
)
def test_anchored_refusal_phrases_are_access_denied(text: str) -> None:
    classified = classify_pull_failure(DriverError(text), REF)
    assert type(classified) is DriverAccessDenied
    assert str(classified) == refused(REF)


@pytest.mark.parametrize("text", ["access forbidden", "forbidden", "unauthorized", "denied by x"])
def test_bare_words_are_not_refusal_phrases(text: str) -> None:
    classified = classify_pull_failure(DriverError(text), REF)
    assert type(classified) is DriverError
    assert str(classified) == f"could not pull {REF}"


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_ecr_denial_is_access_denied(helper: Any) -> None:
    client = failing_pull_client(daemon_error(errors.APIError, 500, ECR_DENIAL))
    with pytest.raises(DriverAccessDenied) as caught:
        await helper(client, REF)
    assert type(caught.value) is DriverAccessDenied
    assert caught.value.ref == REF


# -- the tenant-visible reason ---------------------------------------------------------------


def test_access_denied_exception_is_fixed_and_leaks_nothing() -> None:
    classified = classify_pull_failure(DriverError(ECR_DENIAL), REF)
    assert isinstance(classified, DriverAccessDenied)
    assert str(classified) == refused(REF)
    assert "arn:" not in str(classified)
    assert "123456789012" not in str(classified)
    assert failure_reason(classified) == refused(REF)


def test_invalid_reference_exception_names_the_reference_and_no_host_text() -> None:
    text = "invalid reference format: repository name must be lowercase (host ecr.internal:5000)"
    classified = classify_pull_failure(DriverError(text), "Team/App:1")
    assert type(classified) is DriverInvalidReference
    assert str(classified) == "invalid image reference Team/App:1: invalid reference format"
    assert "ecr.internal" not in str(classified)
    assert "lowercase" not in str(classified)
    assert failure_reason(classified) == str(classified)


def test_failure_reason_is_the_exception_message() -> None:
    exc = DriverInvalidReference("invalid image reference Team/App:1", ref="Team/App:1")
    assert failure_reason(exc) == "invalid image reference Team/App:1"


def test_other_failures_keep_their_message() -> None:
    assert failure_reason(DriverError("boom", ref=REF)) == "boom"
    unreachable = DriverRegistryUnreachable("no answer", ref=REF)
    assert failure_reason(unreachable) == "no answer"


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
    org_id = await add_org(app, "pullclass-r35")
    return await seed_key(app, org_id, READ_WRITE)


async def create_failing_with(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    monkeypatch: pytest.MonkeyPatch,
    failure: DriverError,
) -> dict[str, Any]:
    driver = app.state.driver
    assert isinstance(driver, FakeDriver)

    async def failing_create(spec: SandboxSpec) -> InstanceInfo:
        raise failure

    monkeypatch.setattr(driver, "create", failing_create)
    body = await send(client, "POST", BASE, key, status=201, json={"snapshot": REF})
    created: dict[str, Any] = body["data"]
    assert created["state"] == "error"
    fetched = await send(client, "GET", f"{BASE}/{created['id']}", key, status=200)
    record: dict[str, Any] = fetched["data"]
    return record


async def test_recorded_reason_of_an_ecr_denial_has_no_identity(
    app: FastAPI, client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    failure = classify_pull_failure(DriverError(ECR_DENIAL), REF)
    assert isinstance(failure, DriverAccessDenied)
    record = await create_failing_with(app, client, key, monkeypatch, failure)
    assert record["error_code"] == "image_access_denied"
    assert record["error_reason"] == refused(REF)
    assert "arn:" not in record["error_reason"]
    assert "123456789012" not in record["error_reason"]


async def test_recorded_reason_of_an_invalid_reference_has_no_daemon_host_text(
    app: FastAPI, client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = "invalid reference format: lookup ecr.internal:5000 failed"
    failure = classify_pull_failure(DriverError(text), REF)
    assert isinstance(failure, DriverInvalidReference)
    record = await create_failing_with(app, client, key, monkeypatch, failure)
    assert record["error_code"] == "invalid_image_reference"
    assert REF in record["error_reason"]
    assert "ecr.internal" not in record["error_reason"]
    assert "lookup" not in record["error_reason"]


# -- unchanged paths -------------------------------------------------------------------------


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_not_found_path_is_unchanged(helper: Any) -> None:
    client = failing_pull_client(daemon_error(errors.NotFound, 404, f"No such image: {REF}"))
    with pytest.raises(DriverNotFound) as caught:
        await helper(client, REF)
    assert type(caught.value) is DriverNotFound
    assert str(caught.value) == f"no such image or snapshot: {REF}"


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_pull_denial_sentence_is_still_a_not_found(helper: Any) -> None:
    text = (
        "pull access denied for team/app, repository does not exist or may require "
        "'docker login': denied: requested access to the resource is denied"
    )
    client = failing_pull_client(daemon_error(errors.APIError, 500, text))
    with pytest.raises(DriverNotFound) as caught:
        await helper(client, REF)
    assert str(caught.value) == f"no such image or snapshot: {REF}"


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_disk_full_path_is_unchanged(helper: Any) -> None:
    client = failing_pull_client(daemon_error(errors.APIError, 500, DISK_FULL_RAW))
    with pytest.raises(DriverConflict) as caught:
        await helper(client, REF)
    assert type(caught.value) is DriverConflict
    assert str(caught.value) == DISK_FULL_MESSAGE
    assert failure_reason(caught.value) == DISK_FULL_MESSAGE


# -- second review: containerd, GHCR and ECR shapes; tenant-safe exceptions -----------------

CONTAINERD_REF = "ghcr.io/org/img:1"
TOKEN_URL = "https://auth.example.net/token?scope=repository%3Aorg%2Fimg%3Apull&service=ghcr.io"
CONTAINERD_TEXTS = [
    f'failed to resolve reference "{CONTAINERD_REF}": failed to authorize: failed to fetch '
    f"anonymous token: unexpected status from GET request to {TOKEN_URL}: 403 Forbidden",
    f'failed to resolve reference "{CONTAINERD_REF}": failed to authorize: failed to fetch '
    f"oauth token: unexpected status from GET request to {TOKEN_URL}: 401 Unauthorized",
]
GHCR_BARE_DENIED = 'Head "https://ghcr.io/v2/org/img/manifests/1": denied'
REGISTRY_BARE_DENIED = "error from registry: denied"
ECR_NO_BASIC_AUTH = (
    "Get https://123456789012.dkr.ecr.eu-west-1.amazonaws.com/v2/team/app/manifests/1: "
    "no basic auth credentials"
)
DENIED_TEXTS = [*CONTAINERD_TEXTS, GHCR_BARE_DENIED, REGISTRY_BARE_DENIED, ECR_NO_BASIC_AUTH]
DAEMON_HOSTS = ("auth.example.net", "ghcr.io", "amazonaws.com", "ecr")
SAFE_REF = "team/app:1"  # names none of the daemon hosts above


@pytest.mark.parametrize("helper", PULL_HELPERS)
@pytest.mark.parametrize("text", CONTAINERD_TEXTS)
async def test_containerd_token_status_is_access_denied(helper: Any, text: str) -> None:
    client = failing_pull_client(daemon_error(errors.APIError, 500, text))
    with pytest.raises(DriverAccessDenied) as caught:
        await helper(client, CONTAINERD_REF)
    assert type(caught.value) is DriverAccessDenied
    assert str(caught.value) == refused(CONTAINERD_REF)


@pytest.mark.parametrize("helper", PULL_HELPERS)
@pytest.mark.parametrize("text", [GHCR_BARE_DENIED, REGISTRY_BARE_DENIED, ECR_NO_BASIC_AUTH])
async def test_bare_denied_and_no_basic_auth_are_access_denied(helper: Any, text: str) -> None:
    client = failing_pull_client(daemon_error(errors.APIError, 500, text))
    with pytest.raises(DriverAccessDenied) as caught:
        await helper(client, SAFE_REF)
    assert str(caught.value) == refused(SAFE_REF)


@pytest.mark.parametrize("text", DENIED_TEXTS)
def test_an_answered_refusal_beats_a_transport_phrase_in_the_same_text(text: str) -> None:
    probe = f"{text}\nlookup ghcr.io: no such host"
    assert type(classify_pull_failure(DriverError(probe), SAFE_REF)) is DriverAccessDenied


def test_failed_to_authorize_around_a_dial_failure_stays_unreachable() -> None:
    text = (
        f'failed to resolve reference "{CONTAINERD_REF}": failed to authorize: failed to fetch '
        "anonymous token: dial tcp: lookup auth.example.net: no such host"
    )
    classified = classify_pull_failure(DriverError(text), CONTAINERD_REF)
    assert type(classified) is DriverRegistryUnreachable


@pytest.mark.parametrize("reference", ["denied", "unauthorized"])
def test_a_reference_named_like_a_marker_does_not_erase_it(reference: str) -> None:
    text = (
        f"Head https://ecr/v2/{reference}/manifests/latest: denied: User: "
        "arn:aws:sts::123456789012:assumed-role/h is not authorized"
    )
    classified = classify_pull_failure(DriverError(text), reference)
    assert type(classified) is DriverAccessDenied
    assert str(classified) == refused(reference)


def test_a_reference_named_denied_with_a_bare_ecr_denial_is_access_denied() -> None:
    classified = classify_pull_failure(DriverError("error from registry: denied"), "denied")
    assert type(classified) is DriverAccessDenied


@pytest.mark.parametrize(
    "text",
    [
        *DENIED_TEXTS,
        ECR_DENIAL,
        "invalid reference format: repository name must be lowercase (host ecr.internal)",
    ],
)
def test_no_access_denied_or_invalid_reference_message_quotes_the_daemon(text: str) -> None:
    classified = classify_pull_failure(DriverError(text), SAFE_REF)
    assert isinstance(classified, DriverAccessDenied | DriverInvalidReference)
    assert "arn:" not in str(classified)
    assert "123456789012" not in str(classified)
    for host in DAEMON_HOSTS:
        assert host not in str(classified)


def test_an_unclassified_failure_quoting_a_host_identity_is_wrapped() -> None:
    text = "registry hiccup for arn:aws:iam::123456789012:role/pull, try later"
    classified = classify_pull_failure(DriverError(text), REF)
    assert type(classified) is DriverError
    assert str(classified) == f"could not pull {REF}"
    assert classified.ref == REF


# -- the reset service records the same tenant-safe text ------------------------------------


async def test_a_reset_refused_by_the_registry_records_the_fixed_text(
    app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    org_id = await add_org(app, "reset-pull-r35")
    token = await seed_key(app, org_id, READ_WRITE | {Scope.AUDIT_READ})
    sandbox_id = (await send(client, "POST", BASE, token, status=201, json={}))["data"]["id"]
    driver = app.state.driver
    assert isinstance(driver, FakeDriver)
    images: list[str] = []

    async def failing_create(spec: SandboxSpec) -> InstanceInfo:
        images.append(spec.image)
        raise classify_pull_failure(DriverError(ECR_DENIAL), spec.image)

    monkeypatch.setattr(driver, "create", failing_create)
    body = await send(client, "POST", f"{BASE}/{sandbox_id}/reset", token, status=502)
    fetched = (await send(client, "GET", f"{BASE}/{sandbox_id}", token, status=200))["data"]
    params = {"action": "sandbox.reset_failed", "target_id": sandbox_id}
    audit = await send(client, "GET", "/v1/audit-events", token, status=200, params=params)
    [event] = audit["data"]
    [image] = images
    assert fetched["error_code"] == "reset_failed"
    for text in (body["error"]["message"], fetched["error_reason"], event["details"]["error"]):
        assert text == refused(image)
        assert "arn:" not in text
        assert "123456789012" not in text


# -- third review: leading "denied", fixed unclassified text, TLS and EOF ---------------------

LEADING_DENIALS = [
    "denied",
    "denied: User: assumed-role/h/i is not authorized to perform: ecr:BatchGetImage on "
    "resource: repository x",
]
# Round 67: a TLS validation failure is ``DriverRegistryTlsError`` (see test_pull_taxonomy_r67.py);
# an EOF stays a network condition.
EOF_TEXTS = [
    'Get "https://reg.corp/v2/team/app/manifests/1": EOF',
    "unexpected EOF",
]
LEAKY_TEXT = "registry hiccup on ip-10-1-2-3.corp.internal for account 123456789012, try later"


@pytest.mark.parametrize("helper", PULL_HELPERS)
@pytest.mark.parametrize("text", LEADING_DENIALS)
async def test_denied_opening_the_text_or_a_line_is_access_denied(helper: Any, text: str) -> None:
    client = failing_pull_client(daemon_error(errors.APIError, 500, text))
    with pytest.raises(DriverAccessDenied) as caught:
        await helper(client, REF)
    assert str(caught.value) == refused(REF)
    assert "assumed-role" not in str(caught.value)


def test_denied_opening_a_later_line_is_access_denied() -> None:
    text = "pull failed\ndenied: User: assumed-role/h/i is not authorized\nlookup x: no such host"
    assert type(classify_pull_failure(DriverError(text), REF)) is DriverAccessDenied


def test_denied_by_phrasing_is_not_an_answered_denial() -> None:
    classified = classify_pull_failure(DriverError("denied by the local policy engine"), REF)
    assert type(classified) is DriverError


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_unclassified_text_gets_the_fixed_message(helper: Any) -> None:
    client = failing_pull_client(daemon_error(errors.APIError, 500, LEAKY_TEXT))
    with pytest.raises(DriverError) as caught:
        await helper(client, REF)
    assert type(caught.value) is DriverError
    assert str(caught.value) == f"could not pull {REF}"
    assert "123456789012" not in str(caught.value)
    assert "corp.internal" not in str(caught.value)


@pytest.mark.parametrize("cls", [DriverTimeout, DriverConflict, DriverError])
def test_unclassified_failure_keeps_its_own_type(cls: type[DriverError]) -> None:
    classified = classify_pull_failure(cls(LEAKY_TEXT, ref=REF), REF)
    assert type(classified) is cls
    assert str(classified) == f"could not pull {REF}"
    assert classified.ref == REF


@pytest.mark.parametrize("helper", PULL_HELPERS)
@pytest.mark.parametrize("text", EOF_TEXTS)
async def test_eof_failures_are_registry_unreachable(helper: Any, text: str) -> None:
    client = failing_pull_client(daemon_error(errors.APIError, 500, text))
    with pytest.raises(DriverRegistryUnreachable) as caught:
        await helper(client, REF)
    assert "corp" not in str(caught.value)
    assert caught.value.ref == REF


async def test_create_path_invalid_reference_equals_the_pull_path_form() -> None:
    reference = "Team/App:1"
    pulled = classify_pull_failure(DriverError("invalid reference format"), reference)
    client = FakeClient()
    client.create_results = [daemon_error(errors.APIError, 400, "invalid reference format")]
    with pytest.raises(DriverInvalidReference) as caught:
        await create_container(client, make_spec(image=reference), SETTINGS)
    assert type(pulled) is DriverInvalidReference
    assert str(caught.value) == str(pulled)
    assert caught.value.ref == pulled.ref == reference
