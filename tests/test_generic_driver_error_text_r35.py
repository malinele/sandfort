"""Round 35, fourth review: unclassified daemon text never reaches a tenant.

The generic branch of ``as_driver_error`` gives the tenant one fixed sentence and logs the
cleaned daemon text with the operation name. The classified branches keep their specific
messages. The API answers use the fake driver with a temp SQLite database, the same way the
other round-35 tests stage a failing driver call.
"""

import logging
import pickle
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from sandfort.domain.org import Scope
from sandfort.drivers.base import InstanceInfo, SandboxSpec
from sandfort.drivers.docker import client as docker_client
from sandfort.drivers.docker import image_export
from sandfort.drivers.docker.client import GENERIC_DRIVER_MESSAGE, as_driver_error, translate_errors
from sandfort.drivers.docker.images import classify_pull_failure, pull_image
from sandfort.drivers.errors import (
    DriverAccessDenied,
    DriverConflict,
    DriverError,
    DriverNotFound,
)
from sandfort.drivers.fake import FakeDriver
from sandfort.observability import tracing
from test_api_sandboxes import BASE, add_org, migrated_app, seed_key, send
from test_docker_driver_unit import daemon_error, failing_pull_client

errors = pytest.importorskip("docker.errors")

FIXED_SENTENCE = "the sandbox runtime reported an error; the details are in the server log"
SOCKET_PATH = "/var/run/docker.sock"
INTERNAL_HOST = "build-07.corp.internal"
ACCOUNT_ID = "123456789012"
LEAKY_TEXT = (
    f"failed to create task for container: OCI runtime create failed: cannot use {SOCKET_PATH} "
    f"(node {INTERNAL_HOST}, account {ACCOUNT_ID})"
)
LEAKED_WORDS = (SOCKET_PATH, "docker.sock", INTERNAL_HOST, ACCOUNT_ID, "OCI", "runtime create")
SNAPSHOTS = "/v1/snapshots"
READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
SNAPSHOT_SCOPES = frozenset({Scope.SNAPSHOTS_READ, Scope.SNAPSHOTS_WRITE})


def leaky_error() -> Exception:
    return daemon_error(errors.APIError, 500, LEAKY_TEXT)


def assert_no_leak(text: str) -> None:
    for word in LEAKED_WORDS:
        assert word not in text


# -- the mapping -----------------------------------------------------------------------------


def test_the_fixed_sentence_is_the_documented_one() -> None:
    assert GENERIC_DRIVER_MESSAGE == FIXED_SENTENCE


def test_an_unclassified_api_error_carries_only_the_fixed_sentence() -> None:
    mapped = as_driver_error(leaky_error(), ref="sf-1")
    assert type(mapped) is DriverError
    assert mapped.message == FIXED_SENTENCE
    assert mapped.ref == "sf-1"
    assert_no_leak(mapped.message)


def test_the_fixed_sentence_is_kept_without_a_ref() -> None:
    mapped = as_driver_error(leaky_error())
    assert mapped is not None
    assert mapped.message == FIXED_SENTENCE
    assert mapped.ref is None


def test_a_docker_exception_without_a_status_gets_the_fixed_sentence_too() -> None:
    mapped = as_driver_error(errors.DockerException(f"cannot reach {SOCKET_PATH}"))
    assert mapped is not None
    assert mapped.message == FIXED_SENTENCE


def test_translate_errors_raises_the_fixed_sentence() -> None:
    with pytest.raises(DriverError) as caught, translate_errors("sf-1", "exec"):
        raise leaky_error()
    assert caught.value.message == FIXED_SENTENCE
    assert caught.value.ref == "sf-1"


def test_the_cleaned_daemon_text_is_logged_with_the_operation(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=docker_client.logger.name):
        with pytest.raises(DriverError), translate_errors("sf-1", "container start"):
            raise leaky_error()
    records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(records) == 1
    logged = records[0].getMessage()
    assert "container start" in logged
    assert "sf-1" in logged
    assert INTERNAL_HOST in logged  # the detail is for the server log
    assert "http+docker" not in logged  # the cleaned text, not the raw one


# -- fifth review: daemon text travels out of band ------------------------------------------

# Texts the pull classifier recognises (certificate, EOF, lookup) that come from other calls.
OUT_OF_BAND_LEAKS = [
    pytest.param(
        "OCI runtime create failed: open /etc/sandfort/pki/certificate.pem: permission denied "
        "(node runner-4.corp.internal)",
        "container.start",
        ("certificate.pem", "runner-4.corp.internal", "/etc/sandfort"),
        id="oci-certificate",
    ),
    pytest.param(
        "unexpected EOF reading /srv/tenants/acme/state.json",
        "archive.get",
        ("/srv/tenants", "acme", "state.json", "EOF"),
        id="eof-tenant-path",
    ),
    pytest.param(
        "failed to start shim: lookup vsock: connection refused",
        "exec.start",
        ("vsock", "shim", "lookup"),
        id="shim-lookup",
    ),
]


@pytest.mark.parametrize(("text", "operation", "secrets"), OUT_OF_BAND_LEAKS)
def test_pull_like_text_from_another_operation_gets_the_fixed_sentence(
    text: str, operation: str, secrets: tuple[str, ...]
) -> None:
    with pytest.raises(DriverError) as caught, translate_errors("sf-1", operation):
        raise daemon_error(errors.APIError, 500, text)
    assert type(caught.value) is DriverError
    assert caught.value.message == FIXED_SENTENCE
    assert str(caught.value) == FIXED_SENTENCE
    assert caught.value.daemon_text == text
    for secret in secrets:
        assert secret not in str(caught.value)


def test_a_whitelisted_error_carries_no_daemon_text() -> None:
    mapped = as_driver_error(daemon_error(errors.NotFound, 404, "No such container: web"), "sf-1")
    assert mapped is not None
    assert mapped.daemon_text is None


def test_the_daemon_text_is_never_part_of_the_message() -> None:
    exc = DriverError("fixed", daemon_text="secret detail")
    assert str(exc) == exc.message == "fixed"
    assert exc.args == ("fixed",)
    assert exc.classification_text == "secret detail"
    assert DriverError("fixed").classification_text == "fixed"


ECR_DENIAL = (
    "Head https://ecr/v2/x: denied: User: arn:aws:sts::123456789012:assumed-role/h "
    "is not authorized"
)
CONTAINERD_403 = (
    'failed to resolve reference "ghcr.io/org/img:1": failed to authorize: failed to fetch '
    "anonymous token: unexpected status from GET request to https://auth.example.net/token: "
    "403 Forbidden"
)
MANIFEST_UNKNOWN = "manifest for team/app:1 not found: manifest unknown: manifest unknown"
PULL_REF = "team/app:1"


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        pytest.param(ECR_DENIAL, DriverAccessDenied, id="ecr-denial"),
        pytest.param(CONTAINERD_403, DriverAccessDenied, id="containerd-403"),
        pytest.param(MANIFEST_UNKNOWN, DriverNotFound, id="not-found"),
    ],
)
async def test_the_pull_path_classifies_from_the_daemon_text(
    text: str, kind: type[DriverError]
) -> None:
    raw = daemon_error(errors.APIError, 500, text)
    mapped = as_driver_error(raw, ref=PULL_REF)
    assert mapped is not None
    assert mapped.message == FIXED_SENTENCE
    assert mapped.daemon_text == docker_client.clean_message(raw)
    assert type(classify_pull_failure(mapped, PULL_REF)) is kind
    with pytest.raises(DriverError) as caught:
        await pull_image(failing_pull_client(raw), PULL_REF)
    assert type(caught.value) is kind
    assert PULL_REF in str(caught.value)
    assert "123456789012" not in str(caught.value)
    assert "auth.example.net" not in str(caught.value)


def warning_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_the_warning_carries_the_operation_ref_and_job_ids(
    caplog: pytest.LogCaptureFixture,
) -> None:
    assert tracing._JOB_IDS.name == docker_client.JOB_IDS_CONTEXT_VAR
    ids = {tracing.ORG_ID_ATTR: "org_abc", tracing.SANDBOX_ID_ATTR: "sbx_def"}
    token = tracing._JOB_IDS.set(ids)
    try:
        with caplog.at_level(logging.WARNING, logger=docker_client.logger.name):
            with pytest.raises(DriverError), translate_errors("sf-1", "volume.create"):
                raise leaky_error()
    finally:
        tracing._JOB_IDS.reset(token)
    [record] = warning_records(caplog)
    logged = record.getMessage()
    assert "volume.create" in logged
    assert "ref=sf-1" in logged
    assert "sandfort.org_id=org_abc" in logged
    assert "sandfort.sandbox_id=sbx_def" in logged


def test_the_warning_has_no_job_ids_outside_a_job(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger=docker_client.logger.name):
        with pytest.raises(DriverError), translate_errors(None, "daemon.info"):
            raise leaky_error()
    [record] = warning_records(caplog)
    assert "daemon.info" in record.getMessage()
    assert "sandfort.org_id" not in record.getMessage()


def test_the_logged_daemon_text_is_bounded(caplog: pytest.LogCaptureFixture) -> None:
    long_text = "OCI runtime exec failed: " + "x" * 5000
    limit = docker_client.MAX_LOGGED_DAEMON_TEXT
    with caplog.at_level(logging.WARNING, logger=docker_client.logger.name):
        with pytest.raises(DriverError) as caught, translate_errors("sf-1", "exec.start"):
            raise daemon_error(errors.APIError, 500, long_text)
    [record] = warning_records(caplog)
    assert limit == 500
    assert record.getMessage().endswith(": " + long_text[:limit])
    assert caught.value.daemon_text == long_text  # only the log line is bounded


def test_the_pure_mapper_logs_nothing(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        mapped = docker_client.map_driver_error(leaky_error(), "sf-1")
    assert mapped is not None
    assert mapped.daemon_text == LEAKY_TEXT
    assert warning_records(caplog) == []


def test_remove_quietly_logs_nothing_on_a_not_found(caplog: pytest.LogCaptureFixture) -> None:
    def missing() -> None:
        raise daemon_error(errors.NotFound, 404, "no such container")

    with caplog.at_level(logging.DEBUG):
        image_export._remove_quietly(missing, "container")
    assert warning_records(caplog) == []


def test_remove_quietly_logs_one_warning_for_another_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def broken() -> None:
        raise leaky_error()

    with caplog.at_level(logging.DEBUG):
        image_export._remove_quietly(broken, "image")
    [record] = warning_records(caplog)
    assert record.name == image_export.logger.name


# -- the classified branches are unchanged ---------------------------------------------------


NOT_FOUND_FIXED = "the object does not exist"
CONFLICT_FIXED = "the operation conflicts with the current state"
STAT_404 = "stat /var/lib/docker/overlay2/abc/merged/etc/foo: no such file or directory"
MOUNT_409 = "cannot mount /srv/tenants/acme into container; busy at /var/lib/kata/x"


def test_a_host_path_not_found_gets_the_fixed_sentence() -> None:
    mapped = as_driver_error(daemon_error(errors.NotFound, 404, STAT_404), ref="sf-1")
    assert type(mapped) is DriverNotFound
    assert mapped.message == NOT_FOUND_FIXED
    assert mapped.daemon_text == STAT_404


def test_a_host_path_conflict_gets_the_fixed_sentence() -> None:
    mapped = as_driver_error(daemon_error(errors.APIError, 409, MOUNT_409), ref="sf-1")
    assert type(mapped) is DriverConflict
    assert mapped.message == CONFLICT_FIXED
    assert mapped.daemon_text == MOUNT_409


@pytest.mark.parametrize(
    ("exc_type", "status", "raw", "kind"),
    [
        (errors.NotFound, 404, "No such container: web", DriverNotFound),
        (errors.NotFound, 404, "No such image: alpine:3.20", DriverNotFound),
        (errors.NotFound, 404, "No such image: registry.io/team/app:v1", DriverNotFound),
        (errors.NotFound, 404, "No such volume: data", DriverNotFound),
        (errors.NotFound, 404, "No such exec instance 'ab12' found in daemon", DriverNotFound),
        (errors.APIError, 409, "container web is not running", DriverConflict),
        (errors.APIError, 409, "web is not running", DriverConflict),
        (errors.APIError, 409, 'container name "/web" is already in use', DriverConflict),
        (errors.APIError, 409, "removal of container web is already in progress", DriverConflict),
        (errors.APIError, 409, "container web is paused", DriverConflict),
    ],
)
def test_whitelisted_phrases_keep_their_message(
    exc_type: type[Exception], status: int, raw: str, kind: type[DriverError]
) -> None:
    mapped = as_driver_error(daemon_error(exc_type, status, raw), ref="sf-1")
    assert type(mapped) is kind
    assert mapped.message == raw
    assert mapped.daemon_text is None


def test_a_whitelisted_phrase_cannot_carry_a_path_behind_it() -> None:
    raw = "No such container: web at /var/lib/docker/containers/x"
    mapped = as_driver_error(daemon_error(errors.NotFound, 404, raw))
    assert mapped is not None
    assert mapped.message == NOT_FOUND_FIXED
    assert mapped.daemon_text == raw


def test_the_exec_gone_marker_and_the_not_running_phrase_survive() -> None:
    from sandfort.api.routes.toolbox.process import NOT_RUNNING_PHRASE
    from sandfort.drivers.docker.exec import EXEC_GONE_MARKER

    gone = as_driver_error(daemon_error(errors.NotFound, 404, "No such exec instance: ab12"))
    stopped = as_driver_error(daemon_error(errors.APIError, 409, "container web is not running"))
    assert gone is not None
    assert stopped is not None
    assert EXEC_GONE_MARKER in gone.message
    assert NOT_RUNNING_PHRASE in stopped.message


HEX64 = "0123456789abcdef" * 4
PLACEHOLDER = "the sandbox container"
STOPPED_REAL = f"Container {HEX64} is not running"
EXEC_GONE_REAL = f"No such exec instance: {HEX64}"
EXEC_GONE_FOUND_REAL = f"No such exec instance '{HEX64}' found in daemon"


def test_a_capitalised_container_reference_becomes_the_placeholder() -> None:
    capital = docker_client.clean_message(Exception(f"Container {HEX64} is paused"))
    lower = docker_client.clean_message(Exception(f"container {HEX64} is paused"))
    assert capital == lower == f"{PLACEHOLDER} is paused"


@pytest.mark.parametrize(
    ("exc_type", "status", "raw", "cleaned", "kind"),
    [
        (errors.APIError, 409, STOPPED_REAL, f"{PLACEHOLDER} is not running", DriverConflict),
        (
            errors.NotFound,
            404,
            EXEC_GONE_REAL,
            f"No such exec instance: {PLACEHOLDER}",
            DriverNotFound,
        ),
        (
            errors.NotFound,
            404,
            EXEC_GONE_FOUND_REAL,
            f"No such exec instance '{PLACEHOLDER}' found in daemon",
            DriverNotFound,
        ),
    ],
)
def test_real_daemon_ids_keep_the_markers_in_the_message(
    exc_type: type[Exception], status: int, raw: str, cleaned: str, kind: type[DriverError]
) -> None:
    from sandfort.api.routes.toolbox.process import NOT_RUNNING_PHRASE
    from sandfort.drivers.docker.exec import EXEC_GONE_MARKER

    mapped = as_driver_error(daemon_error(exc_type, status, raw), ref="sf-1")
    assert type(mapped) is kind
    assert mapped.message == cleaned
    assert mapped.daemon_text is None
    assert HEX64 not in mapped.message
    assert EXEC_GONE_MARKER in mapped.message or NOT_RUNNING_PHRASE in mapped.message


HEX12 = "0123456789ab"


@pytest.mark.parametrize("container_id", [HEX12, HEX64])
def test_a_not_found_container_id_keeps_the_wording_and_gets_the_placeholder(
    container_id: str,
) -> None:
    mapped = as_driver_error(
        daemon_error(errors.NotFound, 404, f"No such container: {container_id}"), ref="sf-1"
    )
    assert type(mapped) is DriverNotFound
    assert mapped.message == f"No such container: {PLACEHOLDER}"
    assert mapped.daemon_text is None
    assert container_id not in mapped.message


@pytest.mark.parametrize("exec_id", ["ab/cd", "$(x)"])
def test_an_odd_exec_id_falls_to_the_fixed_sentence(exec_id: str) -> None:
    raw = f"No such exec instance: {exec_id}"
    mapped = as_driver_error(daemon_error(errors.NotFound, 404, raw), ref="sf-1")
    assert type(mapped) is DriverNotFound
    assert mapped.message == NOT_FOUND_FIXED
    assert mapped.daemon_text == raw


@pytest.mark.parametrize("exec_id", [HEX12, HEX64, "ab12", "exec_1.x-y"])
def test_a_hex_or_plain_word_exec_id_keeps_its_message(exec_id: str) -> None:
    cleaned = PLACEHOLDER if exec_id == HEX64 else exec_id
    mapped = as_driver_error(
        daemon_error(errors.NotFound, 404, f"No such exec instance: {exec_id}"), ref="sf-1"
    )
    assert type(mapped) is DriverNotFound
    assert mapped.message == f"No such exec instance: {cleaned}"
    assert mapped.daemon_text is None


class _Call:
    """An awaitable that raises ``error`` when awaited, like a driver exec call."""

    def __init__(self, error: DriverError) -> None:
        self.error = error

    def __await__(self) -> Any:
        async def fail() -> None:
            raise self.error

        return fail().__await__()


async def run_watching_death(error: DriverError, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Run the process route's death watch over a failing call; return the death settlements."""
    from sandfort.api.routes.toolbox import process as process_route

    deaths: list[str] = []

    async def on_death(request: Any, driver: Any, sandbox: Any) -> None:
        deaths.append("died")

    monkeypatch.setattr(process_route, "_on_death", on_death)
    with pytest.raises(DriverConflict):
        await process_route._run_watching_death(None, None, None, _Call(error))  # type: ignore[arg-type]
    return deaths


async def test_the_process_route_detects_death_for_a_real_daemon_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = as_driver_error(daemon_error(errors.APIError, 409, STOPPED_REAL))
    assert isinstance(error, DriverConflict)
    assert await run_watching_death(error, monkeypatch) == ["died"]


async def test_the_process_route_reads_the_daemon_text_not_the_tenant_wording(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = DriverConflict(
        "the operation conflicts with the current state",
        daemon_text=f"{PLACEHOLDER} is not running",
    )
    assert await run_watching_death(error, monkeypatch) == ["died"]


async def test_the_process_route_ignores_an_unrelated_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = as_driver_error(daemon_error(errors.APIError, 409, f"Container {HEX64} is paused"))
    assert isinstance(error, DriverConflict)
    assert await run_watching_death(error, monkeypatch) == []


def test_unknown_driver_survives_pickling() -> None:
    from sandfort.drivers.registry import UnknownDriver

    error = UnknownDriver("nope", ["fake", "docker"])
    loaded = pickle.loads(pickle.dumps(error))  # noqa: S301 - a value built in this test
    assert type(loaded) is UnknownDriver
    assert loaded.message == error.message
    assert loaded.ref == "nope"
    assert loaded.known == ("docker", "fake")


def test_the_pull_denial_sentence_on_exec_gets_the_fixed_not_found_sentence() -> None:
    raw = (
        "pull access denied for x, repository does not exist or may require 'docker login' "
        "while reading /srv/tenants/acme/secret"
    )
    mapped = as_driver_error(daemon_error(errors.APIError, 500, raw), "sf-1", "exec.start")
    assert type(mapped) is DriverNotFound
    assert mapped.message == NOT_FOUND_FIXED
    assert mapped.daemon_text is not None
    assert "/srv/tenants/acme" in mapped.daemon_text


def test_the_pull_denial_sentence_on_a_pull_maps_to_not_found() -> None:
    raw = "pull access denied for x, repository does not exist or may require 'docker login'"
    mapped = as_driver_error(daemon_error(errors.APIError, 500, raw), "x", "image.pull")
    assert type(mapped) is DriverNotFound


def test_a_pull_failure_logs_at_info_and_an_exec_failure_at_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger=docker_client.logger.name)
    as_driver_error(daemon_error(errors.APIError, 500, LEAKY_TEXT), "x", "image.pull")
    as_driver_error(daemon_error(errors.APIError, 500, LEAKY_TEXT), "x", "image.build")
    assert [r.levelno for r in caplog.records] == [logging.INFO, logging.INFO]
    caplog.clear()
    as_driver_error(daemon_error(errors.APIError, 500, LEAKY_TEXT), "x", "exec.start")
    assert [r.levelno for r in caplog.records] == [logging.WARNING]


def test_pickling_drops_the_daemon_text() -> None:
    error = DriverNotFound(NOT_FOUND_FIXED, ref="sf-1", daemon_text=STAT_404)
    loaded = pickle.loads(pickle.dumps(error))  # noqa: S301 - a value built in this test
    assert type(loaded) is DriverNotFound
    assert loaded.message == NOT_FOUND_FIXED
    assert loaded.ref == "sf-1"
    assert loaded.daemon_text is None
    assert STAT_404 not in repr(vars(loaded))
    assert STAT_404 not in pickle.dumps(error).decode("latin-1")


def test_disk_full_keeps_its_fixed_conflict() -> None:
    raw = "mkdir /var/lib/docker/overlay2/x: no space left on device"
    mapped = as_driver_error(daemon_error(errors.APIError, 500, raw))
    assert type(mapped) is DriverConflict
    assert mapped.message == docker_client.DISK_FULL_MESSAGE


# -- through the API -------------------------------------------------------------------------


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    async with migrated_app(tmp_path) as application:
        yield application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


def fake_driver(app: FastAPI) -> FakeDriver:
    driver = app.state.driver
    assert isinstance(driver, FakeDriver)
    return driver


async def test_the_502_body_carries_the_fixed_sentence_only(
    app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    org_id = await add_org(app, "genericerr-r35")
    key = await seed_key(app, org_id, SNAPSHOT_SCOPES)

    async def failing_pull(reference: str) -> str:
        with translate_errors(reference, "pull"):
            raise leaky_error()
        return ""

    monkeypatch.setattr(fake_driver(app), "pull_image_digest", failing_pull)
    body = await send(
        client, "POST", SNAPSHOTS, key, status=502, json={"image": "registry.example/app:1"}
    )
    assert body["error"]["code"] == "DRIVER_ERROR"
    assert body["error"]["message"] == FIXED_SENTENCE
    assert_no_leak(str(body))


async def test_a_failed_create_records_the_fixed_sentence_as_the_error_reason(
    app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    org_id = await add_org(app, "genericreason-r35")
    key = await seed_key(app, org_id, READ_WRITE)

    async def failing_create(spec: SandboxSpec) -> InstanceInfo:
        with translate_errors(spec.name, "create"):
            raise leaky_error()
        raise AssertionError("unreachable")

    monkeypatch.setattr(fake_driver(app), "create", failing_create)
    created = await send(client, "POST", BASE, key, status=201, json={"snapshot": "alpine:3.20"})
    data = created["data"]
    assert data["state"] == "error"
    assert data["error_reason"] == FIXED_SENTENCE
    assert_no_leak(str(created))
