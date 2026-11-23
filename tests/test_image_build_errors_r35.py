"""Round 35 (third review): a docker build error never reaches the tenant verbatim.

The build runs through ``build.start_build`` on a fake docker-py client whose ``api.build``
returns a decoded progress stream (the fake-stream shape of the docker build starvation test).
A base-image pull failure is classified like a pull of the Dockerfile's first ``FROM``; any other
error becomes a fixed sentence. The raw daemon text only reaches the debug log.
"""

import logging
import time
from collections.abc import Iterator, Mapping, Sequence
from types import SimpleNamespace
from typing import Any

import pytest
from docker import errors

from sandfort.drivers.docker import build, lanes
from sandfort.drivers.errors import (
    DriverAccessDenied,
    DriverError,
    DriverNotFound,
    DriverRegistryTlsError,
    DriverTimeout,
)
from test_docker_driver_unit import daemon_error

TAG = "sf-snap:1"
BASE = "registry.example/team/base:1"
ACCOUNT_ID = "123456789012"
ECR_FROM_DENIAL = (
    f"Head https://{ACCOUNT_ID}.dkr.ecr.eu-west-1.amazonaws.com/v2/team/base/manifests/1: "
    f"denied: User: arn:aws:sts::{ACCOUNT_ID}:assumed-role/sandfort-host/i-0abc is not "
    f"authorized to perform: ecr:BatchGetImage on resource: "
    f"arn:aws:ecr:eu-west-1:{ACCOUNT_ID}:repository/team/base"
)
STEP_FAILURE = "The command '/bin/sh -c curl https://x.corp/a' returned a non-zero code: 6"
OTHER_FAILURE = f"failed to register layer on host build-7.corp.internal for {ACCOUNT_ID}"
TLS_FAILURE = 'Get "https://registry.example/v2/": x509: certificate is valid for a.corp, not b'
IMAGE_ID = "sha256:" + "a" * 64
CLASSIC_STEP_SENTENCE = "image build failed: a build step exited with a non-zero code (exit code 6)"
BUILDKIT_STEP_FAILURE = (
    'process "/bin/sh -c echo exit code: 9 && false" did not complete successfully: exit code: 1'
)
BUILDKIT_STEP_SENTENCE = (
    "image build failed: a build step exited with a non-zero code (exit code 1)"
)
PULL_DENIAL_404 = (
    "pull access denied for registry.example/team/base, repository does not exist or may "
    "require 'docker login': denied: requested access to the resource is denied"
)
NOT_FOUND_SENTENCE = f"image build failed: no such image or snapshot: {BASE}"
REFUSED_SENTENCE = (
    f"image build failed: the registry refused to pull {BASE}; check the image name and "
    "the registry access"
)


@pytest.fixture(autouse=True)
def default_lanes() -> Iterator[None]:
    """Fresh lanes: an earlier test may have closed the shared ones with its driver."""
    lanes.configure_thread_limit()
    yield
    lanes.configure_thread_limit()


def fake_client(chunks: Sequence[Mapping[str, Any]]) -> SimpleNamespace:
    """A docker-py client whose build streams ``chunks`` and whose inspect knows the tag."""
    return SimpleNamespace(
        api=SimpleNamespace(
            build=lambda **_: iter(list(chunks)),
            inspect_image=lambda ref: {"Id": IMAGE_ID},
        )
    )


def failing_stream(error: str) -> list[dict[str, Any]]:
    return [
        {"stream": f"Step 1/2 : FROM {BASE}\n"},
        {"error": error, "errorDetail": {"message": error}},
    ]


def context(base: str = BASE) -> dict[str, bytes]:
    return {"Dockerfile": f"FROM {base}\nRUN true\n".encode()}


async def start(chunks: Sequence[Mapping[str, Any]], base: str = BASE) -> Any:
    return await build.start_build(
        fake_client(chunks), context(base), TAG, cpu_millicores=1000, memory_mib=256, timeout_s=30
    )


async def run_failing_build(error: str) -> tuple[list[str], DriverError]:
    handle = await start(failing_stream(error))
    with pytest.raises(DriverError) as caught:
        await handle.result()
    lines = [line async for line in handle.logs()]
    return lines, caught.value


async def test_an_ecr_from_denial_leaks_no_identity(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger=build.__name__)
    lines, exc = await run_failing_build(ECR_FROM_DENIAL)
    assert type(exc) is DriverAccessDenied
    assert exc.ref == TAG
    assert lines[-1] == str(exc)
    assert str(exc) == (
        f"image build failed: the registry refused to pull {BASE}; check the image name and "
        "the registry access"
    )
    for text in (*lines, str(exc)):
        assert "arn:" not in text
        assert ACCOUNT_ID not in text
        assert "assumed-role" not in text
    assert "arn:aws:sts" in caplog.text  # the raw daemon text is kept at debug level


async def test_a_from_tls_failure_is_registry_tls_error() -> None:
    lines, exc = await run_failing_build(TLS_FAILURE)
    assert type(exc) is DriverRegistryTlsError
    assert lines[-1] == str(exc)
    assert str(exc).startswith(f"image build failed: could not pull {BASE}: ")
    assert "a.corp" not in str(exc)


async def test_a_failed_step_gets_a_fixed_sentence() -> None:
    lines, exc = await run_failing_build(STEP_FAILURE)
    assert type(exc) is DriverError
    assert str(exc) == CLASSIC_STEP_SENTENCE
    assert lines[-1] == str(exc)
    assert "x.corp" not in str(exc)


async def test_any_other_build_error_gets_a_fixed_sentence() -> None:
    lines, exc = await run_failing_build(OTHER_FAILURE)
    assert type(exc) is DriverError
    assert str(exc) == "image build failed: the Docker daemon could not complete the build"
    assert lines[-1] == str(exc)
    for text in (*lines, str(exc)):
        assert ACCOUNT_ID not in text
        assert "corp.internal" not in text


async def test_an_http_error_from_the_build_call_is_classified_too() -> None:
    response = SimpleNamespace(status_code=500, reason="x", url="http+docker://localhost/v1.43")

    def refuse(**_: Any) -> Iterator[Any]:
        raise errors.APIError("500 Server Error", response=response, explanation=ECR_FROM_DENIAL)

    client = SimpleNamespace(api=SimpleNamespace(build=refuse))
    handle = await build.start_build(
        client, context(), TAG, cpu_millicores=1000, memory_mib=256, timeout_s=30
    )
    with pytest.raises(DriverError) as caught:
        await handle.result()
    lines = [line async for line in handle.logs()]
    assert type(caught.value) is DriverAccessDenied
    assert lines == [str(caught.value)]
    assert str(caught.value) == (
        f"image build failed: the registry refused to pull {BASE}; check the image name and "
        "the registry access"
    )
    for text in (*lines, str(caught.value)):
        assert "arn:" not in text
        assert ACCOUNT_ID not in text


async def run_refused_build(error: Exception) -> tuple[list[str], DriverError]:
    """A build whose ``api.build`` call itself raises ``error`` (an HTTP error status)."""

    def refuse(**_: Any) -> Iterator[Any]:
        raise error

    client = SimpleNamespace(api=SimpleNamespace(build=refuse))
    handle = await build.start_build(
        client, context(), TAG, cpu_millicores=1000, memory_mib=256, timeout_s=30
    )
    with pytest.raises(DriverError) as caught:
        await handle.result()
    return [line async for line in handle.logs()], caught.value


HTTP_ERROR_ROWS = [
    pytest.param(errors.APIError, 500, ECR_FROM_DENIAL, DriverAccessDenied, REFUSED_SENTENCE,
                 id="ecr-denial"),
    pytest.param(errors.NotFound, 404, PULL_DENIAL_404, DriverNotFound, NOT_FOUND_SENTENCE,
                 id="404-pull-denial"),
    pytest.param(errors.APIError, 500, STEP_FAILURE, DriverError, CLASSIC_STEP_SENTENCE,
                 id="classic-step"),
    pytest.param(errors.APIError, 500, BUILDKIT_STEP_FAILURE, DriverError,
                 BUILDKIT_STEP_SENTENCE, id="buildkit-step"),
]  # fmt: skip


@pytest.mark.parametrize(("cls", "status", "text", "kind", "sentence"), HTTP_ERROR_ROWS)
async def test_an_http_build_error_classifies_like_the_same_text_in_the_stream(
    cls: type[Exception], status: int, text: str, kind: type[DriverError], sentence: str
) -> None:
    lines, exc = await run_refused_build(daemon_error(cls, status, text))
    assert type(exc) is kind
    assert str(exc) == sentence
    assert lines == [sentence]
    _, streamed = await run_failing_build(text)
    assert (type(streamed), str(streamed)) == (kind, sentence)
    for leaked in (ACCOUNT_ID, "x.corp", "echo", "docker login", "the Docker daemon could not"):
        assert leaked not in str(exc)


@pytest.mark.parametrize(
    "text", [f"No such image: {BASE}", "stat /var/lib/docker/x: no such file"]
)
async def test_a_404_build_error_keeps_its_not_found_type(text: str) -> None:
    lines, exc = await run_refused_build(daemon_error(errors.NotFound, 404, text))
    assert type(exc) is DriverNotFound
    assert str(exc) == NOT_FOUND_SENTENCE
    assert lines == [NOT_FOUND_SENTENCE]
    assert "/var/lib/docker" not in str(exc)


async def test_an_unclassified_http_build_error_gets_the_daemon_sentence() -> None:
    _, exc = await run_refused_build(daemon_error(errors.APIError, 500, OTHER_FAILURE))
    assert type(exc) is DriverError
    assert str(exc) == "image build failed: the Docker daemon could not complete the build"
    assert "corp.internal" not in str(exc)


async def test_a_buildkit_step_failure_naming_certificate_is_a_step_failure() -> None:
    error = (
        'process "/bin/sh -c apt-get install -y certificate eof" did not complete '
        "successfully: exit code: 1"
    )
    lines, exc = await run_failing_build(error)
    assert type(exc) is DriverError
    assert str(exc) == "image build failed: a build step exited with a non-zero code (exit code 1)"
    assert lines[-1] == str(exc)
    assert "certificate" not in str(exc)


async def test_a_build_timeout_from_the_deadline_is_not_reclassified() -> None:
    def slow(**_: Any) -> Iterator[Any]:
        time.sleep(0.5)
        return iter([])

    client = SimpleNamespace(api=SimpleNamespace(build=slow))
    handle = await build.start_build(
        client, context(), TAG, cpu_millicores=1000, memory_mib=256, timeout_s=0.05
    )
    with pytest.raises(DriverTimeout):
        await handle.result()


async def test_a_clean_build_keeps_its_progress_lines() -> None:
    chunks = [{"stream": "Step 1/1 : FROM alpine\n"}, {"stream": "Successfully built x\n"}]
    handle = await start(chunks, base="alpine")
    assert await handle.result() == IMAGE_ID
    assert [line async for line in handle.logs()] == [
        "Step 1/1 : FROM alpine",
        "Successfully built x",
    ]


@pytest.mark.parametrize(
    ("dockerfile", "expected"),
    [
        (b"FROM alpine:3.20\nRUN true\n", "alpine:3.20"),
        (b"# comment\nfrom --platform=linux/amd64 team/app:1 AS base\n", "team/app:1"),
        (b"RUN true\n", "the base image"),
    ],
)
def test_base_image_is_the_first_from(dockerfile: bytes, expected: str) -> None:
    assert build.base_image({"Dockerfile": dockerfile}) == expected


def test_base_image_without_a_dockerfile_is_the_fixed_phrase() -> None:
    assert build.base_image({}) == "the base image"
