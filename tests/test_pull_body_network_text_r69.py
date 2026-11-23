"""Round 69 (SF75-001): network phrases inside a registry's 401/403 body do not unclassify it.

The partner's HTTPS registry answered a real 401 (``UNAUTHORIZED``) and a real 403 (``DENIED``)
whose message field was ``dial tcp: lookup backend.invalid: no such host`` — network words as
DATA, with no actual transport failure. The daemon echoes the body after its error code, and the
hard-transport guard used to scan the whole text, so the answer classified as the retryable
``registry_unreachable``. The guard must only read the daemon's own words BEFORE the registry's
``unauthorized:`` / ``denied:``; everything after the marker is the registry's body.

A transport failure the daemon itself reports (before any registry answer text) must stay
``registry_unreachable``.
"""

from typing import Any

import pytest

from sandfort.domain.sandbox import ERROR_INTERNAL
from sandfort.drivers.docker.images import classify_pull_failure, pull_image, pull_image_digest
from sandfort.drivers.errors import (
    DriverAccessDenied,
    DriverError,
    DriverRegistryUnreachable,
)
from sandfort.services.sandbox_jobs import driver_error_code
from test_docker_driver_unit import daemon_error, failing_pull_client

errors = pytest.importorskip("docker.errors")

PULL_HELPERS = [pull_image, pull_image_digest]
REF = "reg.example/probe/body-network:v1"
REPO = "reg.example/probe/body-network"
SENTENCE = f"pull access denied for {REPO}, repository does not exist or may require 'docker login'"
NETWORK_BODY = "dial tcp: lookup backend.invalid: no such host"
UNAUTHORIZED_401 = f"unauthorized: {NETWORK_BODY}"
DENIED_403 = f"{SENTENCE}: denied: {NETWORK_BODY}"


async def code_of(helper: Any, failure: Exception) -> str:
    with pytest.raises(DriverError) as caught:
        await helper(failing_pull_client(failure), REF)
    return driver_error_code(caught.value, fallback=ERROR_INTERNAL, image=REF)


def code_of_text(text: str) -> str:
    return driver_error_code(
        classify_pull_failure(DriverError(text), REF), fallback=ERROR_INTERNAL, image=REF
    )


# -- the two partner bodies: network words as registry data ------------------------------------


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_a_401_whose_body_names_a_dial_failure_is_access_denied(helper: Any) -> None:
    failure = daemon_error(errors.APIError, 401, UNAUTHORIZED_401)
    assert await code_of(helper, failure) == "image_access_denied"


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_a_403_whose_body_names_a_dial_failure_is_access_denied(helper: Any) -> None:
    failure = daemon_error(errors.NotFound, 404, DENIED_403)
    assert await code_of(helper, failure) == "image_access_denied"


def test_the_401_body_classifies_as_a_denial_not_unreachable() -> None:
    classified = classify_pull_failure(DriverError(UNAUTHORIZED_401), REF)
    assert isinstance(classified, DriverAccessDenied)


def test_an_eof_only_inside_the_body_is_still_a_denial() -> None:
    assert code_of_text("unauthorized: unexpected EOF while reading") == "image_access_denied"


def test_throttle_words_inside_the_body_are_still_a_denial() -> None:
    assert code_of_text("unauthorized: too many requests") == "image_access_denied"
    body_503 = f"{SENTENCE}: denied: received unexpected HTTP status: 503 Service Unavailable"
    assert code_of_text(body_503) == "image_access_denied"


# -- a transport failure the daemon itself reports stays unreachable ---------------------------


def test_a_dial_failure_before_the_marker_stays_unreachable() -> None:
    text = f'Get "https://reg.example/v2/": dial tcp: i/o timeout: unauthorized: {NETWORK_BODY}'
    classified = classify_pull_failure(DriverError(text), REF)
    assert isinstance(classified, DriverRegistryUnreachable)


def test_a_plain_dial_failure_without_any_marker_stays_unreachable() -> None:
    assert code_of_text(f'Get "https://reg.example/v2/": {NETWORK_BODY}') == "registry_unreachable"


def test_a_token_fetch_that_could_not_dial_stays_unreachable() -> None:
    text = (
        "failed to authorize: failed to fetch anonymous token: "
        'Get "https://auth.reg.example/token": dial tcp: lookup auth.reg.example: no such host'
    )
    assert code_of_text(text) == "registry_unreachable"
