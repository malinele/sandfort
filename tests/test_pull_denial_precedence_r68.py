"""Round 68 (SF74-002): an answered 401/403 is ``image_access_denied``, whatever else the text says.

The partner's HTTPS registry answered a real 401 (``UNAUTHORIZED``) and a real 403 (``DENIED``)
whose body was a certificate sentence. The daemon echoes the registry body after its error code:

* 401: ``unauthorized: x509: certificate has expired`` (an ``APIError``). It used to be a TLS error
  because only the weak, last ``unauthorized: `` marker saw it and the TLS check ran first.
* 403: moby turns a ``DENIED`` answer into the not-found family, so the daemon text is
  ``pull access denied for <repo>, repository does not exist or may require 'docker login':
  denied: x509: certificate has expired`` (a 404 ``NotFound``). It used to be ``image_not_found``
  because the not-found branch is decided first and never looked at the registry body.

The Docker Hub privacy mapping stays: the same sentence with Hub's stock ``denied: requested
access to the resource is denied`` tail (or GHCR's bare ``denied: denied``) is still not found.
"""

from typing import Any

import pytest

from sandfort.domain.sandbox import ERROR_INTERNAL
from sandfort.drivers.docker.images import classify_pull_failure, pull_image, pull_image_digest
from sandfort.drivers.errors import (
    DriverAccessDenied,
    DriverError,
    DriverNotFound,
    DriverRegistryTlsError,
    DriverRegistryUnreachable,
)
from sandfort.services.sandbox_jobs import driver_error_code
from test_docker_driver_unit import daemon_error, failing_pull_client

errors = pytest.importorskip("docker.errors")

PULL_HELPERS = [pull_image, pull_image_digest]
REF = "reg.example/probe/unauthorized-tls:v1"
REPO = "reg.example/probe/unauthorized-tls"
SENTENCE = f"pull access denied for {REPO}, repository does not exist or may require 'docker login'"
CERT_BODY = "x509: certificate has expired"
UNAUTHORIZED_401 = f"unauthorized: {CERT_BODY}"
DENIED_403 = f"{SENTENCE}: denied: {CERT_BODY}"
THROTTLE = "toomanyrequests: You have reached your pull rate limit"
SERVER_ERROR = "received unexpected HTTP status: 503 Service Unavailable"


async def code_of(helper: Any, failure: Exception) -> str:
    with pytest.raises(DriverError) as caught:
        await helper(failing_pull_client(failure), REF)
    return driver_error_code(caught.value, fallback=ERROR_INTERNAL, image=REF)


def code_of_text(text: str) -> str:
    return driver_error_code(
        classify_pull_failure(DriverError(text), REF), fallback=ERROR_INTERNAL, image=REF
    )


# -- the two exact partner bodies, through the pull path to the error code ---------------------


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_401_unauthorized_with_a_certificate_body_is_access_denied(helper: Any) -> None:
    failure = daemon_error(errors.APIError, 401, UNAUTHORIZED_401)
    assert await code_of(helper, failure) == "image_access_denied"


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_401_with_the_request_prefix_is_access_denied(helper: Any) -> None:
    text = f'Head "https://reg.example/v2/probe/unauthorized-tls/manifests/v1": {UNAUTHORIZED_401}'
    failure = daemon_error(errors.APIError, 401, text)
    assert await code_of(helper, failure) == "image_access_denied"


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_403_denied_with_a_certificate_body_is_access_denied(helper: Any) -> None:
    failure = daemon_error(errors.NotFound, 404, DENIED_403)
    assert await code_of(helper, failure) == "image_access_denied"


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_403_denied_text_that_arrives_as_an_api_error_is_access_denied(helper: Any) -> None:
    failure = daemon_error(errors.APIError, 500, DENIED_403)
    assert await code_of(helper, failure) == "image_access_denied"


# -- an answered 401/403 beats TLS, throttle and 5xx phrases in the same text ------------------


@pytest.mark.parametrize(
    "tail", ["", f"; {THROTTLE}", f"; {SERVER_ERROR}", f"; {THROTTLE}; {SERVER_ERROR}"]
)
@pytest.mark.parametrize("head", [UNAUTHORIZED_401, DENIED_403, f"denied: {CERT_BODY}"])
def test_combined_tls_throttle_and_5xx_phrases_do_not_beat_an_answered_denial(
    head: str, tail: str
) -> None:
    assert code_of_text(f"{head}{tail}") == "image_access_denied"


@pytest.mark.parametrize(
    "text",
    [
        f"unauthorized: {THROTTLE}",
        f"unauthorized: {SERVER_ERROR}",
        f"error from registry: unauthorized: {CERT_BODY} ({SERVER_ERROR})",
        f"Head: unauthorized: authentication required\n{CERT_BODY}\n{THROTTLE}",
    ],
)
def test_a_registry_body_denial_beats_throttle_and_server_error_words(text: str) -> None:
    assert code_of_text(text) == "image_access_denied"


# -- what must not change ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "tail",
    [
        "denied: requested access to the resource is denied",
        "denied: requested access to the resource is denied.",
        "denied: denied",
        "denied",
        "",
    ],
)
def test_the_hub_privacy_mapping_to_not_found_is_kept(tail: str) -> None:
    text = f"{SENTENCE}: {tail}" if tail else SENTENCE
    classified = classify_pull_failure(DriverError(text), REF)
    assert type(classified) is DriverNotFound
    assert code_of_text(text) == "image_not_found"


async def test_the_hub_sentence_as_a_404_stays_not_found() -> None:
    text = f"{SENTENCE}: denied: requested access to the resource is denied"
    assert await code_of(pull_image, daemon_error(errors.NotFound, 404, text)) == "image_not_found"


@pytest.mark.parametrize(
    "text",
    [
        "x509: certificate signed by unknown authority",
        'Get "https://reg.corp/v2/": tls: failed to verify certificate: x509: certificate has '
        "expired or is not yet valid",
        'Get "https://reg.corp/v2/": http: server gave HTTP response to HTTPS client',
        'failed to do request: Head "https://reg.corp/v2/x/manifests/1": tls: first record '
        "does not look like a TLS handshake",
    ],
)
def test_a_genuine_tls_failure_is_still_a_tls_error(text: str) -> None:
    assert type(classify_pull_failure(DriverError(text), REF)) is DriverRegistryTlsError
    assert code_of_text(text) == "registry_tls_error"


@pytest.mark.parametrize(
    "text", [THROTTLE, SERVER_ERROR, "unexpected status from HEAD request to: 503 x"]
)
def test_plain_throttle_and_server_errors_are_still_unreachable(text: str) -> None:
    classified = classify_pull_failure(DriverError(text), REF)
    assert type(classified) is DriverRegistryUnreachable


def test_a_hard_transport_failure_before_the_denial_echo_still_wins() -> None:
    # Round 69: the transport failure must be in the daemon's own words BEFORE the registry's
    # "denied:" echo. Network words inside the answered body are the registry's data and keep
    # the denial (SF75-001; see test_pull_body_network_text_r69.py).
    text = "Get https://r.example/v2/: dial tcp 10.0.0.1:443: i/o timeout: denied: requested access"
    assert type(classify_pull_failure(DriverError(text), REF)) is DriverRegistryUnreachable


@pytest.mark.parametrize(
    "reference",
    ["acme/unauthorized:1", "acme/denied:1", "unauthorized/app:2", "reg.example/denied/app:1"],
)
def test_a_reference_named_like_the_body_marker_is_not_a_denial(reference: str) -> None:
    exc = DriverError(f"could not handle {reference}: the daemon is overloaded")
    classified = classify_pull_failure(exc, reference)
    assert type(classified) is DriverError
    exc = DriverError(f"{reference}: the daemon is overloaded")
    assert type(classify_pull_failure(exc, reference)) is DriverError


def test_access_denied_message_for_the_partner_bodies_carries_no_registry_text() -> None:
    for text in (UNAUTHORIZED_401, DENIED_403):
        classified = classify_pull_failure(DriverError(text), REF)
        assert type(classified) is DriverAccessDenied
        assert "x509" not in str(classified)
        assert "certificate" not in str(classified)
