"""Round 67: registry throttling, registry 5xx and TLS validation get their own pull classes.

HTTP 429 and 5xx are ``registry_unreachable`` (retryable after a pause). A TLS validation failure
(untrusted or wrong certificate, a plain-HTTP registry) is ``registry_tls_error``: not retryable,
because only a change of the registry trust or configuration fixes it. An EOF or a handshake
timeout stays ``registry_unreachable``: those are network conditions, not validation failures.
"""

import logging
from typing import Any

import pytest

from sandfort.domain.sandbox import ERROR_CODES, ERROR_INTERNAL, IMAGE_PULL_ERROR_CODES
from sandfort.drivers.docker.images import (
    classify_known_pull_failure,
    classify_pull_failure,
    pull_image,
    pull_image_digest,
)
from sandfort.drivers.errors import (
    DriverAccessDenied,
    DriverError,
    DriverNotFound,
    DriverRegistryTlsError,
    DriverRegistryUnreachable,
)
from sandfort.services.sandbox_jobs import driver_error_code
from test_docker_driver_unit import (
    REGISTRY_UNREACHABLE,
    daemon_error,
    failing_pull_client,
)

errors = pytest.importorskip("docker.errors")

PULL_HELPERS = [pull_image, pull_image_digest]
REF = "registry.example/team/app:1"
TLS_MESSAGE = (
    "could not pull {ref}: the TLS connection to the registry failed validation (an untrusted "
    "or wrong certificate, or a plain-HTTP registry); fix the registry trust or configuration"
)
THROTTLE_TEXTS = [
    "toomanyrequests: You have reached your pull rate limit. You may increase the limit by "
    "authenticating and upgrading: https://www.docker.com/increase-rate-limit",
    "Error response from daemon: toomanyrequests: Too Many Requests.",
    "unexpected status from HEAD request to https://registry-1.docker.io/v2/library/x/"
    "manifests/1: 429 Too Many Requests",
    "unexpected status from GET request to https://ghcr.io/token?scope=repository: "
    "429 Too Many Requests",
]
SERVER_ERROR_TEXTS = [
    "received unexpected HTTP status: 503 Service Unavailable",
    "Error response from daemon: received unexpected HTTP status: 502 Bad Gateway",
    "unexpected status from HEAD request to https://reg.example/v2/team/app/manifests/1: "
    "503 Service Unavailable",
    "unexpected status from GET request to https://reg.example/v2/team/app/blobs/sha256:ab: "
    "500 Internal Server Error",
    'failed to resolve reference "reg.example/team/app:1": failed to authorize: failed to fetch '
    "anonymous token: unexpected status from GET request to https://auth.example/token: "
    "503 Service Unavailable",
    # the form the daemon text has after ``clean_message`` stripped every url
    "unexpected status from HEAD request to: 503 Service Unavailable",
    "unexpected status from GET request to: 429 Too Many Requests",
]
TRANSIENT_TEXTS = [
    "unexpected EOF",
    'Get "https://reg.corp/v2/team/app/manifests/1": EOF',
    "net/http: TLS handshake timeout",
]
TLS_VALIDATION_TEXTS = [
    'Get "https://reg.corp/v2/": tls: failed to verify certificate: x509: certificate signed '
    "by unknown authority",
    "x509: certificate signed by unknown authority",
    "x509: certificate has expired or is not yet valid: current time 2026-11-13T00:00:00Z",
    "x509: certificate is valid for a.corp, b.corp, not reg.corp",
    'Get "https://reg.corp/v2/": http: server gave HTTP response to HTTPS client',
    "http: server gave HTTP response to HTTPS client",
]


# -- the new class and code ------------------------------------------------------------------


def test_tls_error_is_a_direct_driver_error_not_an_unreachable_subclass() -> None:
    assert DriverRegistryTlsError.__bases__ == (DriverError,)
    assert not issubclass(DriverRegistryTlsError, DriverRegistryUnreachable)
    assert not issubclass(DriverRegistryUnreachable, DriverRegistryTlsError)
    exc = DriverRegistryTlsError("bad certificate", ref=REF)
    assert exc.ref == REF
    assert exc.message == "bad certificate"


def test_the_tls_code_is_listed_and_a_pull_code() -> None:
    assert "registry_tls_error" in ERROR_CODES
    assert "registry_tls_error" in IMAGE_PULL_ERROR_CODES


def test_jobs_map_the_tls_error_to_its_code() -> None:
    exc = DriverRegistryTlsError("x", ref=REF)
    assert driver_error_code(exc, fallback=ERROR_INTERNAL) == "registry_tls_error"
    unreachable = DriverRegistryUnreachable("x", ref=REF)
    assert driver_error_code(unreachable, fallback=ERROR_INTERNAL) == "registry_unreachable"


# -- 429 and 5xx -----------------------------------------------------------------------------


@pytest.mark.parametrize("helper", PULL_HELPERS)
@pytest.mark.parametrize("text", [*THROTTLE_TEXTS, *SERVER_ERROR_TEXTS, *TRANSIENT_TEXTS])
async def test_throttle_server_error_and_transient_texts_are_registry_unreachable(
    helper: Any, text: str
) -> None:
    client = failing_pull_client(daemon_error(errors.APIError, 500, text))
    with pytest.raises(DriverRegistryUnreachable) as caught:
        await helper(client, REF)
    assert type(caught.value) is DriverRegistryUnreachable
    assert str(caught.value) == REGISTRY_UNREACHABLE.format(ref=REF)
    assert caught.value.ref == REF


def test_a_registry_404_status_is_not_a_server_error() -> None:
    text = "unexpected status from HEAD request to https://r.example/v2/: 404 Not Found"
    assert type(classify_pull_failure(DriverError(text), REF)) is DriverError


@pytest.mark.parametrize(
    "text",
    [
        "received unexpected HTTP status: 401 Unauthorized",
        "unexpected status from HEAD request to https://r.example/v2/x/manifests/1: "
        "403 Forbidden",
    ],
)
def test_a_registry_401_or_403_status_is_still_access_denied(text: str) -> None:
    assert type(classify_pull_failure(DriverError(text), REF)) is DriverAccessDenied


# -- TLS validation --------------------------------------------------------------------------


@pytest.mark.parametrize("helper", PULL_HELPERS)
@pytest.mark.parametrize("text", TLS_VALIDATION_TEXTS)
async def test_tls_validation_texts_are_registry_tls_error(helper: Any, text: str) -> None:
    client = failing_pull_client(daemon_error(errors.APIError, 500, text))
    with pytest.raises(DriverRegistryTlsError) as caught:
        await helper(client, REF)
    assert type(caught.value) is DriverRegistryTlsError
    assert str(caught.value) == TLS_MESSAGE.format(ref=REF)
    assert caught.value.ref == REF
    assert "corp" not in str(caught.value)
    assert "x509" not in str(caught.value)


def test_tls_validation_text_goes_to_the_debug_log_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="sandfort.drivers.docker.images")
    text = "x509: certificate is valid for a.corp, not reg.corp"
    classified = classify_pull_failure(DriverError(text), REF)
    assert type(classified) is DriverRegistryTlsError
    assert "a.corp" not in str(classified)
    assert "a.corp" in caplog.text


def test_a_tls_error_is_not_caught_by_an_unreachable_retry_loop() -> None:
    classified = classify_pull_failure(DriverError("x509: certificate has expired"), REF)
    with pytest.raises(DriverRegistryTlsError):
        try:
            raise classified
        except DriverRegistryUnreachable:  # pragma: no cover - must not be reached
            pytest.fail("a TLS validation error must not be retried as unreachable")


# -- precedence ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "unexpected status from GET request to https://reg.corp/token: 401 Unauthorized "
        "(x509: certificate signed by unknown authority)",
        "unexpected status from HEAD request to https://reg.corp/v2/x/manifests/1: "
        "403 Forbidden: tls: failed to verify certificate",
        "error from registry: denied\nx509: certificate signed by unknown authority",
    ],
)
def test_an_answered_denial_that_mentions_a_certificate_is_access_denied(text: str) -> None:
    assert type(classify_pull_failure(DriverError(text), REF)) is DriverAccessDenied


def test_the_not_found_family_wins_over_a_certificate_word() -> None:
    text = "pull access denied for team/app, repository does not exist: x509: certificate"
    assert type(classify_pull_failure(DriverError(text), REF)) is DriverNotFound


def test_a_not_found_answer_wins_over_a_server_error_phrase() -> None:
    exc = DriverNotFound("received unexpected HTTP status: 503 Service Unavailable", ref=REF)
    assert type(classify_known_pull_failure(exc, REF)) is DriverNotFound


def test_tls_validation_wins_over_a_transport_marker() -> None:
    text = "Get https://reg.corp/v2/: x509: certificate signed by unknown authority: i/o timeout"
    assert type(classify_pull_failure(DriverError(text), REF)) is DriverRegistryTlsError


def test_a_server_error_on_a_token_fetch_wins_over_failed_to_authorize() -> None:
    text = (
        "failed to authorize: failed to fetch anonymous token: unexpected status from GET "
        "request to https://auth.example/token: 503 Service Unavailable"
    )
    assert type(classify_pull_failure(DriverError(text), REF)) is DriverRegistryUnreachable


# -- the reference is not evidence -----------------------------------------------------------


@pytest.mark.parametrize(
    "reference",
    [
        "acme/app:toomanyrequests",
        "acme/toomanyrequests:1",
        "acme/toomanyrequests",
        "toomanyrequests/app:1.0",
        "acme/app:503",
        "acme/certificate:1",
        "acme/x509:1",
        "reg.example/received-unexpected-http-status:5",
    ],
)
def test_a_marker_like_word_in_the_reference_is_not_a_failure_class(reference: str) -> None:
    exc = DriverError(f"the daemon could not handle {reference}: the daemon is overloaded")
    classified = classify_pull_failure(exc, reference)
    assert type(classified) is DriverError
    assert str(classified) == f"could not pull {reference}"


@pytest.mark.parametrize("reference", ["toomanyrequests", "library/toomanyrequests:latest"])
def test_a_reference_named_toomanyrequests_in_a_qualified_echo_is_not_a_throttle(
    reference: str,
) -> None:
    # The daemon qualifies the reference with a host, so ``_without_reference`` cannot blank it.
    exc = DriverError(f"could not handle docker.io/library/{reference}: overloaded")
    assert type(classify_pull_failure(exc, reference)) is DriverError


def test_a_reference_named_toomanyrequests_still_sees_a_real_throttle() -> None:
    reference = "acme/app:toomanyrequests"
    text = f"toomanyrequests: You have reached your pull rate limit for {reference}"
    assert type(classify_pull_failure(DriverError(text), reference)) is DriverRegistryUnreachable


# -- review fixes: tenant-controlled text is not a TLS marker ---------------------------------

# (reference, daemon text, expected class): each reference or tag echo holds a TLS-like word in a
# place ``_without_reference`` never blanks (a bare name, a host label, a URL path segment).
TLS_WORD_ECHOES = [
    (
        "certificate.example.com/app:1",
        "dial tcp: lookup certificate.example.com on 127.0.0.53:53: no such host",
    ),
    (
        "certificate-store.corp/app:1",
        'Get "https://certificate-store.corp/v2/": dial tcp 10.0.0.1:443: i/o timeout',
    ),
    (
        "certificate",
        'Get "https://registry-1.docker.io/v2/library/certificate/manifests/latest": '
        "context deadline exceeded",
    ),
    (
        "acme/app:certificate",
        'Head "https://reg.example/v2/acme/app/manifests/certificate": dial tcp 1.2.3.4:443: '
        "i/o timeout",
    ),
    (
        "reg.example/acme/app:x509",
        "unexpected status from HEAD request to "
        "https://reg.example/v2/acme/app/manifests/x509: 503 Service Unavailable",
    ),
]


@pytest.mark.parametrize(("reference", "text"), TLS_WORD_ECHOES)
def test_a_tls_like_word_in_the_reference_echo_is_not_a_tls_error(
    reference: str, text: str
) -> None:
    classified = classify_pull_failure(DriverError(text), reference)
    assert type(classified) is DriverRegistryUnreachable


@pytest.mark.parametrize("helper", PULL_HELPERS)
@pytest.mark.parametrize(("reference", "text"), TLS_WORD_ECHOES)
async def test_the_pull_path_agrees_on_a_tls_like_word_in_the_reference(
    helper: Any, reference: str, text: str
) -> None:
    client = failing_pull_client(daemon_error(errors.APIError, 500, text))
    with pytest.raises(DriverRegistryUnreachable):
        await helper(client, reference)


def test_a_bare_certificate_repository_echo_with_a_tag_is_not_a_tls_error() -> None:
    text = "the daemon could not handle certificate:latest: overloaded"
    assert type(classify_pull_failure(DriverError(text), "certificate")) is DriverError


@pytest.mark.parametrize(
    "text",
    [
        "x509: certificate relies on legacy Common Name field, use SANs instead",
        "x509: cannot validate certificate for 10.0.0.5 because it doesn't contain any IP SANs",
        "x509: failed to load system roots and no roots provided",
        "x509: unsupported signature algorithm",
        "remote error: tls: bad certificate",
        "tls: first record does not look like a TLS handshake",
        'Get "https://reg.corp/v2/": tls: first record does not look like a TLS handshake',
    ],
)
def test_more_real_tls_and_plain_http_symptoms_are_tls_errors(text: str) -> None:
    assert type(classify_pull_failure(DriverError(text), REF)) is DriverRegistryTlsError


# -- review fixes: the containerd status pattern is anchored to the request URL ---------------


def test_a_later_5xx_on_the_same_line_as_a_404_status_is_not_a_server_error() -> None:
    text = (
        "unexpected status from HEAD request to https://r.example/v2/acme/app/manifests/1: "
        "404 Not Found: retry 500 times"
    )
    assert type(classify_pull_failure(DriverError(text), "acme/app:1")) is DriverError


@pytest.mark.parametrize(
    "text",
    [
        "unexpected status from POST request to https://auth.example/token: 500 Internal",
        "unexpected status from POST request to: 500 Internal Server Error",
    ],
)
def test_a_containerd_5xx_status_after_the_request_url_is_a_server_error(text: str) -> None:
    classified = classify_pull_failure(DriverError(text), "acme/app:1")
    assert type(classified) is DriverRegistryUnreachable


# -- review fixes: an architecture mismatch is the not-found family ---------------------------

# Captured on 2026-11-13 from Docker Engine server 29.8.2 (``docker version --format
# '{{.Server.Version}}'``) with ``docker pull --platform linux/mips64le alpine:3.20``.
NO_MATCHING_MANIFEST = (
    "Error response from daemon: no matching manifest for linux/mips64le in the manifest list "
    "entries: no match for platform in manifest: not found"
)


@pytest.mark.parametrize("status", [404, 500])
@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_no_matching_manifest_is_image_not_found_whatever_the_status(
    helper: Any, status: int
) -> None:
    client = failing_pull_client(daemon_error(errors.APIError, status, NO_MATCHING_MANIFEST))
    with pytest.raises(DriverNotFound) as caught:
        await helper(client, "alpine:3.20")
    assert str(caught.value) == "no such image or snapshot: alpine:3.20"


def test_no_matching_manifest_text_alone_is_not_found() -> None:
    classified = classify_pull_failure(DriverError(NO_MATCHING_MANIFEST), "alpine:3.20")
    assert type(classified) is DriverNotFound
    assert driver_error_code(classified, fallback=ERROR_INTERNAL, image="alpine:3.20") == (
        "image_not_found"
    )
