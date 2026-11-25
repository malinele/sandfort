"""The sandbox ``error_code`` values the server sends, as a type alias and module constants.

``SandboxInfo.error_code``, ``Sandbox.error_code`` and ``SandboxFailedError.error_code`` stay
``str | None`` so that a code a newer server adds does not break an older SDK. Branch on the
constants, and use :func:`is_known_error_code` to narrow the attribute to :data:`ErrorCode` for
a type checker (for example before an exhaustive ``match`` that ends in ``assert_never``).

The server picks a code from the exception type or the drift kind, never from the message
text, so a script can branch on it while the free-text ``error_reason`` wording changes.

Retryability: ``registry_unreachable`` is retryable (the registry did not answer, throttled the
pull with HTTP 429 or failed with HTTP 5xx; try again after a pause). ``registry_tls_error`` is
not: the registry's TLS connection failed validation (an untrusted or wrong certificate, or a
plain-HTTP registry), and a repeat fails the same way until the registry trust or configuration
changes. ``image_access_denied`` and ``invalid_image_reference`` are not either: they stay the
same until the reference or the registry access changes.
"""

from typing import Final, Literal, TypeGuard, get_args

ErrorCode = Literal[
    "image_not_found",
    "registry_unreachable",
    "registry_tls_error",
    "image_access_denied",
    "invalid_image_reference",
    "start_failed",
    "timeout",
    "reset_failed",
    "container_missing",
    "container_exited",
    "node_lost",
    "egress_unavailable",
    "internal",
]

ERROR_CODE_IMAGE_NOT_FOUND: Final = "image_not_found"  # the image or snapshot is not found
ERROR_CODE_REGISTRY_UNREACHABLE: Final = "registry_unreachable"  # retryable: no registry answer
# Not retryable: the registry's TLS connection failed validation; fix the registry trust.
ERROR_CODE_REGISTRY_TLS_ERROR: Final = "registry_tls_error"
ERROR_CODE_IMAGE_ACCESS_DENIED: Final = "image_access_denied"  # not retryable: pull refused
# Not retryable: the image reference cannot be parsed.
ERROR_CODE_INVALID_IMAGE_REFERENCE: Final = "invalid_image_reference"
ERROR_CODE_START_FAILED: Final = "start_failed"  # another driver error at create or start
ERROR_CODE_TIMEOUT: Final = "timeout"  # a driver operation exceeded its deadline
ERROR_CODE_RESET_FAILED: Final = "reset_failed"  # the driver failed during a reset
# The reconciler found the started sandbox's container gone, or present but never started.
ERROR_CODE_CONTAINER_MISSING: Final = "container_missing"
# The reconciler found the container exited; the sandbox is ``stopped`` and can be started
# again (a successful start clears the code).
ERROR_CODE_CONTAINER_EXITED: Final = "container_exited"
ERROR_CODE_NODE_LOST: Final = "node_lost"  # the owning node is gone (reserved by the server)
# Not retryable on that node: the node that ran the create job has no egress proxy settings, so
# the allowlisted sandbox was not created and nothing runs on any network.
ERROR_CODE_EGRESS_UNAVAILABLE: Final = "egress_unavailable"
ERROR_CODE_INTERNAL: Final = "internal"  # anything else

KNOWN_ERROR_CODES: Final[frozenset[str]] = frozenset(get_args(ErrorCode))


def is_known_error_code(value: str | None) -> TypeGuard[ErrorCode]:
    """True when ``value`` is an error code this SDK version knows (``None`` is not one)."""
    return value in KNOWN_ERROR_CODES
