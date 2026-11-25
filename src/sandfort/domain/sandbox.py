"""FROZEN: Sandbox entity, state enum and network policy.

``egress_allowlist`` follows docs/egress-allowlist-design.md (data model): ``None`` keeps
today's egress, a tuple names the only hosts the sandbox may reach. This slice stores and
validates the list; nothing enforces it yet (the proxy and driver wiring are later slices).
"""

import json
import re
from collections.abc import Callable, Mapping
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from sandfort.domain.egress_entries import cidr_problem, is_cidr_candidate
from sandfort.domain.node import DEFAULT_NODE_ID
from sandfort.domain.resources import ResourceSpec

DOMAIN_MARKER = "."  # a leading dot: the domain and all its subdomains
MAX_HOSTNAME_LENGTH = 253  # counted without the domain marker
# Transient carrier from the create schema to the service (the route copies request fields
# one by one). It uses the platform's reserved ``sandfort.`` label prefix and is never stored.
EGRESS_ALLOWLIST_LABEL = "sandfort.egress_allowlist"
# Set on the driver spec (never stored) when the sandbox has an allowlist (even empty), so the
# driver can pick the egress-restricted network without knowing the hostnames.
EGRESS_RESTRICTED_LABEL = "sandfort.egress_restricted"
# One label: 1 to 63 lowercase letters, digits or inner hyphens; IDNA labels are ``xn--`` LDH.
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
# WHATWG "ends in a number": such a host parses as IPv4 (``10.0.0.1``, ``127.1``, ``0x7f``).
_NUMERIC_LABEL = re.compile(r"[0-9]+|0x[0-9a-f]*")

# Machine-readable codes stored in ``Sandbox.error_code`` next to the free-text
# ``error_reason``. Each is chosen from the exception type or the drift kind, never from the
# message text, so a script can branch on it while the reason wording changes:
#
# * ``image_not_found``: the driver's not-found error for the image or snapshot at create.
#   Retry: no, not with the same reference.
# * ``registry_unreachable``: the network to the image registry failed (resolver, dial,
#   timeout, EOF), or the registry throttled the pull (HTTP 429) or failed on its side
#   (HTTP 5xx); the image may well exist. Retry: yes, after a pause.
# * ``registry_tls_error``: the registry's TLS connection failed validation (an untrusted or
#   wrong certificate, or a plain-HTTP registry answering an HTTPS request). Retry: no, a
#   repeat fails the same way until the registry trust or configuration changes.
# * ``image_access_denied``: the registry answered and refused the pull (denied, unauthorized:
#   a private or nonexistent repository). Retry: no, not until the reference or the access
#   changes.
# * ``invalid_image_reference``: the image reference cannot be parsed. Retry: no, fix the name.
# * ``start_failed``: any other driver error while creating or starting the sandbox.
#   Retry: maybe; read ``error_reason``.
# * ``timeout``: a driver operation exceeded its deadline. Retry: yes.
# * ``reset_failed``: the driver failed during a reset (after the old container was removed).
# * ``container_missing``: the reconciler found the started sandbox's container gone, or
#   present but never started.
# * ``container_exited``: the reconciler found the container exited; the sandbox is
#   ``stopped`` and can be started again (a successful start clears the code).
# * ``node_lost``: the node that owns the sandbox is gone (reserved: no path sets it yet).
# * ``egress_unavailable``: the node that ran the create job has no egress proxy settings, so an
#   allowlisted sandbox was not created (nothing runs on any network).
# * ``internal``: anything else.
ERROR_IMAGE_NOT_FOUND = "image_not_found"
ERROR_REGISTRY_UNREACHABLE = "registry_unreachable"
ERROR_REGISTRY_TLS_ERROR = "registry_tls_error"
ERROR_IMAGE_ACCESS_DENIED = "image_access_denied"
ERROR_INVALID_IMAGE_REFERENCE = "invalid_image_reference"
ERROR_START_FAILED = "start_failed"
ERROR_TIMEOUT = "timeout"
ERROR_RESET_FAILED = "reset_failed"
ERROR_CONTAINER_MISSING = "container_missing"
ERROR_CONTAINER_EXITED = "container_exited"
ERROR_NODE_LOST = "node_lost"
ERROR_EGRESS_UNAVAILABLE = "egress_unavailable"
ERROR_INTERNAL = "internal"
# The codes the SDK's ``ErrorCode`` Literal mirrors one for one (a parity test pins the two).
ERROR_CODES: tuple[str, ...] = (
    ERROR_IMAGE_NOT_FOUND,
    ERROR_REGISTRY_UNREACHABLE,
    ERROR_REGISTRY_TLS_ERROR,
    ERROR_IMAGE_ACCESS_DENIED,
    ERROR_INVALID_IMAGE_REFERENCE,
    ERROR_START_FAILED,
    ERROR_TIMEOUT,
    ERROR_RESET_FAILED,
    ERROR_CONTAINER_MISSING,
    ERROR_CONTAINER_EXITED,
    ERROR_NODE_LOST,
    ERROR_EGRESS_UNAVAILABLE,
    ERROR_INTERNAL,
)
# The image pull failures (round 35): a subset of ``ERROR_CODES``, kept for callers that
# import the tuple.
IMAGE_PULL_ERROR_CODES: tuple[str, ...] = (
    ERROR_REGISTRY_UNREACHABLE,
    ERROR_REGISTRY_TLS_ERROR,
    ERROR_IMAGE_ACCESS_DENIED,
    ERROR_INVALID_IMAGE_REFERENCE,
)

# Why a sandbox stopped, stored in ``Sandbox.stop_cause`` by the write that starts the stop:
#
# * ``requested``: a user (or API key) asked for the stop.
# * ``auto_stop``: the idle scanner stopped it after ``auto_stop_minutes`` without activity.
# * ``container_exited``: the reconciler found the container exited and settled the row as
#   ``stopped``.
# * ``oom_killed``: the container was killed for exceeding its memory limit, as the runtime
#   records it (``OomObservableDriver``; the Docker container tier only). The reconciler stores
#   it in place of ``container_exited`` when it settles such a container. gVisor and the
#   microVM tiers cannot see it and keep ``container_exited``.
# * ``unknown``: never stored. It is the API value for a ``stopping`` or ``stopped`` row whose
#   stored cause is null (a stop recorded before the column existed).
#
# A successful start clears the stored cause. A second stop request never overwrites it.
STOP_CAUSE_REQUESTED = "requested"
STOP_CAUSE_AUTO_STOP = "auto_stop"
STOP_CAUSE_CONTAINER_EXITED = "container_exited"
STOP_CAUSE_OOM_KILLED = "oom_killed"
STOP_CAUSE_UNKNOWN = "unknown"
STOP_CAUSES: tuple[str, ...] = (
    STOP_CAUSE_REQUESTED,
    STOP_CAUSE_AUTO_STOP,
    STOP_CAUSE_CONTAINER_EXITED,
    STOP_CAUSE_OOM_KILLED,
    STOP_CAUSE_UNKNOWN,
)


class SandboxState(StrEnum):
    PENDING = "pending"
    CREATING = "creating"
    STARTED = "started"
    STOPPING = "stopping"
    STOPPED = "stopped"
    STARTING = "starting"
    DESTROYING = "destroying"
    DESTROYED = "destroyed"
    ERROR = "error"


class NetworkPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    block_all: bool = False


class Sandbox(BaseModel):
    """Persistent sandbox record; ``version`` supports optimistic locking."""

    model_config = ConfigDict(frozen=True)

    id: str
    org_id: str
    name: str
    state: SandboxState = SandboxState.PENDING
    desired_state: SandboxState = SandboxState.STARTED
    image_ref: str
    driver: str
    driver_ref: str | None = None
    resources: ResourceSpec = Field(default_factory=ResourceSpec)
    env: dict[str, str] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    public: bool = False
    auto_stop_minutes: int = 15
    auto_delete_minutes: int = -1
    last_activity_at: datetime | None = None
    started_at: datetime | None = None
    stopped_at: datetime | None = None
    error_reason: str | None = None
    error_code: str | None = None  # one of ERROR_CODES; set with error_reason
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None = None
    version: int = 1
    standby: bool = False  # a pre-built warm-pool member that no user has claimed yet
    spec_hash: str | None = None  # warm-pool key of the spec this sandbox was built from
    node_id: str = DEFAULT_NODE_ID  # the node whose worker and docker daemon own this sandbox
    # replaced by PATCH while the generation is at least 1; None = today's egress
    egress_allowlist: tuple[str, ...] | None = None
    # 0: no allowlist or a legacy v1 token; see r0027
    egress_policy_generation: int = Field(default=0, ge=0)
    # raised by 1 per reset; a token carries it
    egress_credential_epoch: int = Field(default=0, ge=0)
    snapshot: str | None = None  # snapshot id or image reference it was created from
    stop_cause: str | None = None  # one of STOP_CAUSES (never unknown); set with the stop


def visible_stop_cause(sandbox: Sandbox) -> str | None:
    """The stop cause to show: stored, or ``unknown`` when null, while stopping or stopped.

    Every other state shows ``None``, whatever the row holds.
    """
    if sandbox.state not in (SandboxState.STOPPING, SandboxState.STOPPED):
        return None
    return sandbox.stop_cause or STOP_CAUSE_UNKNOWN


def visible_stopped_at(sandbox: Sandbox) -> datetime | None:
    """``stopped_at`` only while the sandbox is ``stopped``; ``None`` in every other state."""
    return sandbox.stopped_at if sandbox.state is SandboxState.STOPPED else None


def check_egress_allowlist(
    entries: tuple[str, ...] | None,
    network: NetworkPolicy,
    max_entries: int,
    error: Callable[[str], Exception] = ValueError,
    *,
    denied: tuple[str, ...] = (),
) -> None:
    """Raise ``error(message)`` unless ``entries`` is a valid allowlist; ``None`` always passes.

    Every entry is a lowercase ASCII hostname (internationalized names in their IDNA ``xn--``
    form), optionally prefixed with ``DOMAIN_MARKER``, or a canonical CIDR range (see
    ``sandfort.domain.egress_entries``; it must not overlap a ``denied`` network). Nothing is
    normalized: an entry not already in that form (uppercase, a trailing dot, surrounding
    space) is refused. An empty tuple is valid (nothing is reachable), so it may be combined
    with ``block_all``.
    """
    if entries is None:
        return
    if len(entries) > max_entries:
        raise error(f"egress_allowlist allows at most {max_entries} entries, got {len(entries)}")
    if entries and network.block_all:
        raise error("egress_allowlist contradicts network.block_all; send only one of them")
    for entry in entries:
        if is_cidr_candidate(entry):
            problem = cidr_problem(entry, denied)
        else:
            problem = _hostname_problem(entry)
        if problem is not None:
            raise error(f"egress_allowlist entry {entry!r} {problem}")


def _hostname_problem(entry: str) -> str | None:
    """Why ``entry`` is not an allowlist hostname, or ``None`` when it is one."""
    if "://" in entry:
        return "must not include a scheme"
    if any(mark in entry for mark in "/?#"):
        return "must not include a path"
    if entry.startswith("[") or entry.count(":") > 1:
        return "must not be an IP literal"
    if ":" in entry:
        return "must not include a port"
    if "*" in entry:
        return "must not use wildcards (a leading dot covers subdomains)"
    if entry != entry.lower():
        return "must be lowercase"
    if not entry.isascii():
        return "must be ASCII (write internationalized names in their IDNA xn-- form)"
    name = entry.removeprefix(DOMAIN_MARKER)
    if len(name) > MAX_HOSTNAME_LENGTH:
        return f"is longer than {MAX_HOSTNAME_LENGTH} characters"
    labels = name.split(".")
    if not all(_LABEL.fullmatch(label) for label in labels):
        return "needs labels of 1 to 63 lowercase letters, digits or inner hyphens"
    if _NUMERIC_LABEL.fullmatch(labels[-1]):
        return "must not be an IP literal"
    return None


def egress_spec_labels(sandbox: Sandbox) -> dict[str, str]:
    """The spec label marking any allowlist, empty included; empty when egress is unrestricted.

    An empty allowlist reaches nothing, so it is restricted too: fail closed, never the open
    bridge. The service also stores ``block_all`` for it, which wins in the driver.
    """
    if sandbox.egress_allowlist is None:
        return {}
    return {EGRESS_RESTRICTED_LABEL: "true"}


def egress_restricted(labels: Mapping[str, str]) -> bool:
    """True when a driver spec's labels mark the sandbox as egress-restricted."""
    return labels.get(EGRESS_RESTRICTED_LABEL) == "true"


def encode_egress_allowlist(entries: list[str] | tuple[str, ...] | None) -> dict[str, str]:
    """The transient label carrying ``entries``; empty when no allowlist was given."""
    if entries is None:
        return {}
    return {EGRESS_ALLOWLIST_LABEL: json.dumps(list(entries), separators=(",", ":"))}


def take_egress_allowlist(
    labels: Mapping[str, str],
) -> tuple[dict[str, str], tuple[str, ...] | None]:
    """Split the transient allowlist off ``labels``; a malformed carrier is a ``ValueError``."""
    raw = labels.get(EGRESS_ALLOWLIST_LABEL)
    if raw is None:
        return dict(labels), None
    remaining = {name: value for name, value in labels.items() if name != EGRESS_ALLOWLIST_LABEL}
    items = json.loads(raw)  # a decode failure is a ValueError too
    if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
        raise ValueError("malformed egress allowlist carrier")
    return remaining, tuple(str(item) for item in items)
