"""Docker ``ImageRegistryDriver`` operations plus the export/import flatten (WP 3.2).

``pull_image_digest`` pins a registry image to its repo digest. ``commit_container`` uses
docker's own ``pause`` flag, so the container is frozen for the duration of the commit, and
reports the new image id with its layer count. The commit stores no env value the sandbox set
(``commit_env.py``): its ``Env`` is the base image's, plus ``KEY=`` with an empty value for every
key the sandbox added, because docker's commit merge can blank a key but never remove it; the
export route sanitizes on top of that. ``flatten_container`` exports the container
filesystem and imports it as a single-layer image; the snapshot service uses it when a commit
stacks more layers than its cap; ``export_image`` (``image_export.py``) reuses that export/import
to stream a sanitized ``docker save``. Pull, commit, the export/import flatten and image removal
depend on a registry or on the size of the image, so they run through ``run_bulk`` (bulk
lane); every other docker-py call (inspect, pause, unpause) runs through ``run_blocking``
(control lane). Failures surface as ``drivers.errors`` types.

Pull failures are classified from the daemon text by ``classify_known_pull_failure``; its
docstring has the full precedence. In short: the not-found family (Docker Hub's stock "pull
access denied ... docker login ... denied: requested access to the resource is denied" included)
first; then a registry that ANSWERED 401/403 (a status pair, or the registry's own
"unauthorized: <message>" / "denied: <message>", whatever the message says about certificates,
throttling or 5xx) is ``DriverAccessDenied``, unless the text shows a hard transport failure;
then TLS validation, then transport/throttle/5xx, then the weak refusal phrases.
"""

import logging
import re
from collections.abc import Mapping, Sequence
from typing import Any

from sandfort.drivers.base import CommitResult, ImageInfo
from sandfort.drivers.docker.client import (
    DISK_FULL_MESSAGE,
    PULL_DENIAL_PHRASE,
    run_blocking,
    translate_errors,
)
from sandfort.drivers.docker.commit_env import base_image_id, commit_env, config_env
from sandfort.drivers.docker.lanes import run_bulk
from sandfort.drivers.errors import (
    DriverAccessDenied,
    DriverError,
    DriverInvalidReference,
    DriverNotFound,
    DriverRegistryTlsError,
    DriverRegistryUnreachable,
)

logger = logging.getLogger(__name__)

DIGEST_SEPARATOR = "@"
FLAT_LAYER_COUNT = 1
# ``docker import`` drops the image config; these survive as Dockerfile changes when plain.
CARRIED_ENV = frozenset({"PATH"})
_PLAIN_VALUE = re.compile(r"[A-Za-z0-9_./:@%+,=-]+")
# Lower-case fragments of the daemon text for a reference it cannot pull (access-denied family).
# ``PULL_DENIAL_PHRASE`` is what ``clean_message`` puts in place of the daemon's denial sentence.
# "no matching manifest" is the daemon's answer when the manifest list has no entry for the host's
# platform (a CPU architecture mismatch), whatever HTTP status carried it; it holds spaces, which
# a reference cannot.
_PULL_DENIED_MARKERS = ("pull access denied", "repository does not exist", "docker login",
                        "manifest unknown", "no matching manifest",
                        PULL_DENIAL_PHRASE)  # fmt: skip
# Lower-case fragments of a transport failure (dial, resolver, timeout). They win over the
# anchored access-denied phrases (a registry that never answered cannot have refused the pull),
# not over a refusal only an answering registry gives (``_REGISTRY_ANSWERED_DENIAL``).
_TRANSPORT_FAILURE_MARKERS = (
    "dial tcp", "lookup ", "i/o timeout", "no such host", "connection refused",
    "context deadline exceeded", "client.timeout exceeded while awaiting headers",
)  # fmt: skip
# Lower-case fragments of a registry NETWORK failure (resolver, dial, timeout); the image may exist.
# The weaker ones ("failed to resolve reference" also prefixes a 401) are checked after denials.
_REGISTRY_NETWORK_MARKERS = (
    *_TRANSPORT_FAILURE_MARKERS,
    "failed to resolve reference",
    "server misbehaving",
    "tls handshake timeout",
    "temporary failure in name resolution",
)
# Lower-case anchored phrases of a registry that answered and refused the pull. Bare words such
# as "forbidden" are not markers: daemon text echoes the image reference, which can contain them.
# Checked after the not-found family, whose daemon sentence also says "denied", and after the
# transport markers: "failed to authorize" also prefixes a token fetch that could not dial.
_ACCESS_DENIED_MARKERS = (
    ": denied:", "denied: requested access", "unauthorized: ", "status: 401", "status: 403",
    "pull access denied", "failed to authorize",
)  # fmt: skip
# Phrases only a registry that ANSWERED produces: a 401/403 status word pair (containerd's token
# fetch), a bare ": denied" ending the text or a line (GHCR, "error from registry: denied"),
# "denied" opening the text or a line (docker-py's explanation, "denied: User: ..." from ECR; not
# "denied by ...") and ECR's "no basic auth credentials". Decided before the transport markers.
_REGISTRY_ANSWERED_DENIAL = re.compile(
    r"\b(?:401\s+unauthorized|403\s+forbidden)\b|:\s*denied\.?\s*$"
    r"|^\s*denied\b(?!\s+by\b)|no basic auth credentials",
    re.IGNORECASE | re.MULTILINE,
)
# A refusal in the registry's own words: the daemon echoes the registry's answer after its error
# code ("unauthorized: <message>" for a 401, "denied: <message>" for a 403), either as the whole
# text, opening a line, or after a colon ("...: unauthorized: x509: ..."). Anchored the same way
# as the phrases above, so a word inside a reference ("library/unauthorized: ...", a repository
# named ``denied``) is not one, nor is "access denied: ..." or "denied by ...". The message after
# the code is the REGISTRY'S text and can say anything (a certificate, a throttle, a 503), so this
# decides before TLS, throttle and server-error phrases; only a transport failure (the registry
# did not answer at all) still wins over it.
_REGISTRY_BODY_DENIAL = re.compile(
    r"(?:^\s*|:\s+)(?:unauthorized|denied):\s+\S", re.IGNORECASE | re.MULTILINE
)
# The tail of the daemon's not-found sentence ("pull access denied for X, repository does not exist
# or may require 'docker login': denied: <message>"; ``clean_message`` swaps the sentence for
# ``PULL_DENIAL_PHRASE``). Moby builds it for a registry ``DENIED`` answer as well as for a missing
# repository, and Docker Hub gives both the stock message "requested access to the resource is
# denied" (GHCR: a bare "denied"). Those stay not-found, which is what keeps a private repository
# indistinguishable from a missing one. Any OTHER message is the registry saying something
# specific about this pull, so it is a refusal, not a not-found.
_SPECIFIC_DENIAL_AFTER_SENTENCE = re.compile(
    rf"(?:docker login['\"]?|{re.escape(PULL_DENIAL_PHRASE)})\s*:\s*denied:\s+"
    r"(?!(?:requested access to the resource is denied|denied)\W*$)\S",
    re.IGNORECASE,
)
# A TLS validation failure: the registry's certificate is not trusted or does not match, or the
# registry speaks plain HTTP. Retrying cannot help; the registry trust or configuration must
# change, so it is its own class (``DriverRegistryTlsError``), decided before the transport markers.
# Anchored, because the daemon echoes tenant-chosen text (a registry host, a repository, a tag)
# that ``_without_reference`` does not always blank: "certificate" counts only as a whole word
# that does not follow a path, host or tag separator and is not a host label (``certificate.corp``),
# a hyphenated name or a tag (``certificate:latest``); "x509:" only as Go's own "x509: <sentence>"
# (a space and a known opening, never after a separator, so ``manifests/x509: 503`` is not one).
# The two plain-HTTP symptoms are phrases with spaces, which a reference cannot hold.
_TLS_VALIDATION_FAILURE = re.compile(
    r"(?<![\w./:-])x509:\s+(?:certificate|cannot validate|failed to|unsupported|"
    r"negative serial|invalid|too many|internal error|signature)"
    r"|(?<![\w./-])certificate(?![\w/-]|\.\w|:\w)"
    r"|http response to https client|first record does not look like a tls handshake",
    re.IGNORECASE,
)
# An EOF mid-read is a network condition, not a validation failure: no answer was given.
_EOF_FAILURE = re.compile(r"\beof\b", re.IGNORECASE)
# A registry that throttled the pull (HTTP 429) or failed on its side (HTTP 5xx); the image may
# well exist and a later attempt can succeed. Every alternative is anchored: bare words are not
# markers, because the daemon echoes the tenant-chosen image reference. "toomanyrequests" counts
# only as the docker error code ("toomanyrequests: You have ..."), never after a path or tag
# separator, so a repository or tag of that name that the daemon qualifies with a host (not
# blanked by ``_without_reference``) is not a throttle. "too many requests" holds spaces, which a
# reference cannot. The 5xx forms are docker's "received unexpected HTTP status: 503 ..." and
# containerd's "unexpected status from <METHOD> request to <url>: 503 ..." (the same sentence
# prefixes a failed token fetch). The status must follow the request URL directly ("request to
# <url>: 503"; ``clean_message`` strips the url, which leaves "request to: 503"), so a later
# number on the line is not one, and the space after the colon keeps a ``name:503`` tag echo out.
_THROTTLE_OR_SERVER_ERROR = re.compile(
    r"(?<![\w./-])toomanyrequests:\s|\btoo many requests\b"
    r"|\breceived unexpected http status: 5\d\d\b"
    r"|\bunexpected status from \w+ request to(?: \S+)?:\s+(?:429|5\d\d)\b",
    re.IGNORECASE,
)
# A trailing "...: unauthorized" (the daemon url before it is already removed from the text).
_UNAUTHORIZED_SUFFIX = ": unauthorized"
# A reference fragment is removed from the text only when it holds one of these characters.
_REFERENCE_PUNCTUATION = frozenset("/:@")
# Lower-case daemon sentence for a reference it cannot parse (the one a tenant sees for it).
_INVALID_REFERENCE_MARKER = "invalid reference format"


def split_reference(reference: str) -> tuple[str, str | None]:
    """``(repository, tag)``; a digest reference is returned whole with no tag."""
    if DIGEST_SEPARATOR in reference:
        return reference, None
    slash, colon = reference.rfind("/"), reference.rfind(":")
    if colon > slash:
        return reference[:colon], reference[colon + 1 :]
    return reference, None


def repository_name(reference: str) -> str:
    return split_reference(reference)[0].split(DIGEST_SEPARATOR, 1)[0]


def layer_count(attrs: Mapping[str, Any]) -> int:
    rootfs = attrs.get("RootFS") or {}
    return len(rootfs.get("Layers") or [])


def repo_digest(attrs: Mapping[str, Any], reference: str) -> str:
    """The registry digest of ``reference`` from an image inspect payload."""
    entries = [str(item) for item in attrs.get("RepoDigests") or []]
    if not entries:
        raise DriverError(f"image {reference} has no registry digest", ref=reference)
    wanted = repository_name(reference)
    for entry in entries:
        name, _, digest = entry.partition(DIGEST_SEPARATOR)
        if name == wanted:
            return digest
    return entries[0].partition(DIGEST_SEPARATOR)[2]


def config_changes(config: Mapping[str, Any]) -> list[str]:
    """Dockerfile instructions restoring the plain PATH and WORKDIR that an import drops."""
    changes: list[str] = []
    for entry in config.get("Env") or []:
        name, separator, value = str(entry).partition("=")
        if separator and name in CARRIED_ENV and _PLAIN_VALUE.fullmatch(value):
            changes.append(f"ENV {name}={value}")
    workdir = str(config.get("WorkingDir") or "")
    if workdir and _PLAIN_VALUE.fullmatch(workdir):
        changes.append(f"WORKDIR {workdir}")
    return changes


def _tag_target(image_reference: str) -> tuple[str, str | None]:
    if DIGEST_SEPARATOR in image_reference:
        raise DriverError(
            f"cannot write an image to a digest reference: {image_reference}", ref=image_reference
        )
    return split_reference(image_reference)


def _commit_result(attrs: Mapping[str, Any]) -> CommitResult:
    return CommitResult(digest=str(attrs["Id"]), layer_count=layer_count(attrs))


def image_info(ref: str, attrs: Mapping[str, Any]) -> ImageInfo:
    return ImageInfo(
        ref=ref,
        digest=str(attrs["Id"]),
        size_bytes=int(attrs.get("Size") or 0),
        layer_count=layer_count(attrs),
    )


def _is_pull_denied(message: str) -> bool:
    """Whether a cleaned daemon pull message says the reference is unknown or not accessible."""
    lowered = message.lower()
    return any(marker in lowered for marker in _PULL_DENIED_MARKERS)


def _is_registry_network_failure(message: str) -> bool:
    """Whether a cleaned daemon pull message describes a failure to reach the registry."""
    lowered = message.lower()
    return any(marker in lowered for marker in _REGISTRY_NETWORK_MARKERS)


def _is_tls_validation_failure(message: str) -> bool:
    """Whether a daemon pull message says the registry's TLS connection failed validation."""
    return _TLS_VALIDATION_FAILURE.search(message) is not None


def _is_hard_transport_failure(message: str) -> bool:
    """Whether a daemon pull message shows the registry never answered: a dial, resolver or
    timeout failure, or an EOF."""
    lowered = message.lower()
    if _EOF_FAILURE.search(lowered):
        return True
    return any(marker in lowered for marker in _TRANSPORT_FAILURE_MARKERS)


def _is_transport_failure(message: str) -> bool:
    """Whether a daemon pull message shows the registry never gave a usable answer: a hard
    transport failure, or a throttle or server error (429, 5xx)."""
    return (
        _is_hard_transport_failure(message)
        or _THROTTLE_OR_SERVER_ERROR.search(message.lower()) is not None
    )


def _is_registry_body_denial(message: str) -> bool:
    """Whether a daemon pull message echoes a registry's "unauthorized: ..." or "denied: ...",
    with no transport failure in the daemon's own words BEFORE that echo.

    Everything after the marker is the REGISTRY'S body: network words there ("dial tcp",
    "no such host", an EOF) are data an answering registry chose to send, never evidence that
    it was unreachable (SF75-001). Only the prefix — the daemon's own words — can show that
    the registry was not reached, as in a token fetch that could not dial.
    """
    match = _REGISTRY_BODY_DENIAL.search(message)
    if match is None:
        return False
    return not _is_hard_transport_failure(message[: match.start()])


def _is_specific_denial_after_sentence(message: str) -> bool:
    """Whether the not-found sentence is followed by a registry "denied: <message>" that is not
    the stock one of Docker Hub or GHCR."""
    return _SPECIFIC_DENIAL_AFTER_SENTENCE.search(message.strip()) is not None


def _is_registry_answered_denial(message: str) -> bool:
    """Whether a daemon pull message carries a refusal only an answering registry can give."""
    return _REGISTRY_ANSWERED_DENIAL.search(message) is not None


def _is_access_denied(message: str) -> bool:
    """Whether a cleaned daemon pull message says the registry refused (denied, unauthorized)."""
    lowered = message.lower()
    if lowered.rstrip(" .").endswith(_UNAUTHORIZED_SUFFIX):
        return True
    return any(marker in lowered for marker in _ACCESS_DENIED_MARKERS)


def _without_reference(message: str, reference: str) -> str:
    """``message`` with every echo of ``reference`` (and of its repository path) blanked out.

    The daemon repeats the image reference in its text, and a reference is tenant-chosen, so a
    name such as ``acme/forbidden-fruit`` must never trigger a marker. Only whole tokens are
    removed, so a one-letter repository cannot eat the middle of a marker word, and only a
    fragment with a slash, a colon or an at sign: a bare word (a reference named ``denied``)
    stays, since removing it would erase the marker word it equals.
    """
    text = message
    for fragment in sorted({reference, repository_name(reference)}, key=len, reverse=True):
        if _REFERENCE_PUNCTUATION.intersection(fragment):
            pattern = rf"(?<![\w.-]){re.escape(fragment)}(?![\w-])"
            text = re.sub(pattern, " ", text, flags=re.IGNORECASE)
    return text


def _registry_unreachable(reference: str) -> DriverRegistryUnreachable:
    return DriverRegistryUnreachable(
        f"could not pull {reference}: the registry did not answer (a transient network "
        "problem, or a registry host that does not exist); check the name, then try again",
        ref=reference,
    )


def _registry_tls_error(reference: str, daemon_text: str) -> DriverRegistryTlsError:
    """The tenant-safe TLS validation failure: a fixed message from the reference only; the daemon
    text (it can name the registry host and the certificate subject) goes to the debug log."""
    logger.debug("TLS validation failed pulling %s: %s", reference, daemon_text)
    return DriverRegistryTlsError(
        f"could not pull {reference}: the TLS connection to the registry failed validation "
        "(an untrusted or wrong certificate, or a plain-HTTP registry); fix the registry trust "
        "or configuration",
        ref=reference,
    )


def is_invalid_reference(message: str) -> bool:
    """Whether a cleaned daemon message says the image reference cannot be parsed."""
    return _INVALID_REFERENCE_MARKER in message.lower()


def access_denied(reference: str, daemon_text: str) -> DriverAccessDenied:
    """The tenant-safe refusal: the daemon text (it can quote the host's registry identity, an
    AWS role ARN in an ECR denial) goes to the debug log only."""
    logger.debug("registry refused the pull of %s: %s", reference, daemon_text)
    return DriverAccessDenied(
        f"the registry refused to pull {reference}; check the image name and the registry access",
        ref=reference,
    )


def invalid_reference(reference: str, daemon_text: str) -> DriverInvalidReference:
    """The tenant-safe unparsable reference: the reference plus the daemon's own sentence."""
    logger.debug("unparsable image reference %s: %s", reference, daemon_text)
    message = f"invalid image reference {reference}"
    if is_invalid_reference(daemon_text):
        message = f"{message}: {_INVALID_REFERENCE_MARKER}"
    return DriverInvalidReference(message, ref=reference)


def _unclassified(exc: DriverError, reference: str) -> DriverError:
    """The fixed "could not pull <reference>" in ``exc``'s type (a timeout keeps its code); the
    daemon text (account ids, internal hosts) is debug-only. The fixed disk-full one is kept."""
    if exc.message == DISK_FULL_MESSAGE:
        return exc
    logger.debug("pull of %s failed: %s", reference, exc.classification_text)
    return type(exc)(f"could not pull {reference}", ref=reference)


def classify_known_pull_failure(exc: DriverError, reference: str) -> DriverError | None:
    """The fixed-message driver error for a recognised pull failure, else ``None``.

    The not-found family (``DriverNotFound``) and the pull-denial sentence ("pull access denied
    ... may require 'docker login'") become ``DriverNotFound``. A reference the daemon cannot
    parse becomes ``DriverInvalidReference``; a registry that answered "denied", "unauthorized",
    a 401/403 status or "no basic auth credentials" becomes ``DriverAccessDenied``. A registry
    network failure (resolver, dial, timeout, an EOF), a throttled pull (HTTP 429) or a registry
    server error (HTTP 5xx) becomes ``DriverRegistryUnreachable``, since the image may well exist
    and a later attempt can succeed. A TLS validation failure (an x509 or certificate error, a
    plain-HTTP registry answering an HTTPS request) becomes ``DriverRegistryTlsError``: retrying
    cannot help, the registry trust or configuration must change.

    Matching runs on the text with the image reference removed (the daemon echoes it). Precedence,
    first match wins:

    1. The not-found family and the pull-denial sentence, unless the sentence is followed by a
       registry ``denied: <message>`` that is not the stock one of Docker Hub ("requested access
       to the resource is denied") or GHCR ("denied"): moby wraps every registry ``DENIED`` answer
       in that sentence, so a specific message is the registry refusing this pull, not a missing
       repository. The stock tails keep the Hub privacy mapping (a private repository is not told
       apart from a missing one).
    2. An unparsable reference.
    3. A refusal only an answering registry gives (a 401/403 status pair, a trailing ": denied",
       "denied" opening a line, ECR's "no basic auth credentials").
    4. The registry's own "unauthorized: <message>" / "denied: <message>" (opening the text or a
       line, or after a colon), unless the daemon's own words BEFORE that echo show a hard
       transport failure (dial, lookup, timeout, refused, EOF — a token fetch that could not
       dial). The message after the marker is the registry's text and may mention a certificate,
       a throttle, a 503 or network words such as "no such host" (SF75-001); the status it
       answered with decides, so an answered 401/403 is ``DriverAccessDenied`` whatever its body
       says.
    5. A TLS validation failure (an "x509: <sentence>", a "certificate" word, a plain-HTTP
       registry), before the transport markers (an EOF and a "TLS handshake timeout" are network
       conditions and stay unreachable).
    6. A transport failure (dial, lookup, timeout, refused, EOF) or a throttle or server error
       (429, 5xx), which wins over the remaining weak access-denied phrases.
    7. The weak, anchored access-denied phrases (": denied:", "unauthorized: ", "failed to
       authorize", a trailing ": unauthorized"), never bare words: "failed to authorize" also
       prefixes a token fetch the registry failed to serve with a 503.
    8. Other registry network failures.

    The text read is ``exc.daemon_text`` when set (an unclassified daemon failure carries the
    fixed generic sentence as its message), else ``exc.message``.
    """
    message = exc.classification_text
    probe = _without_reference(message, reference)
    if (
        isinstance(exc, DriverNotFound) or _is_pull_denied(probe)
    ) and not _is_specific_denial_after_sentence(probe):
        return DriverNotFound(f"no such image or snapshot: {reference}", ref=reference)
    if is_invalid_reference(probe):
        return invalid_reference(reference, message)
    if _is_registry_answered_denial(probe):
        return access_denied(reference, message)
    if _is_registry_body_denial(probe):
        return access_denied(reference, message)
    if _is_tls_validation_failure(probe):
        return _registry_tls_error(reference, message)
    if _is_transport_failure(probe):
        return _registry_unreachable(reference)
    if _is_access_denied(probe):
        return access_denied(reference, message)
    if _is_registry_network_failure(probe):
        return _registry_unreachable(reference)
    return None


def classify_pull_failure(exc: DriverError, reference: str) -> DriverError:
    """The tenant-safe driver error for a failed pull of ``reference``: a fixed message built from
    the reference the tenant supplied, never the daemon text (debug log only). A recognised
    failure is classified (``classify_known_pull_failure``); anything else keeps its type with
    "could not pull <reference>" (the disk-full conflict keeps its own fixed sentence)."""
    known = classify_known_pull_failure(exc, reference)
    return known if known is not None else _unclassified(exc, reference)


async def _pull(client: Any, reference: str) -> Any:
    """Pull ``reference``; a failure is re-raised as ``classify_pull_failure`` decides."""
    try:
        with translate_errors(reference, "image.pull"):
            return await run_bulk(client.images.pull, reference)
    except DriverError as exc:
        classified = classify_pull_failure(exc, reference)
        if classified is exc:
            raise
        raise classified from exc


async def pull_image_digest(client: Any, reference: str) -> str:
    image = await _pull(client, reference)
    return repo_digest(image.attrs, reference)


async def pull_image(client: Any, reference: str) -> ImageInfo:
    await _pull(client, reference)
    return await inspect_image(client, reference)


async def inspect_image(client: Any, ref: str) -> ImageInfo:
    with translate_errors(ref, "image.inspect"):
        attrs = await run_blocking(client.api.inspect_image, ref)
    return image_info(ref, attrs)


async def image_exists(client: Any, reference: str) -> bool:
    try:
        with translate_errors(reference, "image.exists"):
            await run_blocking(client.api.inspect_image, reference)
    except DriverNotFound:
        return False
    return True


async def _commit_conf(
    client: Any, provider_id: str, labels: Mapping[str, str] | None = None
) -> dict[str, Any]:
    """The commit config: the base image's ``Env`` plus ``KEY=`` for each key the sandbox added.

    ``labels``, when given, are merged into the image's labels.
    """
    container = await run_blocking(client.api.inspect_container, provider_id)
    base_ref = base_image_id(container)
    if not base_ref:
        raise DriverError(f"container {provider_id} names no base image", ref=provider_id)
    base = await run_blocking(client.api.inspect_image, base_ref)
    conf: dict[str, Any] = {"Env": commit_env(config_env(base), config_env(container))}
    if labels:
        conf["Labels"] = dict(labels)
    return conf


async def commit_container(
    client: Any,
    provider_id: str,
    image_reference: str,
    labels: Mapping[str, str] | None = None,
) -> CommitResult:
    """Commit with the container paused; the result carries the image id and layer count.

    The stored image carries no env value the sandbox set: the commit ``conf`` holds the base
    image's ``Env`` unchanged (an overridden key gets its base value back) plus ``KEY=`` for each
    key only the container has. Docker merges the commit config with the container's, so a key
    can be blanked but not removed; an empty value, not a missing key, is that limit.
    """
    repository, tag = _tag_target(image_reference)
    with translate_errors(provider_id, "container.commit"):
        conf = await _commit_conf(client, provider_id, labels)
        created = await run_bulk(
            client.api.commit, provider_id, repository=repository, tag=tag, pause=True, conf=conf
        )
        attrs = await run_blocking(client.api.inspect_image, created["Id"])
    return _commit_result(attrs)


def export_import(
    api: Any, provider_id: str, repository: str, tag: str | None, changes: Sequence[str]
) -> None:
    """Blocking: stream ``docker export`` straight into ``docker import`` (never buffered)."""
    stream = api.export(provider_id)
    api.import_image(
        src=stream,
        repository=repository,
        tag=tag,
        changes=list(changes) or None,
        stream_src=True,
    )


async def flatten_container(client: Any, provider_id: str, image_reference: str) -> CommitResult:
    """Export the container filesystem and import it as a single-layer ``image_reference``."""
    repository, tag = _tag_target(image_reference)
    with translate_errors(provider_id, "container.flatten"):
        attrs = await run_blocking(client.api.inspect_container, provider_id)
        state = attrs.get("State") or {}
        pause = bool(state.get("Running")) and not state.get("Paused")
        if pause:
            await run_blocking(client.api.pause, provider_id)
        try:
            await run_bulk(
                export_import,
                client.api,
                provider_id,
                repository,
                tag,
                config_changes(attrs.get("Config") or {}),
            )
        finally:
            if pause:
                await run_blocking(client.api.unpause, provider_id)
        image = await run_blocking(client.api.inspect_image, image_reference)
    result = _commit_result(image)
    if result.layer_count != FLAT_LAYER_COUNT:
        raise DriverError(
            f"flatten of {provider_id} produced {result.layer_count} layers", ref=provider_id
        )
    return result


async def remove_image(client: Any, ref: str, force: bool = False) -> None:
    with translate_errors(ref, "image.remove"):
        if force:
            await run_bulk(client.api.remove_image, ref, force=True)
        else:
            await run_bulk(client.api.remove_image, ref)
