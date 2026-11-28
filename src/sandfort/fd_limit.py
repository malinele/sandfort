"""Open-file limit of the server process (round 104).

Docker starts a container with a soft ``RLIMIT_NOFILE`` of 1024 and a much higher hard limit
(524288 under Docker's systemd unit). A preview request in flight, like an open preview
websocket, holds two descriptors: the client socket and the upstream socket. At the default
preview caps the process would run out of descriptors near 450 previews in flight, long before
the cap answers 503, and ``EMFILE`` then fails every accept and database connect in the process,
not only the previews. So at start-up ``sandfort-server`` raises its soft limit to the hard
limit (at most ``MAX_SOFT_LIMIT``) and logs a warning when the preview caps still do not fit.
"""

import logging
import resource
from dataclasses import dataclass

__all__ = [
    "DESCRIPTORS_PER_PREVIEW",
    "MAX_SOFT_LIMIT",
    "RESERVED_DESCRIPTORS",
    "OpenFileLimit",
    "preview_descriptor_need",
    "raise_open_file_limit",
]

logger = logging.getLogger(__name__)

MAX_SOFT_LIMIT = 1 << 20  # the soft limit asked for when the hard limit is unlimited or higher
DESCRIPTORS_PER_PREVIEW = 2  # client socket plus upstream socket, per request or websocket
# Everything else the process keeps open: the API's clients, the database pool, the Docker
# socket, idle client keep-alives, web terminal websockets (two each, outside the preview caps),
# logs and the interpreter's own files. An estimate, not a measurement.
RESERVED_DESCRIPTORS = 1024


@dataclass(frozen=True)
class OpenFileLimit:
    """The soft and hard ``RLIMIT_NOFILE`` after the raise, and the soft limit found before."""

    soft: int
    hard: int
    previous_soft: int


def preview_descriptor_need(max_concurrent: int, keepalive: int) -> int | None:
    """Descriptors the preview proxy can hold at its process cap; ``None`` when it has none.

    ``max_concurrent`` is ``preview_max_concurrent`` (0 = no cap) and ``keepalive`` the idle
    upstream connections the proxy's pool may keep on top of the requests in flight. The result
    is a lower bound: web terminals and idle client connections only have the reserve.
    """
    if max_concurrent <= 0:
        return None
    return DESCRIPTORS_PER_PREVIEW * max_concurrent + max(keepalive, 0) + RESERVED_DESCRIPTORS


def _target(soft: int, hard: int) -> int:
    ceiling = MAX_SOFT_LIMIT if hard == resource.RLIM_INFINITY else min(hard, MAX_SOFT_LIMIT)
    return max(soft, ceiling)


def raise_open_file_limit(need: int | None = None) -> OpenFileLimit:
    """Raise the soft open-file limit to the hard limit; warn when it stays below ``need``.

    Never raises: a platform that refuses the new limit (macOS caps it below an unlimited hard
    limit) keeps its current one, which is logged. ``need`` is what the preview proxy can hold
    (``preview_descriptor_need``); ``None`` checks nothing.
    """
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = _target(soft, hard)
    if target > soft:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        except (ValueError, OSError) as error:
            logger.info("open-file limit kept at %d (raise to %d: %s)", soft, target, error)
        else:
            logger.info("open-file limit raised from %d to %d (hard %d)", soft, target, hard)
    current, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if need is not None and current < need:
        logger.warning(
            "open-file limit %d is below the %d descriptors the preview caps can hold; raise the"
            " container's nofile limit or lower SANDFORT_PREVIEW_MAX_CONCURRENT",
            current,
            need,
        )
    return OpenFileLimit(soft=current, hard=hard, previous_soft=soft)
