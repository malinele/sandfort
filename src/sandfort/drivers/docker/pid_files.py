"""Pid files the exec and pty wrappers leave in a sandbox's /tmp.

A wrapper removes its own file when it ends, and the kill exec removes it for a process it
kills. A sandbox stop SIGKILLs the wrapper with nothing to follow it, and a stopped container
runs no exec, so the leftover files wait until the sandbox starts again: ``DockerDriver.start``
calls ``remove_stale_pid_files_blocking`` then, when no command of this run exists yet.
"""

import logging
from typing import Any

from sandfort.drivers.docker.client import translate_errors
from sandfort.drivers.errors import DriverConflict, DriverNotFound

logger = logging.getLogger(__name__)

PID_FILE_DIR = "/tmp"
# $1 = directory. Both wrappers name their files ``.sf-exec-<id>.pid`` and ``.sf-pty-<id>.pid``.
_REMOVE_STALE_SCRIPT = 'rm -f -- "$1"/.sf-exec-*.pid "$1"/.sf-pty-*.pid'


def remove_stale_pid_files_blocking(client: Any, ref: str, directory: str = PID_FILE_DIR) -> None:
    """Best effort: delete the pid files a stop left behind (detached; never raises)."""
    try:
        with translate_errors(ref, "exec.cleanup"):
            cleanup_id = client.api.exec_create(
                ref, cmd=["sh", "-c", _REMOVE_STALE_SCRIPT, "sh", directory]
            )["Id"]
            client.api.exec_start(cleanup_id, detach=True)
    except (DriverNotFound, DriverConflict):
        # the container was removed or stopped meanwhile: its pid files went with it
        logger.debug(
            "stale pid files not removed in %s: container gone or stopped", ref, exc_info=True
        )
    except Exception:
        logger.warning("could not remove stale pid files in %s", ref, exc_info=True)
