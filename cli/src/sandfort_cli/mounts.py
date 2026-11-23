"""Volume mounts in the CLI: the ``VOLUME:PATH[:ro|rw]`` mode and the sandbox text view."""

import re
from collections.abc import Mapping, Sequence
from typing import Any

from sandfort_sdk import ApiError, ValidationFailed
from sandfort_sdk.models import MountInfo, SandboxInfo

from sandfort_cli.output import (
    LABELS_FIELD,
    AppState,
    is_blank,
    print_fields,
    sandbox_fields,
    shown,
)
from sandfort_cli.output import render_sandbox as render_sandbox_fields
from sandfort_cli.sanitise import MAX_ECHOED_VALUE_CHARS, caller_key, sanitise_text
from sandfort_cli.volume_refs import MOUNT_OPTION

# The volume part is a ``vol_`` id or a volume name.
MOUNT_SHAPE = "VOLUME:PATH[:ro|rw]"
MOUNT_HELP = (
    "Mount a volume as VOLUME:PATH[:ro|rw]; VOLUME is a volume name or a vol_ id, and a value "
    "starting with vol_ is always an id, so a volume named vol_x cannot be mounted by name "
    "(repeatable)."
)
READ_ONLY_MODE = "ro"
READ_WRITE_MODE = "rw"
MOUNT_PARTS_WITH_MODE = 3  # VOLUME, PATH and the mode
VOLUMES_FIELD = "volumes"
# The characters the server refuses in a mount path (the server stays authoritative; the CLI
# only mirrors these three so that the refusal comes before the request).
FORBIDDEN_PATH_CHARS = (":", ",", "\\")
MODE_PROBLEM = "mode must be ro or rw"
# A tail that is a mode written wrongly: only the words ro or rw in any case, optionally followed
# by further colon-separated parts. Punctuation around the word (``ro/``, ``ro,``) is not a mode.
MODE_LIKE_RE = re.compile(r"(?:ro|rw)(?::.*)?", re.IGNORECASE | re.DOTALL)


# A server validation location that points at one mount: ``body.volumes.N.mount_path`` (or
# ``.volume_id``), N counting the ``--mount`` values from zero.
MOUNT_LOCATION_RE = re.compile(r"body\.volumes\.(\d+)\.(?:mount_path|volume_id)")


def mount_location(issue: object, values: Sequence[str]) -> tuple[str, str] | None:
    """``(server location, option text)`` for a validation issue about one of the ``--mount``
    ``values``, else ``None``; the option text is ``--mount <the value as typed>``."""
    loc = issue.get("loc") if isinstance(issue, Mapping) else None
    if not isinstance(loc, list | tuple):
        return None
    dotted = ".".join(str(part) for part in loc)
    found = MOUNT_LOCATION_RE.fullmatch(dotted)
    if found is None or int(found.group(1)) >= len(values):
        return None
    return dotted, f"{MOUNT_OPTION} {values[int(found.group(1))]}"


def name_mount_option(exc: ApiError, values: Sequence[str]) -> ApiError:
    """``exc`` with each validation issue about a mount located at ``--mount <value>`` instead
    of ``body.volumes.N.mount_path``, in the details and in the message that repeats the first.

    Any other error is returned as it is. ``values`` are the ``--mount`` values as typed, in
    order (the server's index N is the position in that list).
    """
    errors = exc.details.get("errors")
    if not isinstance(exc, ValidationFailed) or not isinstance(errors, list):
        return exc
    message = exc.message
    renamed: list[Any] = []
    changed = False
    for position, issue in enumerate(errors):
        located = mount_location(issue, values)
        if located is None:
            renamed.append(issue)
            continue
        changed = True
        dotted, option = located
        renamed.append({**issue, "loc": [option]})
        if position == 0:
            message = message.replace(dotted, option, 1)
    if not changed:
        return exc
    return type(exc)(
        message,
        code=exc.code,
        status_code=exc.status_code,
        details={**exc.details, "errors": renamed},
        request_id=exc.request_id,
    )


def forbidden_char_problem(path: str, chars: Sequence[str]) -> str | None:
    """The sentence naming the first of ``chars`` found in ``path``, or ``None``."""
    for char in chars:
        if char in path:
            shown = repr(sanitise_text(path, api_key=caller_key(), limit=MAX_ECHOED_VALUE_CHARS))
            return f"mount path {shown} contains '{char}' which is not allowed in a mount path"
    return None


def is_mode_like(tail: str) -> bool:
    """True for an empty or blank ``tail`` and for ``ro`` or ``rw`` in any case, optionally
    followed by colon-separated parts: the part after the path's colon looks like a mode."""
    return is_blank(tail) or MODE_LIKE_RE.fullmatch(tail) is not None


def source_problem(volume: str, rest: str) -> str | None:
    """The sentence for a Windows drive-letter source (``C:\\data``), or ``None``.

    One ASCII letter followed by a backslash path is a drive, not a volume name or id; saying so
    is better than naming the backslash and the colon of the path that follows it.
    """
    if len(volume.strip()) == 1 and volume.strip().isascii() and rest.startswith("\\"):
        shown = repr(sanitise_text(volume.strip(), api_key=caller_key(), limit=1))
        return (
            f"the volume part {shown} looks like a Windows drive letter, "
            "not a volume name or a vol_ id"
        )
    return None


def path_problem(rest: str, parsed: tuple[str, bool] | None) -> str | None:
    """The sentence naming what is wrong with the mount path or the mode, or ``None``.

    ``rest`` is what follows the volume part; ``parsed`` is :func:`split_mount_mode` of it. When
    that is ``None`` and the first part is not blank, the part after the first colon is either
    mode-like (empty, or ``ro``/``rw`` mistyped: the mode message, or the generic shape error when
    more parts follow it) or not, and then the whole ``rest`` is taken as a path holding a colon.
    """
    if parsed is not None:
        return forbidden_char_problem(parsed[0].strip(), FORBIDDEN_PATH_CHARS)
    parts = rest.split(":")
    if is_blank(parts[0]):
        return None
    if is_mode_like(parts[1]):
        found = forbidden_char_problem(parts[0].strip(), FORBIDDEN_PATH_CHARS[1:])
        if found is not None or len(parts) > MOUNT_PARTS_WITH_MODE - 1:
            return found
        return MODE_PROBLEM
    return forbidden_char_problem(rest.strip(), FORBIDDEN_PATH_CHARS)


def split_mount_mode(rest: str) -> tuple[str, bool] | None:
    """``PATH[:ro|rw]`` as ``(path, read_only)``; ``None`` for any other shape.

    The path holds no colon (the server refuses one), so a second colon, an empty tail, an empty
    or blank path or a mode other than exactly ``ro`` or ``rw`` is not a mount and ends in a
    usage error (the server would answer an empty path with a 422).
    """
    parts = rest.split(":")
    path = parts[0]
    if is_blank(path):
        return None
    if len(parts) == 1:
        return rest, False
    mode = parts[-1]
    if len(parts) == MOUNT_PARTS_WITH_MODE - 1 and mode in (READ_ONLY_MODE, READ_WRITE_MODE):
        return path, mode == READ_ONLY_MODE
    return None


def mount_lines(volumes: Sequence[MountInfo]) -> str:
    """One ``volume:path`` per line, ``(ro)`` after a read-only mount; each sanitised."""
    key = caller_key()
    lines = [
        shown(f"{mount.volume_id}:{mount.mount_path}", key) + (" (ro)" if mount.read_only else "")
        for mount in volumes
    ]
    return "\n".join(lines)


def render_sandbox(state: AppState, info: SandboxInfo) -> None:
    """The sandbox view; the text form gains a ``volumes`` row when there are mounts."""
    if state.json_output or not info.volumes:
        render_sandbox_fields(state, info)
        return
    fields = {**sandbox_fields(info), VOLUMES_FIELD: mount_lines(info.volumes)}
    print_fields("sandbox", fields, folded=(LABELS_FIELD, VOLUMES_FIELD))
