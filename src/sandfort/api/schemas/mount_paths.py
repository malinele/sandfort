"""The request check for ``VolumeMountSpec.mount_path`` (round 59).

A mount path is stored on the sandbox record and shown in listings, so it follows the visible
text rule the labels use, and it must be an absolute, normalised path that does not replace the
image's own system files. A refusal names the character class or the segment at fault and
never echoes an invisible character raw (the path is shown escaped with ``ascii()``).
"""

import unicodedata

from sandfort.api.schemas.text_checks import (
    VARIATION_SELECTORS,
    content_violation,
    invisible_text_problem,
    plain_error,
)

COMBINING_GRAPHEME_JOINER = 0x034F
# The plural wording of the classes the refusal named before round 63 stays as published.
PLURALS = {
    "a control character": "control characters",
    "a bidi control character": "invisible format characters",
    "an invisible format character": "invisible format characters",
    "a line or paragraph separator": "line or paragraph separators",
    "a private-use character": "private-use characters",
    "a noncharacter": "noncharacters",
    "a non-ASCII space": "non-ASCII spaces",
    "a variation selector at the start": "variation selectors",
}
DOTS_SEGMENT_LENGTH = 3  # a segment of three or more dots (``...``) reads like ``..``
# Characters that read like ``/``, ``:``, ``,``, ``\\`` or ``.`` and so hide what the path is.
LOOKALIKES = {
    0xFF0F: "a fullwidth solidus",
    0xFF1A: "a fullwidth colon",
    0xFF0C: "a fullwidth comma",
    0xFF3C: "a fullwidth reverse solidus",
    0xFF0E: "a fullwidth full stop",
    0x2215: "a division slash",
    0x2216: "a set minus",
    0x2044: "a fraction slash",
    0x29F8: "a big solidus",
    0x2024: "a one dot leader",
    0x2025: "a two dot leader",
    0x2026: "an ellipsis",
    0xFFFC: "an object replacement character",
    0xFFFD: "a replacement character",
}
# Docker reads these in a bind string (``src:dst:mode,opt``): a path holding one is split apart
# and the daemon fails the start, so they are refused here with the character named.
BIND_SYNTAX_CHARACTERS = {":": "colon", ",": "comma", "\\": "backslash"}
# Top-level directories whose files belong to the image: a mount exactly there would replace
# them. A deeper path (``/root/work``, ``/usr/local/share/x``) is a sub-mount and stays allowed.
SYSTEM_DIRECTORIES = frozenset(
    {
        "bin",
        "boot",
        "dev",
        "etc",
        "lib",
        "lib64",
        "proc",
        "root",
        "run",
        "sbin",
        "sys",
        "usr",
        "var",
    }
)
# Trees where nothing may be mounted at any depth: kernel and device views and the boot files.
GUARDED_TREES = frozenset({"proc", "sys", "dev", "boot"})
SYSTEM_SUBPATHS = (("var", "run"),)  # ``/var/run`` is usually a link to ``/run``
# Trees that hold the binaries and libraries every exec needs: hiding any part of them breaks
# the sandbox, so they are refused at any depth (the directory itself included).
BINARY_TREES = (
    ("bin",),
    ("sbin",),
    ("lib",),
    ("lib32",),
    ("lib64",),
    ("usr", "bin"),
    ("usr", "sbin"),
    ("usr", "lib"),
    ("usr", "lib32"),
    ("usr", "lib64"),
    ("usr", "libexec"),
)
# Files Docker writes into the container, plus the account files: refused as exact paths only.
DOCKER_MANAGED_FILES = frozenset(
    {
        ("etc", "hosts"),
        ("etc", "hostname"),
        ("etc", "resolv.conf"),
        ("etc", "passwd"),
        ("etc", "group"),
        ("etc", "shadow"),
        ("var", "run", "docker.sock"),
        ("run", "docker.sock"),
    }
)


def _lookalike_problem(char: str) -> str | None:
    """The class ``char`` falls in when it is a look-alike or has no assigned meaning."""
    code = ord(char)
    if code in LOOKALIKES:
        return LOOKALIKES[code]
    if code in VARIATION_SELECTORS or code == COMBINING_GRAPHEME_JOINER:
        return "an invisible mark"
    if unicodedata.category(char) == "Cn":
        return "an unassigned code point"
    return None


def _character_problem(path: str) -> str | None:
    """The refused character of ``path`` as ``must not contain <class> (U+XXXX)``, or ``None``.

    The content rule of the other stored strings (controls, bidi, invisible format, separators,
    private-use, noncharacters), every space but U+0020, and the look-alikes of a path
    separator, a bind-syntax character or a dot; a space inside a segment stays fine.
    """
    if (found := content_violation(path, ascii_spaces_only=True)) is not None:
        name, point = found
        return f"must not contain {PLURALS.get(name, name)} ({point})"
    for char in path:
        if (lookalike := _lookalike_problem(char)) is not None:
            return f"must not contain {lookalike} (U+{ord(char):04X})"
    return None


def _bind_syntax_problem(path: str) -> str | None:
    """The first character of ``path`` that Docker's bind syntax reads as a separator."""
    for char in path:
        if char in BIND_SYNTAX_CHARACTERS:
            name = BIND_SYNTAX_CHARACTERS[char]
            return f"must not contain a {name} ({char!r}; docker bind syntax)"
    return None


def _segment_problem(segments: list[str]) -> str | None:
    """What is wrong with the segments of an absolute path (everything after the first ``/``)."""
    last = len(segments) - 1
    for index, segment in enumerate(segments):
        if segment == "":
            if index == last:
                return "must not end with '/' (trailing slash)"
            return "must not contain an empty segment ('//')"
        if segment in {".", ".."} or (
            len(segment) >= DOTS_SEGMENT_LENGTH and set(segment) == {"."}
        ):
            return f"must not contain a {segment!r} segment"
        if (problem := invisible_text_problem(segment)) is not None:
            return f"segment {problem}"
    return None


def _system_problem(segments: list[str]) -> str | None:
    """Why a system directory, or a path under a guarded tree, is refused, or ``None``."""
    first = segments[0]
    if first in GUARDED_TREES:
        if len(segments) == 1:
            return f"cannot be the system directory /{first}"
        return f"cannot be under the system directory /{first}"
    if len(segments) == 1 and first in SYSTEM_DIRECTORIES:
        return f"cannot be the system directory /{first}"
    for subpath in SYSTEM_SUBPATHS:
        if tuple(segments) == subpath:
            return f"cannot be the system directory /{'/'.join(subpath)}"
    return _binary_or_managed_problem(tuple(segments))


def _binary_or_managed_problem(segments: tuple[str, ...]) -> str | None:
    """Why a system binary tree or a Docker-managed file is refused, or ``None``."""
    for tree in BINARY_TREES:
        if segments[: len(tree)] == tree:
            name = "/" + "/".join(tree)
            if len(segments) == len(tree):
                return f"cannot be the system binaries {name}"
            return f"cannot be under the system binaries {name}"
    if segments in DOCKER_MANAGED_FILES:
        return f"cannot be the docker-managed file /{'/'.join(segments)}"
    return None


def mount_path_problem(path: str) -> str | None:
    """Why ``path`` is no valid mount path (without the leading ``mount path``), or ``None``."""
    if (problem := _character_problem(path)) is not None:
        return f"{problem}: {ascii(path)}"
    if (problem := _bind_syntax_problem(path)) is not None:
        return f"{problem}: {ascii(path)}"
    if not path.startswith("/"):
        return f"must be an absolute path (start with '/'): {ascii(path)}"
    if path == "/":
        return "cannot be the filesystem root"
    segments = path[1:].split("/")
    problem = _segment_problem(segments) or _system_problem(segments)
    return None if problem is None else f"{problem}: {ascii(path)}"


def check_mount_path(path: str) -> str:
    """``path`` unchanged; a 422 naming the problem (no pydantic prefix) when it is invalid."""
    if (problem := mount_path_problem(path)) is not None:
        raise plain_error(f"mount path {problem}")
    return path
