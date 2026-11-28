"""Ephemeral git credentials: one askpass helper per operation, always removed.

The helper is a tiny ``sh`` script answering git's username and password prompts. It is
written by an exec whose argv carries only the script path (the script, and so the token,
travels on stdin) to a per-operation unique path under the private ``ASKPASS_DIR``
(directory and script are mode 700, owned by the exec user). Git finds it through
``GIT_ASKPASS`` set on that one git exec only, and the script is removed in a ``finally``
step whether the operation succeeded or not. The token never reaches an argv, an
environment, an audit row or an error message: ``redact`` scrubs it (and the helper path)
from any text the git service surfaces. Credential objects live for one call only.

The script answers only a password prompt that names the expected host (derived from the
operation's remote url and baked in as a literal). Every other prompt, including username
prompts and prompts for other hosts, prints nothing and exits non-zero; the username
travels as ``credential.username`` config instead (see ``toolbox.git``). For push and
pull the expected host comes from the caller's ``remote_url``, never from the repository
config inside the sandbox (``require_same_target``).

Residual risk, stated plainly: any process inside the sandbox can still read the token
file during the operation window, because the script (and so the token) lives in the
sandbox filesystem. Tokens must therefore be short-lived and narrowly scoped. This stays
the documented limitation until the token moves out of the container.

The helper is also part of the container root filesystem, so a snapshot committed while it
exists (an operation in flight, or a removal that failed) holds the token. Nothing here
prevents that, because the snapshot job can run in another process than the git call. See
docs/security.md, "Git credentials".
"""

import asyncio
import logging
import re
import secrets
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import quote, urlsplit

from sandfort.drivers.base import ExecRequest, ExecResult, SandboxDriver
from sandfort.drivers.errors import DriverError
from sandfort.errors import Unprocessable

logger = logging.getLogger(__name__)

ASKPASS_DIR = "/tmp/.sandfort-git"
ASKPASS_PREFIX = "askpass-"
ASKPASS_ENV = "GIT_ASKPASS"
HELPER_TIMEOUT_S = 30.0
HELPER_OUTPUT_BYTES = 64 * 1024
REDACTED = "[redacted]"
# Fixed script: stores stdin at "$1" with no group/other bits. Only the path is an argument.
WRITE_SCRIPT = 'umask 077 && cat > "$1" && chmod 700 "$1"'
WRITE_ARGV0 = "sandfort-askpass"

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SCHEME_USERINFO = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)[^/]*@")
_SCP_USERINFO = re.compile(r"^[^/:]*@(?=[^/]*:)")
_TEXT_USERINFO = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)[^/\s'\"]*@")


class Credential(Protocol):
    """What a git operation needs from the request credential (``GitCredential``)."""

    @property
    def username(self) -> str: ...

    @property
    def token(self) -> str: ...


@dataclass(frozen=True, slots=True)
class Askpass:
    """A materialized helper; ``env`` is set on the single git exec that uses it."""

    path: str

    @property
    def env(self) -> dict[str, str]:
        return {ASKPASS_ENV: self.path}


def validate_credential(credential: Credential) -> None:
    """Reject values the helper cannot answer verbatim; the values are never echoed."""
    if not credential.username or not credential.token:
        raise Unprocessable("credential username and token must be non-empty")
    if _CONTROL.search(credential.username) or _CONTROL.search(credential.token):
        raise Unprocessable("credential username and token must not contain control characters")


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _target(url: str) -> tuple[str, str]:
    """``(scheme, host[:port])`` of an http(s) remote url, userinfo dropped."""
    try:
        parts = urlsplit(url)
    except ValueError:
        parts = urlsplit("")
    host = parts.netloc.rpartition("@")[2]
    if parts.scheme not in ("http", "https") or not host or _CONTROL.search(host):
        raise Unprocessable("a credentialed git operation needs an http(s) remote url")
    return parts.scheme, host


def remote_base(url: str) -> str:
    """``scheme://host[:port]/`` of ``url``: the prefix the credential may be used for."""
    scheme, host = _target(url)
    return f"{scheme}://{host}/"


def require_same_target(resolved: str, expected: str) -> None:
    """Refuse unless ``resolved`` (read from the sandbox) names the caller's scheme and host.

    ``expected`` is the caller's ``remote_url``; ``resolved`` is what the repository config
    inside the sandbox says the remote is, which sandbox code controls. Scheme and
    ``host[:port]`` compare case-insensitively; the resolved value is never echoed.
    """
    scheme, host = _target(expected)
    try:
        found_scheme, found_host = _target(resolved)
    except Unprocessable:
        found_scheme = found_host = ""
    if (found_scheme, found_host.lower()) != (scheme, host.lower()):
        raise Unprocessable(
            "the repository's remote url host does not match remote_url",
            details={"field": "remote_url"},
        )


def render_askpass(credential: Credential, url: str) -> bytes:
    """The helper script: git calls it with the prompt text as ``$1``.

    Only ``Password for '<scheme>://[user@]<host>'`` for the host of ``url`` is answered.
    """
    scheme, host = _target(url)
    plain = _shell_quote(f"Password for '{scheme}://{host}'")
    userinfo = _shell_quote(f"Password for '{scheme}://") + "*" + _shell_quote(f"@{host}'")
    lines = [
        "#!/bin/sh",
        'case "$1" in',
        f"  {plain}*|{userinfo}*) printf '%s\\n' {_shell_quote(credential.token)} ;;",
        "  *) exit 1 ;;",
        "esac",
    ]
    return ("\n".join(lines) + "\n").encode()


def new_askpass_path() -> str:
    return f"{ASKPASS_DIR}/{ASKPASS_PREFIX}{secrets.token_hex(16)}"


def strip_userinfo(url: str) -> str:
    """``url`` without a ``user[:password]@`` part (scheme URLs and scp-like ``user@host:``)."""
    stripped = _SCHEME_USERINFO.sub(r"\g<scheme>", url, count=1)
    if stripped != url or "://" in url:
        return stripped
    return _SCP_USERINFO.sub("", url, count=1)


def redact(text: str, *hidden: str | None, truncated: bool = False) -> str:
    """Scrub every ``hidden`` value (raw and URL-encoded) and any URL userinfo from ``text``.

    ``truncated`` says the text was cut by an output cap; its tail is then dropped too,
    because the cut may have split a secret whose prefix would otherwise survive.
    """
    values = {value for value in hidden if value}
    variants = values | {quote(value, safe="") for value in values}
    scrubbed = text
    for value in sorted(variants, key=len, reverse=True):
        scrubbed = scrubbed.replace(value, REDACTED)
    if truncated and values:
        scrubbed = scrubbed[: max(0, len(scrubbed) - max(len(value) for value in variants))]
    return _TEXT_USERINFO.sub(r"\g<scheme>", scrubbed)


async def _exec(
    driver: SandboxDriver, ref: str, argv: Sequence[str], stdin: bytes | None = None
) -> ExecResult:
    request = ExecRequest(
        argv=list(argv),
        stdin=stdin,
        timeout_s=HELPER_TIMEOUT_S,
        max_output_bytes=HELPER_OUTPUT_BYTES,
    )
    return await driver.exec(ref, request)


async def _install(driver: SandboxDriver, ref: str, path: str, script: bytes) -> None:
    prepared = await _exec(driver, ref, ["mkdir", "-p", "-m", "700", ASKPASS_DIR])
    if prepared.exit_code != 0 or prepared.timed_out:
        raise DriverError("could not prepare the git credential directory", ref=ref)
    written = await _exec(driver, ref, ["sh", "-c", WRITE_SCRIPT, WRITE_ARGV0, path], script)
    if written.exit_code != 0 or written.timed_out:
        raise DriverError("could not install the git credential helper", ref=ref)


async def _remove(driver: SandboxDriver, ref: str, path: str) -> None:
    removed = await _exec(driver, ref, ["rm", "-f", path])
    if removed.exit_code != 0 or removed.timed_out:
        raise DriverError("could not remove the git credential helper", ref=ref)


async def _cleanup(driver: SandboxDriver, ref: str, path: str, *, strict: bool) -> None:
    """Remove the helper; shielded so a cancelled request still finishes the removal."""
    try:
        await asyncio.shield(_remove(driver, ref, path))
    except DriverError:
        if strict:
            raise
        # The operation's own error is already propagating and stays the one reported.
        logger.warning("git credential helper cleanup failed in sandbox instance %s", ref)


@asynccontextmanager
async def ephemeral_askpass(
    driver: SandboxDriver, ref: str, credential: Credential, url: str
) -> AsyncIterator[Askpass]:
    """Materialize the helper for one git exec on ``url`` and always remove it afterwards.

    A cleanup failure after a successful operation raises ``DriverError`` (a helper may
    be left behind); after a failed operation it is logged and the original error wins.
    """
    validate_credential(credential)
    askpass = Askpass(new_askpass_path())
    script = render_askpass(credential, url)
    succeeded = False
    try:
        await _install(driver, ref, askpass.path, script)
        yield askpass
        succeeded = True
    finally:
        await _cleanup(driver, ref, askpass.path, strict=succeeded)
