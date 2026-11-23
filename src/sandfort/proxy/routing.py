"""Build and parse preview hostnames of the shape ``<port>-sbx-<id body>.preview.<domain>``.

The builder emits the id with a hyphen in place of its underscore, because an underscore is
not valid in a DNS label and strict TLS clients refuse to wildcard-match it. The parser also
accepts the legacy ``<port>-sbx_<id body>`` form and maps both to the canonical id.

Parsing is strict: anything that is not exactly that shape, with a port in
``MIN_PORT..MAX_PORT`` and a well-formed sandbox id, yields ``None``. Host headers
are matched as given; stripping a ``:port`` suffix is the caller's job (``strip_port``).
"""

import re
from dataclasses import dataclass

from sandfort.ids import SANDBOX, has_prefix

MIN_PORT = 1024
MAX_PORT = 65535
PREVIEW_LABEL = "preview"
MAX_HOSTNAME_LENGTH = 253

_DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
HOST_PATTERN = re.compile(
    rf"(?P<port>[0-9]{{1,5}})-{re.escape(SANDBOX)}[-_](?P<body>[a-z0-9]+)"
    rf"\.{PREVIEW_LABEL}\.(?P<domain>{_DNS_LABEL}(?:\.{_DNS_LABEL})*)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class PreviewTarget:
    port: int
    sandbox_id: str


def parse_preview_host(host: str) -> PreviewTarget | None:
    """Return the target port and canonical sandbox id, or ``None`` if ``host`` is not valid."""
    if len(host) > MAX_HOSTNAME_LENGTH:
        return None
    match = HOST_PATTERN.fullmatch(host)
    if match is None:
        return None
    port_text = match.group("port")
    if port_text.startswith("0"):
        return None
    port = int(port_text)
    if not MIN_PORT <= port <= MAX_PORT:
        return None
    sandbox_id = _canonical_sandbox_id(match.group("body"))
    if sandbox_id is None:
        return None
    return PreviewTarget(port=port, sandbox_id=sandbox_id)


def strip_port(host: str) -> str:
    """``host`` without a trailing ``:<digits>`` (a ``Host`` header may carry one)."""
    name, sep, port = host.rpartition(":")
    return name if sep and port.isdigit() else host


def preview_host(port: int, sandbox_id: str, preview_domain: str) -> str:
    """The lower-cased hostname ``parse_preview_host`` maps back to ``(port, sandbox_id)``.

    ``preview_domain`` already starts with the ``preview`` label (``Settings.preview_domain``).
    """
    return f"{port}-{_hostname_safe_id(sandbox_id)}.{preview_domain}".lower()


def _hostname_safe_id(sandbox_id: str) -> str:
    """The id with its single underscore as a hyphen: ``_`` is not valid in a DNS label."""
    return sandbox_id.replace("_", "-", 1)


def _canonical_sandbox_id(body: str) -> str | None:
    """Hostnames are case-insensitive; ids are ``sbx_`` plus an upper-case body."""
    candidate = f"{SANDBOX}_{body.upper()}"
    return candidate if has_prefix(candidate, SANDBOX) else None
