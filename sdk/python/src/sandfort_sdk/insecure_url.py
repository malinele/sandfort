"""Warn when ``base_url`` sends the api key over plain http to a host that is not loopback."""

import ipaddress
import warnings
from urllib.parse import urlsplit

LOOPBACK_NAME = "localhost"
# Stack: this helper, the client ``__init__``, then the caller that built the client.
CALLER_STACKLEVEL = 3


class InsecureBaseUrlWarning(UserWarning):
    """``base_url`` is ``http://`` for a host that is not loopback, so ``Authorization`` is sent
    in clear text. Use ``https://``, or filter this class for a trusted private network."""


def insecure_host(base_url: str) -> str | None:
    """The host of ``base_url`` when it is ``http`` and not loopback, else ``None``.

    Loopback is ``localhost``, any 127.0.0.0/8 address and ``::1``. A url that cannot be
    parsed gives ``None`` (the http client reports it). Userinfo is never part of the result.
    """
    try:
        parts = urlsplit(base_url.strip())
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme != "http" or not host:
        return None
    if host.rstrip(".") == LOOPBACK_NAME:
        return None
    try:
        if ipaddress.ip_address(host).is_loopback:
            return None
    except ValueError:
        pass
    return host


def warn_if_insecure_base_url(base_url: str, *, stacklevel: int = CALLER_STACKLEVEL) -> None:
    """Emit :class:`InsecureBaseUrlWarning` for an ``http://`` base url to a remote host."""
    host = insecure_host(base_url)
    if host is None:
        return
    warnings.warn(
        f"base_url uses http:// for host {host!r}, so the api key is sent in clear text. "
        "Use https://, or filter InsecureBaseUrlWarning if the network is private and trusted.",
        InsecureBaseUrlWarning,
        stacklevel=stacklevel,
    )
