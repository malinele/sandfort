"""Cache headers of a proxied preview answer, so no shared cache keeps a private one.

A private sandbox answers only a request that carried a preview token, in the ``TOKEN_HEADER``
request header, the query or the cookie. A shared cache in front of the preview domain (a CDN
or a company proxy) must not keep that answer and hand it to a request without the token, while
the viewer's own browser may still cache it. :func:`private_cache_headers` makes
``Cache-Control`` start with a bare ``private`` and drops the directives that only address
shared caches (``public``, ``s-maxage``, ``proxy-revalidate``, and a ``private`` that names
fields, which lets a shared cache keep the rest). Every other directive stays as the sandbox
sent it. ``Vary`` gains each of ``VARY_ON`` it lacks, and a ``Vary: *`` stays as sent. The CDN
targeted headers (``CDN-Cache-Control``, ``<vendor>-CDN-Cache-Control``, ``Surrogate-Control``)
are dropped, since a CDN that reads them ignores ``Cache-Control``.
:func:`answer_cache_headers` picks the rule for one answer: ``no-store`` for a request URL that
named the token parameter (``with_token_response_headers``), else the private rule for a
private sandbox, else the headers of a public sandbox as its app sent them.
"""

import re
from typing import Final

from sandfort.proxy.hygiene import Headers, with_token_response_headers

CACHE_CONTROL: Final = b"cache-control"
VARY: Final = b"vary"
PRIVATE: Final = "private"
_SHARED_ONLY: Final = frozenset({"public", "s-maxage", "proxy-revalidate", PRIVATE})
VARY_ON: Final = ("Cookie", "Sandfort-Preview-Token")  # the token's carriers besides the URL
_CDN_TARGETED: Final = b"cdn-cache-control"  # RFC 9213, also with a vendor prefix
_SURROGATE: Final = b"surrogate-control"
# One element of a comma separated list: a quoted string stays whole, commas inside included.
_ELEMENT: Final = re.compile(r'(?:[^,"]|"(?:[^"\\]|\\.)*"?)+')


def _elements(headers: Headers, name: bytes) -> list[str]:
    """The stripped, non empty list elements of every ``name`` header, in their order."""
    values = [value.decode("latin-1") for key, value in headers if key.lower() == name]
    found = (match.group().strip() for value in values for match in _ELEMENT.finditer(value))
    return [element for element in found if element]


def _directive(element: str) -> str:
    return element.partition("=")[0].strip().lower()


def _cdn_targeted(name: bytes) -> bool:
    lowered = name.lower()
    return lowered.endswith(_CDN_TARGETED) or lowered == _SURROGATE


def private_cache_headers(headers: Headers) -> Headers:
    """``headers`` with ``Cache-Control`` private and ``Vary`` naming the token's carriers.

    The rebuilt ``Cache-Control`` and ``Vary`` go last, one line each, and every other header
    keeps its place and value. ``VARY_ON`` names already in ``Vary`` (in any case) are not
    added twice.
    """
    cache_control = _elements(headers, CACHE_CONTROL)
    kept = [element for element in cache_control if _directive(element) not in _SHARED_ONLY]
    rebuilt = [(CACHE_CONTROL, ", ".join([PRIVATE, *kept]).encode("latin-1"))]
    replaced = {CACHE_CONTROL}
    vary = _elements(headers, VARY)
    if "*" not in vary:
        named = {element.lower() for element in vary}
        added = [name for name in VARY_ON if name.lower() not in named]
        rebuilt.append((VARY, ", ".join([*vary, *added]).encode("latin-1")))
        replaced.add(VARY)
    others = [
        (key, value)
        for key, value in headers
        if key.lower() not in replaced and not _cdn_targeted(key)
    ]
    return [*others, *rebuilt]


def answer_cache_headers(headers: Headers, *, private: bool, token_url: bool) -> Headers:
    """The cache headers of one proxied HTTP answer (see the module docstring)."""
    if token_url:
        return with_token_response_headers(headers)
    return private_cache_headers(headers) if private else headers
