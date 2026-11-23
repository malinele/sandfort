"""The text sanitiser: everything the CLI prints that came from the server, the network or the
caller's own typing goes through here.

It strips terminal escapes, control and invisible characters, masks the caller's api key (exact,
url-encoded, partly percent-encoded) and any key-shaped token, masks url userinfo, query values
and fragments, and cuts text to a bound. The login code, the shared error presentation
(:mod:`sandfort_cli.output`) and the usage-error frames (:mod:`sandfort_cli.main`) all use it.

The mask-stage helpers (the views of a text, the edit machinery and the query and fragment
stages) live in :mod:`sandfort_cli.sanitise_stages` and are re-exported from here; the host-run
and IDNA helpers they use live in :mod:`sandfort_cli.sanitise_hosts`.

Intended trade-off: a fragment mask needs only a url-ish context before the ``#``, not a scheme,
so a scheme-less token is masked too when it is dotted or holds a path. Ordinary dotted or path
tokens followed by a hash (version strings such as ``v1.2.3#build``, file names with anchors such
as ``README.md#install`` or ``docs/guide.md#usage``) are therefore masked as ``#***``. Showing
such a token a little too little is accepted; leaking the fragment of a real url is not. The one
exception is a fragment of only ASCII digits, up to six of them (``refs/heads/feature#12``,
``page.html#42``): it reads as an anchor or an issue number and is shown as written. A scheme
tightens that rule: with ``://`` before the anchor in the same token only up to three digits stay,
so a verify link with a six-digit code (``https://host.test/verify#123456``) is masked. Conscious
trade-off: a scheme-less ``host.test/verify#123456`` and a scheme-relative ``//host/verify#123456``
keep a six-digit fragment, because without a scheme they cannot be told from an anchor or an
issue number.

A query is masked after a host part: any run of letters (of any script), digits, ``-``, ``_`` and
``.`` before the ``?`` counts, so ``café?token=...`` is masked like ``what?x=1``. The IDNA dot
variants (U+3002, U+FF0E, U+FF61, U+2024, U+2025) read as ``.``, and a run that holds a letter may
also hold non-ASCII punctuation and symbols (en dash, middle dot, katakana middle dot, emoji), so
a host written with an ideographic full stop or an en dash between its letters is masked like
the ASCII one. Brackets, quotes and sentence breaks (the ideographic and fullwidth commas, the
fullwidth exclamation and question marks, the ellipsis and the like) are prose and do not make a
host: a Japanese sentence with an ideographic comma before ``?x=1`` stays. A fragment is not
eaten with the closers ``)``, ``]``, ``}``, ``>``, ``|``, an ellipsis, curly closing quotes or CJK
closing brackets and punctuation behind it (``[refs/heads/feature#12]`` stays as written).

A credential without a scheme (``user:secret@host:8443``, also with an empty user:
``:secret@host:8443``) is masked when the host is followed by a port or a path; with an empty user
the host must also have a port, be bracketed, be dotted or start with a letter (``ratio :3@2/3``
stays), and a leading ``key=`` is kept as written (``x=:secret@host:8443`` shows
``x=host:8443``). Inside such a credential any Unicode White_Space character other than the
plain ASCII space and LF (tab, CR, no-break space, line and paragraph separators and so on) does
not end it. Intended trade-off: a plain ASCII space or an LF inside a bare credential still ends
it, because a plain space is what separates words in prose and the line break separates records;
the part after the space is then a token of its own and is judged on its own. The whitespace
rule also covers the part after the ``@``: one whitespace character (not the plain space or LF)
between the ``@`` and a host-shaped token (dotted, bracketed or with a port) does not hide the
password (``admin:pw@<TAB>host.internal:8443/x``), and one between the two slashes of a
scheme-relative url (``/<TAB>/pw@evil.example/x``) does not either. A plain space or LF after the
``@`` or between the slashes still ends the match, for the same reason as above. The same holds
for a tab or a no-break space after the ``@``: a dotted, bracketed or port-shaped token behind it
is treated as a host, so ``meeting at 12:30@<TAB>room.b`` is masked (a prose false positive that
is accepted, as above).

Two false positives of the bare form are deliberate. An empty user before a real-looking host
loses its label: ``see :name@host.com/page`` is shown as ``see host.com/page``. A non-empty user
before a numeric host with a path (``ratio 3:2@4/5``, ``mailto:me@x.com/y``) is still masked,
because it has the shape ``user:pw@host/path``. Showing such text a little too little is accepted;
leaking a password is not.

An unterminated string sequence (APC, OSC, DCS, PM, SOS) inside a text swallows the rest of that
text in the displayed view. That is the terminal's own semantics and the safe choice: what
follows such an introducer is never shown, whatever it holds.
"""

import os
import re
import string
from collections.abc import Callable
from functools import lru_cache
from typing import Any
from urllib.parse import quote, quote_plus, unquote, urlsplit, urlunsplit

from typer import BadParameter

from sandfort_cli.sanitise_hosts import (
    HOST_OPENERS,
    MAX_HOST_CHARS,
    QUERY_SHAPED_RE,
    URLISH_HOST_RE,
)
from sandfort_cli.sanitise_stages import (
    ALL_SPACES,
    CLOSING_PARENTHESIS,
    CONTROL_SPACES,
    DEFAULT_IGNORABLE,
    DISPLAY_FILLERS,
    DISPLAY_KEPT_FORMAT,
    DISPLAY_STRIPPED_CATEGORIES,
    EXTRA_INVISIBLE,
    INVISIBLE_CATEGORIES,
    MASK,
    MATCH_ONLY_INVISIBLE,
    MAX_MASK_ROUNDS,
    SEQUENCE_OPENERS,
    STRING_INTRODUCER_RE,
    STRING_TERMINATOR_RE,
    SURROGATE_CATEGORY,
    TAG_FLAG_SEQUENCE_RE,
    TERMINAL_SEQUENCE_RE,
    VIEW_CACHE_SIZE,
    WORD_ACROSS_BREAKS_RE,
    WORD_RE,
    Edit,
    Edits,
    Sequence,
    Span,
    View,
    _after_group_one,
    _after_slashes,
    _fragments_once,
    _masked_match,
    _masked_sub,
    _queries_once,
    _until_stable,
    _view,
    is_hidden_in_display,
    is_invisible,
    mask_fragments,
    mask_queries,
    strip_invisible,
)

# The stage helpers moved to sanitise_stages.py; these names keep their import path from here.
__all__ = [
    "CLOSING_PARENTHESIS",
    "DEFAULT_IGNORABLE",
    "DISPLAY_FILLERS",
    "DISPLAY_KEPT_FORMAT",
    "DISPLAY_STRIPPED_CATEGORIES",
    "EXTRA_INVISIBLE",
    "HOST_OPENERS",
    "INVISIBLE_CATEGORIES",
    "MASK",
    "MATCH_ONLY_INVISIBLE",
    "MAX_HOST_CHARS",
    "MAX_MASK_ROUNDS",
    "QUERY_SHAPED_RE",
    "SEQUENCE_OPENERS",
    "STRING_INTRODUCER_RE",
    "STRING_TERMINATOR_RE",
    "SURROGATE_CATEGORY",
    "TAG_FLAG_SEQUENCE_RE",
    "TERMINAL_SEQUENCE_RE",
    "URLISH_HOST_RE",
    "VIEW_CACHE_SIZE",
    "WORD_ACROSS_BREAKS_RE",
    "WORD_RE",
    "Edit",
    "Edits",
    "Sequence",
    "Span",
    "View",
    "is_hidden_in_display",
    "is_invisible",
    "mask_fragments",
    "mask_queries",
    "strip_invisible",
]

ELLIPSIS = "…"
# C0 (U+0000-U+001F), DEL and C1 (U+0080-U+009F) control characters.
_CONTROL_CHARS = re.compile("[\x00-\x1f\x7f-\x9f]")
# The control characters that ``str.split`` does not treat as whitespace.
_NON_SPACE_CONTROLS_RE = re.compile("[\x00-\x08\x0e-\x1b\x7f-\x84\x86-\x9f]")

# Anchored: the url being saved. Unanchored: any url inside free text (a transport error, a
# server message); it stops at whitespace so it cannot swallow the words around the url.
USERINFO_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*://)[^/?#]*@")
# The userinfo patterns run in linear time on hostile text: a lookbehind lets a match start only
# at the beginning of a run or token (so a long run is scanned once, not once per character) and
# possessive quantifiers forbid backtracking into a run that already matched.
USERINFO_ANYWHERE_RE = re.compile(
    r"(?<![A-Za-z0-9+.-])([0-9+.-]*+[A-Za-z][A-Za-z0-9+.-]*+://)(?:[^/?#\s@]*+@)++"
)
# Userinfo without a scheme: ``//user:pw@host`` (scheme-relative) and ``user:pw@host``.
SCHEME_RELATIVE_USERINFO_RE = re.compile(r"(?<![\w:/])//(?:[^/?#\s@]*+@)++")
# The first masking pass (on the raw text, before flattening) lets any whitespace other than the
# plain space sit inside the userinfo (tab, newline, vertical tab, form feed, the separator
# controls, next-line, non-breaking and other Unicode spaces, line and paragraph separators:
# exactly what the flattening step turns into a space), so such a character inside a password
# cannot split the url into an unmasked password prefix and a host. The raw text is already
# cut, so the time is bounded.
USERINFO_CHAR = r"[^/?# @]"
USERINFO_ACROSS_BREAKS_RE = re.compile(
    rf"(?<![A-Za-z0-9+.-])([0-9+.-]*+[A-Za-z][A-Za-z0-9+.-]*+://)(?:{USERINFO_CHAR}*+@)++"
)
# Group 1 is the two slashes; a whitespace character other than the plain space and LF may sit
# between them (``/<TAB>/HunterPW@evil.example/x`` flattens to ``/ /HunterPW@...``).
SCHEME_RELATIVE_ACROSS_BREAKS_RE = re.compile(rf"(?<![\w:/])(/[^\S \n]?/)(?:{USERINFO_CHAR}*+@)++")
# Fully bare ``user:pw@host`` is masked only when it reads as a url authority: the host is
# followed by a port or a path segment. ``word:name@example.com`` (a mailto address, a label and
# an email) is left alone, so a plain ``user:pw@plainword`` is no longer masked. A match starts
# at a token start (after whitespace or a slash); the user part may hold ``@`` so that nothing
# before the password is left to a second start inside the same token. A leading ``key=`` run is
# group 1 and is kept (``x=:secret@host:8443`` shows ``x=host:8443``): it is a label, not a user.
# With an empty user (``:secret@host``) the host must read as a host: it has a port, is bracketed
# (IPv6), is dotted or starts with a letter, so ``ratio :3@2/3`` stays as written.
_BARE_KEY_PREFIX = r"(?<![^\s/])((?:[^\s/:=]*+=)*+)"
# The lookahead after the last ``@`` is bounded to a hostname (RFC 1035: at most 253 characters),
# so no start scans far past its own token.
_H = 253
_BARE_ANY_HOST = rf"(?=(?:\[[^\]\s]{{0,{_H}}}+\]|[^\s/@:]{{1,{_H}}}+)(?::\d+\b|/))"
_BARE_EMPTY_USER_HOST = (
    rf"(?=\[[^\]\s]{{0,{_H}}}+\](?::\d+\b|/)|[^\s/@:]{{1,{_H}}}+:\d+\b"
    rf"|(?:[^\W\d_][^\s/@:]{{0,{_H}}}+|[^\s/@:.]{{0,{_H}}}+\.[^\s/@:]{{1,{_H}}}+)/)"
)


# Across breaks only: one whitespace character (not the plain space or LF) after the ``@`` may
# precede a host-shaped token: dotted, bracketed or with a port (``admin:pw@<TAB>host.internal``).
_BARE_BREAK_HOST = (
    rf"(?=[^\S \n](?:\[[^\]\s]{{0,{_H}}}+\]|[^\s/@:.]{{1,{_H}}}+\.[^\s/@:]{{1,{_H}}}+"
    rf"|[^\s/@:]{{1,{_H}}}+:\d+\b))"
)


def _bare_pattern(password: str, after_break: str = "") -> re.Pattern[str]:
    pairs = rf"(?:{password}@)++"
    return re.compile(
        rf"{_BARE_KEY_PREFIX}(?:[^\s/:=]++:{pairs}(?:{_BARE_ANY_HOST}{after_break})"
        rf"|:{pairs}(?:{_BARE_EMPTY_USER_HOST}{after_break}))"
    )


BARE_USERINFO_RE = _bare_pattern(r"[^\s/@]*+")
# The same on raw text: the password may hold any whitespace character except the plain space and
# LF (tab, CR, vertical tab, form feed, next-line, non-breaking and other Unicode spaces, line and
# paragraph separators), which the flattening would later turn into a space. A plain space or LF
# still ends a bare credential (the documented trade-off in the module docstring). The password
# crosses tokens here, so it is bounded: unbounded, every start after a tab would scan to the end
# of the text (quadratic on ``:a<TAB>`` repeated). A longer password without breaks is still
# masked by ``BARE_USERINFO_RE``.
MAX_BARE_PASSWORD_CHARS = 256
BARE_ACROSS_BREAKS_RE = _bare_pattern(
    rf"[^\n /@]{{0,{MAX_BARE_PASSWORD_CHARS}}}+", f"|{_BARE_BREAK_HOST}"
)
# Control characters that are not whitespace (whitespace ones are turned into a space by the
# flattening step) and lone surrogates (a Python string can hold one; it cannot be printed);
# removed before the tail of a cut text is examined.
HIDDEN_CONTROLS_RE = re.compile("[\x00-\x08\x0e-\x1b\x7f-\x84\x86-\x9f\ud800-\udfff]")
MAX_RELAYED_CHARS = 300
# Hostile text is cut to this many characters BEFORE any pattern runs, so the running time is
# bounded whatever the server sends.
MAX_RAW_CHARS = 2000
# Missing scopes relayed from a reply; the rest is only counted (``missing_scopes_beyond_cap``).
MAX_RELAYED_SCOPES = 20
# A url echoed inside a message is cut on its own, so the reason after it always survives.
MAX_ECHOED_URL_CHARS = 200
# A user-typed value (label, env, expiry) echoed inside a usage message is cut on its own, so
# the reason after it survives the whole-message cap.
MAX_ECHOED_VALUE_CHARS = 120
USAGE_MESSAGE_CHARS = 600
# The longest partial api key looked for at the cut of the raw text.
MAX_KEY_TAIL_CHARS = 256
# A partial key may be percent-encoded, also repeatedly (``%5F``, ``%255F``, ``%25255F``: up to
# seven characters per key character for the three levels looked for at the cut).
ENCODED_TAIL_FACTOR = 7
# Percent-decoding rounds (until the text is stable) when a key is looked for in a decoded copy.
MAX_DECODE_ROUNDS = 4
# The tail token examined at the cut is bounded: a long spaceless text (CJK, Thai) with a colon
# loses at most this many trailing characters, never the whole message.
MAX_TAIL_TOKEN_CHARS = 256
INCOMPLETE_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]?$")
# The api key prefix followed by a long key-like tail: any such token from the server is masked,
# not only the caller's own key. The prefix must not follow an alphanumeric, so a longer
# identifier that merely contains it in the middle is left alone.
KEY_SHAPE_RE = re.compile(r"(?<![A-Za-z0-9])sf_[A-Za-z0-9_-]{16,}")
KEY_SHAPE_TAIL_RE = re.compile(r"sf_[A-Za-z0-9_-]{0,15}$")
# A key longer than this is matched through its literal and encoded forms only.
MAX_KEY_PATTERN_CHARS = 512
SCHEME_CHARS = string.ascii_letters + string.digits + "+.-"
URL_TERMINATORS = "/?#"
# The unreserved characters the standard quote leaves as they are.
UNRESERVED_ESCAPES = {"_": "%5F", "-": "%2D", ".": "%2E", "~": "%7E"}
PORT_MAX = 65535
# A host in brackets (IPv6) must be the whole host: ``[addr]`` with an optional ``:port``.
BRACKETED_AUTHORITY_RE = re.compile(r"\[[^\[\]]+\](?::[^\[\]]*)?")
# Server text in the shared error report: one field, one value inside ``details``.
MAX_RELAYED_CODE_CHARS = 100
MAX_RELAYED_ID_CHARS = 128
# Entries of a ``details`` mapping or list that are relayed; the nesting depth that is kept.
MAX_RELAYED_ENTRIES = 50
MAX_RELAYED_DEPTH = 4
# Text the CLI itself wrote (a usage or local error) is not cut short, only bounded.
MAX_LOCAL_CHARS = 2000
# The key shape written with percent escapes (``sf%5Ftest...``, up to every byte escaped): the
# escapes allowed are exactly those of ``[A-Za-z0-9_-]``.
_KEY_ESCAPE = r"%(?i:2d|3[0-9]|4[1-9a-f]|5[0-9af]|6[1-9a-f]|7[0-9a])"
KEY_SHAPE_ENCODED_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:s|%(?i:73))(?:f|%(?i:66))(?:_|%(?i:5f))"
    rf"(?:[A-Za-z0-9_-]|{_KEY_ESCAPE}){{16,}}+"
)


def flatten_text(value: str) -> str:
    """``value`` on one line without control characters, however long it is.

    Whitespace runs (newlines and tabs included) become one space; every other C0 or C1 control
    character (ESC among them) is dropped first, so a dropped one leaves no double or trailing
    space (flattening twice gives the same text as once).
    """
    return _CONTROL_CHARS.sub("", " ".join(_NON_SPACE_CONTROLS_RE.sub("", value).split()))


def mask_query(query: str) -> str:
    """``a=1&b=2`` as ``a=***&b=***``; a pair without ``=`` is masked whole."""
    if not query:
        return query
    pairs = [
        f"{pair.partition('=')[0]}={MASK}" if "=" in pair else MASK for pair in query.split("&")
    ]
    return "&".join(pairs)


def _credentials_once(text: str) -> str:
    return _fragments_once(_queries_once(_userinfo_once(text), True), True)


def _credentials_masked(text: str) -> str:
    """:func:`mask_credentials` without the cut, for text that is already bounded."""
    return _until_stable(_credentials_once, text)


def mask_credentials(text: str) -> str:
    """Userinfo, query and fragment masked for text whose whitespace is not yet flattened
    (whitespace other than the plain space inside a password or a value does not end it); used
    on the raw text before the terminal strip and again after it.

    Like :func:`mask_raw_userinfo`, the text is first cut to ``MAX_RAW_CHARS`` (so the time is
    bounded on any input, ``u:p@<TAB>`` repeated included); after a cut a trailing token holding
    a colon or a double slash (a credential cut short) is dropped."""
    raw = text[:MAX_RAW_CHARS]
    shown = _credentials_masked(raw)
    return drop_partial_url(shown) if len(raw) < len(text) else shown


def mask_userinfo(text: str) -> str:
    """``text`` without ``user:password@`` parts (with a scheme, scheme-relative or bare)."""
    shown = USERINFO_ANYWHERE_RE.sub(r"\1", text)
    shown = SCHEME_RELATIVE_USERINFO_RE.sub("//", shown)
    return BARE_USERINFO_RE.sub(r"\1", shown)


_USERINFO_PASSES: tuple[tuple[re.Pattern[str], Span], ...] = (
    (USERINFO_ACROSS_BREAKS_RE, _after_group_one),
    (SCHEME_RELATIVE_ACROSS_BREAKS_RE, _after_group_one),
    (USERINFO_ANYWHERE_RE, _after_group_one),
    (SCHEME_RELATIVE_USERINFO_RE, _after_slashes),
    (BARE_ACROSS_BREAKS_RE, _after_group_one),
    (BARE_USERINFO_RE, _after_group_one),
)


def mask_raw_userinfo(text: str) -> str:
    """:func:`mask_userinfo` for raw text: any whitespace other than the plain space (tab, line
    breaks, vertical tab, form feed, separators, non-breaking and Unicode spaces) inside the
    userinfo of a url (with a scheme or scheme-relative) does not end it, so no password prefix
    survives the later flattening of whitespace into spaces.

    Each pattern runs on the text as written, through the ignorable characters (an escape byte,
    control or invisible character inside the marker or the credential pair must not hide it)
    and on the displayed view (a terminal sequence inside a password whose body holds an ``@``
    must not end the match early); a masked span that ends inside a sequence takes the rest of
    the sequence with it, so its body never becomes text.

    The text is first cut to ``MAX_RAW_CHARS`` (so the time is bounded on any input); after a cut
    a trailing token holding a colon or a double slash (a credential cut short) is dropped."""
    raw = text[:MAX_RAW_CHARS]
    shown = _until_stable(_userinfo_once, raw)
    return drop_partial_url(shown) if len(raw) < len(text) else shown


def _userinfo_once(text: str) -> str:
    for pattern, span_of in _USERINFO_PASSES:
        text = _masked_sub(text, pattern, span_of, False)
    return text


def redact_url(url: str) -> str:
    """``url`` (or free text holding urls) as it may be echoed: no ``user:password@`` part
    anywhere, query values masked (``k=***``), a url's fragment masked whole (``#***``), with or
    without a scheme.

    Pattern based, so it also works on a malformed url (an unclosed IPv6 bracket) that
    ``urlsplit`` refuses.
    """
    return _until_stable(lambda text: _fragments_once(_queries_once(mask_userinfo(text))), url)


def endpoint_url(base_url: str, path: str) -> str:
    """``base_url`` plus ``path``, without userinfo (so no Basic header can be derived from it).

    The path goes before a query string; a fragment is dropped. Raises :class:`ValueError`
    for a url ``urlsplit`` cannot parse.
    """
    parts = urlsplit(base_url)
    netloc = parts.netloc.rpartition("@")[2]
    return urlunsplit((parts.scheme, netloc, parts.path.rstrip("/") + path, parts.query, ""))


def percent_encode_fully(text: str, *, alphanumerics: bool = False) -> str:
    """``text`` percent-encoded with the unreserved ``_ - . ~`` encoded too (the standard quote
    leaves them, so an ``sf_`` key would barely change); with ``alphanumerics`` every byte."""
    if alphanumerics:
        return "".join(f"%{byte:02X}" for byte in text.encode())
    encoded = quote(text, safe="")
    return "".join(UNRESERVED_ESCAPES.get(char, char) for char in encoded)


def key_forms(api_key: str) -> list[str]:
    """The api key as it may appear in relayed text: exact, url-encoded and fully
    percent-encoded, each with upper and lower case hex (longest first)."""
    key = api_key.strip()
    if not key:
        return []
    forms = {key}
    encodings = (
        quote(key),
        quote(key, safe=""),
        quote_plus(key),
        percent_encode_fully(key),
        percent_encode_fully(key, alphanumerics=True),
    )
    for encoded in encodings:
        forms.add(encoded)
        forms.add(re.sub(r"%[0-9A-F]{2}", lambda match: match.group(0).lower(), encoded))
    return sorted(forms, key=len, reverse=True)


@lru_cache(maxsize=8)
def key_pattern(key: str) -> re.Pattern[str] | None:
    """A pattern for ``key`` in which every character may also be written percent-encoded, in
    any hex case and mixed with literal characters (``sf%5Ftest_key``); ``None`` for an empty
    or very long key."""
    if not key or len(key) > MAX_KEY_PATTERN_CHARS:
        return None
    parts: list[str] = []
    for char in key:
        escapes = "".join(f"%{byte:02X}" for byte in char.encode())
        spaced = "|\\+" if char == " " else ""
        parts.append(f"(?:{re.escape(char)}{spaced}|(?i:{escapes}))")
    return re.compile("".join(parts))


@lru_cache(maxsize=8)
def _forms_pattern(forms: tuple[str, ...]) -> re.Pattern[str] | None:
    """The literal ``forms`` of a key too long for :func:`key_pattern`, as one alternation."""
    if not forms:
        return None
    return re.compile("|".join(re.escape(form) for form in forms))


def mask_key(text: str, forms: list[str], api_key: str) -> str:
    """``text`` with the caller's key masked: the literal and encoded ``forms``, any mix of
    literal and percent-encoded characters (so a partly encoded or mixed-case form is caught as
    if the text were percent-decoded), and any other token that has the shape of an api key,
    also when its characters are written as percent escapes.

    The own key and the shapes are each matched at once on the text as written, through the
    ignorable characters (the own key also through whitespace controls) and on the displayed
    view, and masked at the union of the spans: a plain pass that masked only the part of a key
    before a hidden character would leave a tail no later pass could recognise."""
    for form in forms:
        text = text.replace(form, MASK)
    own = key_pattern(api_key.strip()) or _forms_pattern(tuple(forms))
    if own is not None:
        text = _masked_sub(text, own, _masked_match, ALL_SPACES)
    for shape in (KEY_SHAPE_RE, KEY_SHAPE_ENCODED_RE):
        text = _masked_sub(text, shape, _masked_match, False)
    return _mask_decoded(text, api_key)


_ESCAPE_RUN_RE = re.compile(r"(?:%[0-9A-Fa-f]{2})++")
Spans = list[tuple[int, int]]
BYTES_PER_ESCAPE = 3


def _decode_once(text: str, spans: Spans) -> tuple[str, Spans]:
    """One round of percent-decoding; ``spans`` gives, for each decoded character, the range of
    the original text it came from (a run of escapes that is not one character per byte maps
    every character to the whole run)."""
    out: list[str] = []
    out_spans: Spans = []
    pos = 0
    for run in _ESCAPE_RUN_RE.finditer(text):
        out.append(text[pos : run.start()])
        out_spans.extend(spans[pos : run.start()])
        decoded = bytes.fromhex(run.group(0).replace("%", "")).decode("utf-8", errors="replace")
        origin = spans[run.start() : run.end()]
        if len(decoded) * BYTES_PER_ESCAPE == len(origin):
            for at in range(0, len(origin), BYTES_PER_ESCAPE):
                part = origin[at : at + BYTES_PER_ESCAPE]
                out_spans.append((min(low for low, _ in part), max(high for _, high in part)))
        else:
            whole = (min(low for low, _ in origin), max(high for _, high in origin))
            out_spans.extend(whole for _ in decoded)
        out.append(decoded)
        pos = run.end()
    out.append(text[pos:])
    out_spans.extend(spans[pos:])
    return "".join(out), out_spans


def decode_mapped(text: str) -> tuple[str, Spans]:
    """``text`` percent-decoded until it is stable (at most ``MAX_DECODE_ROUNDS`` rounds), and the
    original range of each decoded character."""
    spans: Spans = [(pos, pos + 1) for pos in range(len(text))]
    for _ in range(MAX_DECODE_ROUNDS):
        if "%" not in text:
            break
        decoded, decoded_spans = _decode_once(text, spans)
        if decoded == text:
            break
        text, spans = decoded, decoded_spans
    return text, spans


@lru_cache(maxsize=8)
def _literal_pattern(key: str) -> re.Pattern[str]:
    return re.compile(re.escape(key))


def _mask_decoded(text: str, api_key: str) -> str:
    """The caller's key and any key-shaped token masked on a repeatedly percent-DECODED copy of
    the text (``sf%255F...`` is ``sf%5F...`` after one round and ``sf_...`` after two), then
    masked at the original range it came from."""
    if "%" not in text:
        return text
    decoded, spans = decode_mapped(text)
    if decoded == text:
        return text
    key = api_key.strip()
    pairs = [(KEY_SHAPE_RE, CONTROL_SPACES)]
    if key and len(key) <= MAX_KEY_PATTERN_CHARS:
        pairs.insert(0, (_literal_pattern(key), ALL_SPACES))
    ranges = sorted(
        (spans[index[hit.start()]][0], spans[index[hit.end() - 1]][1])
        for pattern, gaps in pairs
        for view, index in (_view(decoded, gaps),)
        for hit in pattern.finditer(view)
    )
    merged: list[tuple[int, int]] = []
    for low, high in ranges:
        if merged and low <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], high))
        else:
            merged.append((low, high))
    out: list[str] = []
    pos = 0
    for low, high in merged:
        out.extend((text[pos:low], MASK))
        pos = high
    out.append(text[pos:])
    return "".join(out)


def _decoded_until_stable(text: str) -> str:
    """``text`` percent-decoded (a trailing incomplete escape dropped) until it stops changing."""
    for _ in range(MAX_DECODE_ROUNDS):
        decoded = unquote(INCOMPLETE_ESCAPE_RE.sub("", text))
        if decoded == text:
            break
        text = decoded
    return text


def decoded_key_tail(text: str, key: str) -> int:
    """The length of the longest trailing piece of ``text`` that, percent-decoded (repeatedly, so
    ``%255F`` too), is the start of ``key`` (``0`` when there is none)."""
    if not key:
        return 0
    window = text[-min(len(key), MAX_KEY_TAIL_CHARS) * ENCODED_TAIL_FACTOR :]
    for offset, char in enumerate(window):
        if char != key[0] and char != "%":
            continue
        suffix = window[offset:]
        decoded = _decoded_until_stable(suffix)
        if decoded and len(decoded) < len(key) and key.startswith(decoded):
            return len(suffix)
    return 0


def drop_partial_key(text: str, forms: list[str], api_key: str = "") -> str:
    """``text`` without a trailing piece that is the start of an api key (a key cut in half by
    the raw cut would no longer be recognised and masked): the start of a literal or encoded
    form, of a partly percent-encoded key, or of any key-shaped token."""
    view, index = _view(text, ALL_SPACES)
    longest = decoded_key_tail(view, api_key.strip())
    for form in forms:
        for size in range(min(len(form) - 1, len(view), MAX_KEY_TAIL_CHARS), longest, -1):
            if view.endswith(form[:size]):
                longest = size
                break
    cut = index[len(view) - longest] if longest else len(text)
    shape_view, shape_index = _view(text, CONTROL_SPACES)
    shape = KEY_SHAPE_TAIL_RE.search(shape_view)
    if shape is not None:
        cut = min(cut, shape_index[len(shape_view) - len(shape.group(0))])
    return text[:cut]


def holds_complete_authority(token: str) -> bool:
    """True when the last url in ``token`` (``scheme://`` or ``//``) has its authority closed by
    a ``/``, ``?`` or ``#`` and nothing but a scheme precedes it in the token. Its userinfo, if
    any, is then whole, so the cut did not slice through a password."""
    last = token.rfind("//")
    if last == -1 or not any(char in token[last + 2 :] for char in URL_TERMINATORS):
        return False
    before = token[:last]
    if before.endswith(":"):
        before = before[:-1].rstrip(SCHEME_CHARS)
    return ":" not in before


def _exempt_length(token: str) -> int:
    """How much of a token with a complete authority is exempt from the cut: up to and including
    the last slash, but at least up to the character that closed the authority."""
    rest = token.rfind("//") + 2
    closers = [at for char in URL_TERMINATORS if (at := token.find(char, rest)) != -1]
    return max(token.rfind("/") + 1, min(closers))


def _scheme_start(token: str, last: int) -> int:
    """Where the url whose ``//`` is at ``last`` begins in ``token`` (its scheme, if any)."""
    if last > 0 and token[last - 1] == ":":
        return len(token[: last - 1].rstrip(SCHEME_CHARS))
    return last


def _cut_before(text: str, index: tuple[int, ...], position: int) -> str:
    """``text`` up to (not including) the character at ``position`` of its matching view."""
    return text if position >= len(index) else text[: index[position]]


# A cut token is read through a noisy introducer (one whitespace character between the two
# slashes: ``/ /``, ``/<TAB>/``; a control character is already out of the matching view) and
# through the colon forms (``%3A``, ``%3a``, fullwidth U+FF1A, Armenian full stop U+0589), so
# ``/ /user%3Apw`` cut before its ``@`` is judged like ``//user:pw``.
_CUT_TOKEN_NOISE_RE = re.compile(r"/\s/|%3[Aa]|[：։]")


def _cut_token_start(view: str) -> int:
    """Where the trailing token of ``view`` begins: after its last plain space, unless that space
    sits between two slashes (``/ /``); the token then starts at the word holding the first."""
    start = view.rfind(" ") + 1
    if start >= 2 and view[start - 2] == "/" and view.startswith("/", start):
        return view.rfind(" ", 0, start - 1) + 1
    return start


def _read_as_url(token: str) -> tuple[str, tuple[int, ...]]:
    """``token`` with each noisy introducer read as ``//`` and each colon form as ``:``, and the
    position in ``token`` of every character of the reading (plus its end)."""
    parts: list[str] = []
    at: list[int] = []
    pos = 0
    for match in _CUT_TOKEN_NOISE_RE.finditer(token):
        parts.append(token[pos : match.start()])
        at.extend(range(pos, match.start()))
        if match.group(0).startswith("/"):
            parts.append("//")
            at.extend((match.start(), match.end() - 1))
        else:
            parts.append(":")
            at.append(match.start())
        pos = match.end()
    parts.append(token[pos:])
    at.extend(range(pos, len(token) + 1))
    return "".join(parts), tuple(at)


def drop_partial_url(text: str) -> str:
    """``text`` without its trailing token (delimited by a plain space only, like the userinfo
    patterns) when that token holds a colon or a double slash: a url cut inside its userinfo has
    no ``@`` left to be recognised by, so the part of the password before the cut would otherwise
    be echoed. A token whose last url has a complete authority (a long path, for example) is
    kept.

    The token is found in the MATCHING view (invisible characters, controls and the insides of
    terminal sequences ignored), so a mark or joiner between the two slashes does not defeat the
    drop. The drop is bounded: of a token longer than ``MAX_TAIL_TOKEN_CHARS`` only the last
    ``MAX_TAIL_TOKEN_CHARS`` characters (or, when it holds a url, the url) go, so a long spaceless
    script text with a colon keeps a sanitised prefix.

    A noisy introducer (``/ /``, ``/<TAB>/``, ``scheme:/ /``) reads as ``//`` and the colon forms
    (``%3A``, ``%3a``, U+FF1A, U+0589) as ``:`` when the url in the token is judged, so a cut
    ``/ /user։pw`` is dropped like ``//user:pw``."""
    view, index = _view(text, False)
    start = _cut_token_start(view)
    token, at = _read_as_url(view[start:])
    if "//" not in token:
        start = max(start, len(view) - MAX_TAIL_TOKEN_CHARS)
        return _cut_before(text, index, start) if ":" in view[start:] else text
    if not holds_complete_authority(token):
        if len(view) - start > MAX_TAIL_TOKEN_CHARS:
            start += at[_scheme_start(token, token.rfind("//"))]
        return _cut_before(text, index, start)
    # The exemption reaches only up to the last slash: a credential pair in the last path
    # segment (cut before its ``@``, or whole) is dropped.
    keep = _exempt_length(token)
    return _cut_before(text, index, start + at[keep]) if ":" in token[keep:] else text


def strip_terminal(text: str, trim_tail: Callable[[str], str]) -> str:
    """``text`` without terminal sequences and hidden controls. A string sequence (OSC, DCS, SOS,
    PM, APC) that never ends swallows what follows it, so the text before it is treated like a
    cut one: ``trim_tail`` drops a trailing partial key or url from it."""
    out: list[str] = []
    pos = 0
    for match in TERMINAL_SEQUENCE_RE.finditer(text):
        out.append(text[pos : match.start()])
        pos = match.end()
        sequence = match.group(0)
        if STRING_INTRODUCER_RE.match(sequence) and not STRING_TERMINATOR_RE.search(sequence):
            out = [trim_tail("".join(out))]
    out.append(text[pos:])
    return HIDDEN_CONTROLS_RE.sub("", "".join(out))


def sanitise_text(
    text: str, *, base_url: str = "", api_key: str = "", limit: int = MAX_RELAYED_CHARS
) -> str:
    """``text`` from the server (or the network) as it may be echoed, in text and json alike.

    The raw text is first cut to ``MAX_RAW_CHARS`` characters (before any pattern runs, so the
    time is bounded). Keys, then userinfo, query and fragment are masked on the raw text (a
    whitespace character inside a password or a value does not end it; an escape that will eat a
    marker or a key character cannot hide it; the key goes first so that a question mark or hash
    a hostile sequence puts inside the key cannot split it), the invisible format characters and
    fillers are removed (combining marks, joiners, variation selectors, the signs that draw
    something and well-formed emoji tag sequences are kept: they are part of real text, and
    secrets hidden with them are still found through the matching view), terminal escape and
    control sequences are stripped (a string sequence that never ends counts as a cut), keys,
    userinfo, query and fragment are masked again BEFORE whitespace is flattened, and after a cut
    a trailing partial api key and a trailing token holding a colon or a double slash (a url cut
    inside its userinfo) are dropped, on the matching view and bounded to
    ``MAX_TAIL_TOKEN_CHARS``, so characters interleaved to hide them do not help and a long
    spaceless text keeps a prefix. Whitespace runs become one space, the
    caller's own ``api_key`` (exact, url-encoded, partly, fully or repeatedly percent-encoded)
    and any key-shaped token are masked, userinfo (also without a scheme), query values (after a
    url-ish context) and fragments are masked (and the ``base_url`` as typed), and the result is
    cut to ``limit`` characters with an ellipsis.
    """
    forms = key_forms(api_key)
    raw = text[:MAX_RAW_CHARS]
    cut = len(raw) < len(text)

    def trim_tail(shown: str) -> str:
        return drop_partial_url(drop_partial_key(shown, forms, api_key))

    # Secrets are masked and the cut tail examined BEFORE the terminal strip as well as after it:
    # an escape byte in front of a marker (``?``, ``#``, the colon of ``://``) or a key character
    # would make the strip consume it. The key mask comes FIRST: a question mark or hash that a
    # hostile sequence puts inside the caller's key would otherwise make the query or fragment
    # mask swallow the word from that marker, and the key mask would never see a whole key.
    plain = _credentials_masked(mask_key(raw, forms, api_key))
    plain = strip_invisible(plain)
    if cut:
        plain = trim_tail(plain)
    plain = strip_terminal(plain, trim_tail)
    # Keys, userinfo, query and fragment once more between the strip and the flattening: a
    # sequence inside a key or a userinfo no longer splits it, and a whitespace character inside
    # a password or a value is not yet a space.
    plain = _credentials_masked(mask_key(plain, forms, api_key))
    if cut:
        plain = trim_tail(plain)
    plain = mask_key(flatten_text(plain), forms, api_key)
    # Combining marks and joiners stay in the shown text; the masks below see through them.
    # Already bounded by the raw cut; the public wrapper's own cut must not shorten it again.
    plain = _until_stable(_userinfo_once, plain)
    plain = redact_reason(plain, base_url) if base_url else redact_url(plain)
    if not plain or (len(plain) <= limit and not cut):
        return plain
    return plain[: limit - len(ELLIPSIS)].rstrip() + ELLIPSIS


def echo_url(url: str, api_key: str = "") -> str:
    """``url`` as a message may echo it: sanitised and cut to ``MAX_ECHOED_URL_CHARS``.

    A url longer than the raw bound whose authority is cut off (a very long host) would be
    dropped whole; it is shown as just the ellipsis then, never as an empty echo.
    """
    shown = sanitise_text(url, api_key=api_key, limit=MAX_ECHOED_URL_CHARS)
    if not shown and len(url) > MAX_RAW_CHARS:
        return ELLIPSIS
    return shown


def redact_reason(reason: str, base_url: str) -> str:
    """``reason`` with the base url (as typed and as requested) replaced by its redacted form."""
    shown = redact_url(base_url)
    text = reason.replace(base_url, shown)
    try:
        text = text.replace(endpoint_url(base_url, ""), shown)
    except ValueError:
        pass
    return redact_url(text)


@lru_cache(maxsize=4)
def cached_file_key(raw_path: str) -> str:
    """The key in the file at ``raw_path`` (``""`` when it cannot be read), read once per path
    for the life of the process. Key-file problems are reported by the settings, not here."""
    # Imported here: config imports this module at its top level.
    from sandfort_cli import config

    try:
        return config.read_key_file(raw_path)
    except BadParameter:
        return ""


def caller_key() -> str:
    """The api key the CLI would send now, resolved like the settings do:
    ``SANDFORT_API_KEY``, else the file named by ``SANDFORT_API_KEY_FILE``, else the stored
    profile's.

    It is looked up when a message is about to be printed, so a key that was typed by mistake
    (as an argument, a label, an expiry) is masked even on a command that never opened a client.
    A missing or unreadable key file or profile gives ``""`` for that source (the file is read
    at most once per process; its errors are reported elsewhere).
    """
    # Imported here: config and output import this module at their top level.
    from sandfort_cli import config
    from sandfort_cli.output import CliError

    from_env = os.environ.get(config.API_KEY_ENV)
    if from_env:
        return from_env
    file_path = os.environ.get(config.API_KEY_FILE_ENV)
    from_file = cached_file_key(file_path) if file_path else ""
    if from_file:
        return from_file
    try:
        return config.load_profile().get("api_key", "")
    except CliError:
        return ""


def clean_value(value: Any, api_key: str) -> Any:
    """One scalar server value sanitised for printing: numbers, booleans and ``None`` are kept,
    a string goes through :func:`sanitise_text` and anything else is shown as its sanitised
    ``str``.

    Collections are walked by ``sandfort_cli.output.relay_value`` (entry cap, depth, colliding
    keys); it hands each leaf to this function.
    """
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return sanitise_text(value, api_key=api_key)
    return sanitise_text(str(value), api_key=api_key)


_LOCAL_CONTROLS_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\ud800-\udfff]")


def scrub_local(text: str, api_key: str, limit: int = MAX_LOCAL_CHARS) -> str:
    """Text the CLI wrote itself, made safe to print without being reshaped.

    Terminal sequences, control characters (a newline and a tab are kept) and invisible format
    characters are removed and the api key (and any key-shaped token) is masked; the text is
    otherwise as written, only cut to ``limit`` characters with an ellipsis.
    """
    forms = key_forms(api_key)
    plain = mask_key(text[: limit * 2], forms, api_key)
    plain = TERMINAL_SEQUENCE_RE.sub("", strip_invisible(plain))
    plain = _LOCAL_CONTROLS_RE.sub("", plain)
    plain = mask_key(plain, forms, api_key)
    if len(plain) <= limit and len(text) <= limit * 2:
        return plain
    return plain[: limit - len(ELLIPSIS)].rstrip() + ELLIPSIS
