"""Host-run and IDNA helpers of the sanitiser (:mod:`sandfort_cli.sanitise`).

This module decides whether the part of a word before a ``?`` or ``#`` gives a url-ish context: a
path, a dotted host name (internationalised labels too), a host with a port, a bracketed address,
or (for a query) an ASCII token followed by ``key=``. It imports nothing from the other sanitiser
modules; :mod:`sandfort_cli.sanitise_stages` uses it and :mod:`sandfort_cli.sanitise` re-exports
its public names.

The lookback is bounded: only the last ``MAX_HOST_CHARS`` characters before the marker are
translated and tested, so a long single word costs time linear in its length, not quadratic. The
``/`` test and the ASCII test use positions found once per word (:func:`scan_word`), so many
markers in one word do not rescan the head.
"""

import bisect
import re
import unicodedata
from functools import lru_cache
from typing import NamedTuple

# A query or fragment counts only after a url-ish context: a scheme or ``//``, a path, a dotted
# host name (internationalised labels too), a host with a port or a bracketed address, or (for a
# query) an ASCII token followed by ``key=``. A question mark or hash glued to ordinary prose
# (CJK, Thai, a plain word) is not a marker. The context is tested on the matching view, so a
# joiner or combining mark before the marker does not hide it.
URLISH_HOST_RE = re.compile(
    r"(?:[\w-]++\.)++[\w-]++(?::\d{0,5})?|[\w.-]*+:\d{1,5}|\[[^\]]*+\](?::\d{0,5})?|localhost",
    re.IGNORECASE,
)
QUERY_SHAPED_RE = re.compile(r"[A-Za-z0-9_.%\[\]-]++=")
# A bracketed IPv6 literal (hex digits, colons, an embedded IPv4 tail, an optional ``%zone``) with
# an optional ``:port``. It is a host whatever precedes it (``key=[::1]:8080#x``, ``，[::1]#x``):
# the colons inside the brackets would otherwise be read as separators. The lookahead asks for two
# colons, so a slice such as ``a[1:2]`` is not a host; :func:`_is_ipv6_literal` then refuses a
# subscript such as ``a[1:2:3]``. Every quantifier is possessive.
IPV6_HOST_RE = re.compile(
    r"\[(?=[0-9a-f.]*+:[0-9a-f.]*+:)(?P<literal>[0-9a-f:.]++)(?:%[^\]\[\s]++)?\](?::\d{0,5})?",
    re.IGNORECASE,
)
# A group of an address without ``::`` that no subscript has: longer than two characters.
MAX_SUBSCRIPT_GROUP_CHARS = 2
HEX_LETTERS = frozenset("abcdef")
# The host part before a ``?``: a run of letters of any script, digits, ``-``, ``_``, ``.`` and
# combining marks (categories Mn and Mc: NFD ``café?token=...``, Devanagari), so a non-ASCII word
# is treated like the ASCII ``what?x=1``. See :func:`_is_host_run`.
HOST_RUN_EXTRA_CHARS = "_.-"
# The IDNA dot variants (ideographic full stop, fullwidth full stop, halfwidth ideographic full
# stop, one dot leader, two dot leader) read as ``.`` in a host (``host。example?token=...``).
IDNA_DOTS = "。．｡․‥"
# A regex substitution, not ``str.translate``: on a non-ASCII window translate leaves its fast
# path and costs microseconds per marker, while a substitution with no match is a single scan.
_IDNA_DOT_RE = re.compile(f"[{IDNA_DOTS}]")
# A character that is neither ASCII nor an IDNA dot: a head before the first one reads as ASCII
# once its IDNA dots are translated (``ref=foo。?token=...``).
_WIDE_CHAR_RE = re.compile(f"[^\\x00-\\x7f{IDNA_DOTS}]")
# A host run may also hold non-ASCII punctuation and symbols (en dash, middle dot, katakana middle
# dot, emoji: categories P* and S*) as long as it holds a letter, except the brackets and quotes
# (Ps, Pe, Pi, Pf) and these sentence breaks, which are prose: the ideographic comma, the
# fullwidth comma, exclamation, question mark, semicolon and colon, the ellipsis, the inverted
# Spanish marks, the Arabic comma and question mark and the danda signs.
HOST_RUN_PUNCTUATION = frozenset({"Pc", "Pd", "Po"})
PROSE_BREAKS = "、，！？；：…¡¿،؟।॥､‼⁇⁈⁉︒﹒︙۔؛"
# Punctuation that may open a word before a host (``(host.test#x)``, ``"host.test?k=v"``).
HOST_OPENERS = "(<{\"'"
# Separators that may sit glued to a host in prose or in a log line: assignment and label
# colons, list commas, brackets, pipes, ``@``, ``~``, ``*``, a backtick and the arrow forms
# (``->``, ``=>`` end in ``>``), plus the CJK and fullwidth colon, brackets and quotes, and the
# twins of ``=``, ``|``, ``->`` and ``=>``: fullwidth equals, fullwidth vertical line, rightwards
# arrow and rightwards double arrow. The host is the run after the LAST opener or separator. A
# sentence break inside a host stays prose.
HOST_SEPARATORS = "=:,;[|@~*`>：︓﹕「」（）【】“”«»‘’＝｜→⇒"
# CJK and fullwidth sentence punctuation (ideographic comma and full stop, fullwidth comma,
# semicolon, exclamation and question marks, the ellipses, the vertical and small variants). It
# separates a dotted host or a host with a port from the prose before it (``失败，host.test#x``),
# but it is NOT in ``HOST_SEPARATORS``: a bare word after it (``你好，再见?x=1``) stays prose.
SENTENCE_SEPARATORS = "、。，；！？…⋯︐︑︔︕︖﹐﹑﹔﹖﹗"
# Script-independent host separators: every non-ASCII character of the punctuation categories
# (Po, Pd, Ps, Pe, Pi, Pf) and of the space separators (Zs) separates a dotted host or a host with
# a port from the text before it (Arabic comma and semicolon, danda, wave dash, katakana middle
# dot, ideographic space), and so does the fullwidth tilde (category Sm, the twin of ``~``). The
# IDNA dots are not separators: they read as ``.`` inside a host. ASCII is not in this rule, so
# the dot and hyphen of a host and every ASCII separator keep their meaning.
SEPARATOR_CATEGORIES = frozenset({"Po", "Pd", "Ps", "Pe", "Pi", "Pf", "Pc", "Zs"})
# The fullwidth tilde, the fullwidth and small less-than and greater-than signs (category Sm: the
# twins of ``<`` and ``>``), which open or end a host in a log line like their ASCII forms. The
# connector punctuation (Pc: the wavy low line and its kin) is in ``SEPARATOR_CATEGORIES``.
EXTRA_SEPARATORS = "～＜＞﹤﹥"
# ASCII symbols that are neither host characters nor in ``HOST_SEPARATORS``: after a CJK word
# (``你好!host.test?token=...``) each one still separates a dotted host from the text before it.
ASCII_BREAKS = "!$%&)+\\]^}"
# A masked query or fragment ends before the first non-ASCII character of these categories: a
# sentence break (Po) or a closing quote or bracket (Pe, Pf). An ASCII quote ends it as well. The
# apostrophe between two alphanumerics belongs to the word. A space separator (Zs) does NOT end
# it: the flattening turns a Unicode space into a plain one later, so a hostile server could split
# a secret with one and show its second half (``tests/test_cli_r54b.py``).
#
# Reconciliation of the two rules (tests/test_cli_sanitise_r56b.py and
# tests/test_cli_sanitise_r60.py). r60: a masked run ends at sentence-ending punctuation and
# closers only, never at bare whitespace, so a value cannot be split by a space. r56b: text after
# whitespace that continues a secret-looking fragment is still masked, and plain words after it
# stay visible. Both hold because a numeric anchor (``#12``) is exempt only up to its own end:
# the scan resumes there (``_fragment_edits``), so a later ``#secret`` after whitespace is
# judged on its own instead of being skipped with the rest of the run.
RUN_END_CATEGORIES = frozenset({"Po", "Pe", "Pf"})
APOSTROPHES = "'’"
# A port is at most five digits; a longer run of digits after a colon is not a port.
MAX_PORT_DIGITS = 5
_OPENER_RE = re.compile("[" + "".join(re.escape(char) for char in HOST_OPENERS) + "]")
_BOUNDARY_RE = re.compile(
    "[" + "".join(re.escape(char) for char in HOST_OPENERS + HOST_SEPARATORS) + "]"
)
_BREAK_RE = re.compile(
    "["
    + "".join(
        re.escape(char)
        for char in HOST_OPENERS + HOST_SEPARATORS + SENTENCE_SEPARATORS + ASCII_BREAKS
    )
    + "]"
)
_NON_ASCII_RE = re.compile(r"[^\x00-\x7f]")
# A character that may end a masked run: any non-ASCII one (judged by category) or an ASCII quote.
_RUN_END_CANDIDATE_RE = re.compile("[\"'\u0080-\U0010ffff]")
# A hostname is at most 253 characters (RFC 1035); a longer host is not a usable url.
MAX_HOST_CHARS = 253
CHAR_CACHE_SIZE = 4096


@lru_cache(maxsize=CHAR_CACHE_SIZE)
def _is_separator(char: str) -> bool:
    """A non-ASCII host separator: the fullwidth tilde or a character of ``SEPARATOR_CATEGORIES``
    that is not an IDNA dot."""
    if char in EXTRA_SEPARATORS:
        return True
    return char not in IDNA_DOTS and unicodedata.category(char) in SEPARATOR_CATEGORIES


@lru_cache(maxsize=CHAR_CACHE_SIZE)
def _ends_run(char: str) -> bool:
    """A character before which a masked query or fragment stops (see ``RUN_END_CATEGORIES``)."""
    return char in "\"'" or unicodedata.category(char) in RUN_END_CATEGORIES


def _is_word_apostrophe(word: str, pos: int) -> bool:
    """True for an apostrophe between two alphanumerics."""
    return (
        word[pos] in APOSTROPHES
        and 0 < pos < len(word) - 1
        and word[pos - 1].isalnum()
        and word[pos + 1].isalnum()
    )


def run_end(word: str, start: int) -> int:
    """The end of the masked run that begins at ``start``: the first non-ASCII punctuation (Po),
    closing bracket or quote (Pe, Pf) or ASCII quote at or after ``start``
    that is not an apostrophe inside a word, else the end of the word. One forward pass that stops
    at the first match."""
    for match in _RUN_END_CANDIDATE_RE.finditer(word, start):
        pos = match.start()
        if _ends_run(match.group()) and not _is_word_apostrophe(word, pos):
            return pos
    return len(word)


class RunEnds:
    """:func:`run_end` for the marks of one word, asked in increasing order. A result is reused
    for every later start up to it (no terminator lies between), so a word costs linear time
    however many marks it has."""

    def __init__(self, word: str) -> None:
        self._word = word
        self._start = 0
        self._stop = -1

    def end(self, start: int, limit: int) -> int:
        """The end of the run beginning at ``start``, not past ``limit``."""
        if not self._start <= start <= self._stop:
            self._start, self._stop = start, run_end(self._word, start)
        return min(self._stop, limit)


def _is_word_char(char: str) -> bool:
    return (
        char.isalnum() or char in HOST_RUN_EXTRA_CHARS or unicodedata.category(char).startswith("M")
    )


def _is_host_symbol(char: str) -> bool:
    """A non-ASCII punctuation or symbol character that may sit inside a host run."""
    if char.isascii() or char in PROSE_BREAKS:
        return False
    category = unicodedata.category(char)
    return category in HOST_RUN_PUNCTUATION or category.startswith("S")


def _is_host_run(host: str) -> bool:
    """True for a non-empty run of alphanumerics of any script, ``_``, ``.``, ``-`` and combining
    marks (Unicode categories starting with ``M``: Mn, Mc, Me); also, when it holds a letter, one
    with non-ASCII punctuation or symbols between the characters (see ``PROSE_BREAKS``)."""
    if not host:
        return False
    if all(_is_word_char(char) for char in host):
        return True
    return any(char.isalpha() for char in host) and all(
        _is_word_char(char) or _is_host_symbol(char) for char in host
    )


class WordScan(NamedTuple):
    """Positions found once per word: the first ``/`` (-1 when none) and the first character
    that is neither ASCII nor an IDNA dot (the word length when none)."""

    first_slash: int
    first_wide: int


def scan_word(word: str) -> WordScan:
    """The :class:`WordScan` of ``word``: one ``find`` and one regex search."""
    wide = _WIDE_CHAR_RE.search(word)
    return WordScan(word.find("/"), len(word) if wide is None else wide.start())


class Boundaries(NamedTuple):
    """Positions found once per word, in increasing order: the openers, every opener or
    separator (see ``HOST_SEPARATORS``), and every opener, separator or sentence punctuation
    mark (``SENTENCE_SEPARATORS``) or non-ASCII separator (``SEPARATOR_CATEGORIES``); used only
    to find a dotted host or a host with a port."""

    openers: list[int]
    boundaries: list[int]
    breaks: list[int]
    hard_breaks: list[int]


def scan_boundaries(word: str) -> Boundaries:
    """The :class:`Boundaries` of ``word``: one forward pass per list, so each marker finds the
    last one before it with a bisect, whatever the number of markers."""
    breaks = [match.start() for match in _BREAK_RE.finditer(word)]
    if not word.isascii():
        wide = [m.start() for m in _NON_ASCII_RE.finditer(word) if _is_separator(m.group())]
        breaks = sorted(breaks + wide)
    return Boundaries(
        [match.start() for match in _OPENER_RE.finditer(word)],
        [match.start() for match in _BOUNDARY_RE.finditer(word)],
        breaks,
        [pos for pos in breaks if word[pos] not in IDNA_DOTS],
    )


def _start_after(positions: list[int], head_end: int, floor: int) -> int:
    """The start of the host: after the last position before ``head_end``, not before ``floor``."""
    at = bisect.bisect_left(positions, head_end) - 1
    return max(floor, positions[at] + 1) if at >= 0 else floor


def _port_host_start(word: str, breaks: list[int], start: int, head_end: int, floor: int) -> int:
    """The start of ``host:port`` when the run ``word[start:head_end]`` is a port (one to five
    ASCII digits after a colon): the colon of the port is not the separator, so the host starts
    after the break before it. ``-1`` when the run is not a port."""
    colon = start - 1
    if colon < 0 or word[colon] != ":" or not 0 < head_end - start <= MAX_PORT_DIGITS:
        return -1
    port = word[start:head_end]
    return _start_after(breaks, colon, floor) if port.isascii() and port.isdigit() else -1


def _url_only_hosts(
    word: str, bounds: Boundaries, head_end: int, floor: int, known: list[str]
) -> list[str]:
    """Hosts that only count as a url context (never as a loose host run): the run after the
    last sentence punctuation mark, ``host:port`` with the port colon stepped over, and the run
    after the last break that is not an IDNA dot (the ideographic full stop is both a sentence
    break and a dot: ``失败，host。test#x`` has the host ``host.test``)."""
    start = _start_after(bounds.breaks, head_end, floor)
    hard_start = _start_after(bounds.hard_breaks, head_end, floor)
    starts = [start, _port_host_start(word, bounds.breaks, start, head_end, floor), hard_start]
    hosts = (_IDNA_DOT_RE.sub(".", word[at:head_end]) for at in starts if at >= 0)
    return [host for host in dict.fromkeys(hosts) if host not in known]


def _is_ipv6_literal(literal: str) -> bool:
    """True for the hex-digit, colon and dot run of a bracketed address: it holds ``::``, or one
    of its colon-separated groups has a hex letter or is longer than two characters (an embedded
    IPv4 tail counts). A subscript such as ``1:2:3`` has neither, so it stays visible."""
    if "::" in literal:
        return True
    return any(
        len(group) > MAX_SUBSCRIPT_GROUP_CHARS or not HEX_LETTERS.isdisjoint(group.lower())
        for group in literal.split(":")
    )


def _ends_with_ipv6_host(word: str, head_end: int, floor: int) -> bool:
    """True when ``word[:head_end]`` ends with a bracketed IPv6 host and an optional port (see
    ``IPV6_HOST_RE`` and :func:`_is_ipv6_literal`); the marker that follows is the query or
    fragment the caller is judging. Only the window from ``floor`` is searched: one bounded
    ``rfind`` for the last ``[`` and one anchored match, with no slice."""
    start = word.rfind("[", floor, head_end)
    if start == -1:
        return False
    match = IPV6_HOST_RE.fullmatch(word, start, head_end)
    return match is not None and _is_ipv6_literal(match["literal"])


def _urlish_before(
    word: str,
    scan: WordScan,
    bounds: Boundaries,
    head_end: int,
    query_start: int,
    query_end: int,
) -> bool:
    """True when the head ``word[:head_end]`` (the part of a word before a ``?`` or ``#``) gives a
    url-ish context; ``word[query_start:query_end]`` is the query that follows a fragment's head
    (empty when there is none). ``scan`` is :func:`scan_word` and ``bounds`` is
    :func:`scan_boundaries` of ``word``. The IDNA dot variants count as ``.``, so a head of ASCII
    and IDNA dots counts as ASCII. The host is judged twice: as the run after the last opener
    (``host.test:8080`` keeps its port) and as the run after the last separator
    (``ref=bücher.example``); a url context is also found after sentence punctuation
    (``失败，host.test``) and with the port colon stepped over (``ref=host:443``). Only the
    last ``MAX_HOST_CHARS`` characters of the head are translated; no other slice of it is made,
    and each marker costs constant work."""
    if 0 <= scan.first_slash < head_end:
        return True
    floor = max(0, head_end - MAX_HOST_CHARS)
    if _ends_with_ipv6_host(word, head_end, floor):
        return True
    open_start = _start_after(bounds.openers, head_end, floor)
    sep_start = _start_after(bounds.boundaries, head_end, floor)
    hosts = [_IDNA_DOT_RE.sub(".", word[open_start:head_end])]
    if sep_start != open_start:
        hosts.append(_IDNA_DOT_RE.sub(".", word[sep_start:head_end]))
    url_hosts = hosts + _url_only_hosts(word, bounds, head_end, floor, hosts)
    # A leading dot (``，｡host.test``: an IDNA dot glued to the break before the host) is dropped.
    if any(URLISH_HOST_RE.fullmatch(host.lstrip(".")) is not None for host in url_hosts):
        return True
    if QUERY_SHAPED_RE.match(word, query_start, query_end) is None:
        return False
    return scan.first_wide >= head_end or any(_is_host_run(host) for host in hosts)
