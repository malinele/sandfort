"""The mask-stage machinery of the sanitiser (:mod:`sandfort_cli.sanitise`).

This is the lower layer: the terminal-sequence and invisible-character tables, the matching and
displayed views of a text, the edit machinery that applies a pattern to every view and edits the
original once at the union of the matched spans, and the query and fragment stages built on it.
It imports nothing from :mod:`sandfort_cli.sanitise`, which re-exports its public names so every
existing import path keeps working. The host-run and IDNA helpers that decide whether a ``?`` or
``#`` has a url-ish context live in :mod:`sandfort_cli.sanitise_hosts`.

In a host run the CJK full stop (U+3002) reads as a dot, and the em dash (U+2014) and the other
non-ASCII punctuation and symbols count as host characters when the run holds a letter, so
``你好。再见?q=1`` masks the query value, while prose breaks (the ideographic comma and the like)
still do not make a host.
"""

import bisect
import re
import unicodedata
from collections import deque
from collections.abc import Callable
from functools import lru_cache

from sandfort_cli.sanitise_hosts import RunEnds, _urlish_before, scan_boundaries, scan_word

MASK = "***"
SPACE = " "
# How far the matching views look through whitespace (the ``spaces`` argument; ``False`` is 0
# and ``True`` is ``CONTROL_SPACES``): a key-shaped token is matched with the whitespace controls
# skipped, the caller's own key with every whitespace character skipped, so a space of any kind
# inside the key does not hide it.
NO_SPACES = 0
CONTROL_SPACES = 1
ALL_SPACES = 2
# Terminal sequences: OSC (ends in BEL or ST: ESC \ or the C1 byte), CSI (ESC [ or the C1 byte),
# DCS/SOS/PM/APC strings and any other short ESC sequence.
TERMINAL_SEQUENCE_RE = re.compile(
    r"(?:\x1b\]|\x9d)[^\x07\x1b\x9c]*(?:\x07|\x1b\\|\x9c)?"
    r"|(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]?"
    r"|(?:\x1b[PX^_]|[\x90\x98\x9e\x9f])[^\x1b\x9c]*(?:\x1b\\|\x9c)?"
    r"|\x1b[ -/]*[0-~]?"
)
# A string sequence opens with one of these and is closed by BEL, ESC \ or the C1 string
# terminator; one without a terminator swallows everything up to the next ESC or the end.
STRING_INTRODUCER_RE = re.compile(r"\x1b[\]PX^_]|[\x90\x98\x9d\x9e\x9f]")
STRING_TERMINATOR_RE = re.compile(r"(?:\x07|\x1b\\|\x9c)\Z")
# TWO views of "invisible", on purpose.
#
# Matching view (:func:`is_invisible`, used to look through a hidden secret): the Unicode
# Default_Ignorable_Code_Point property (assigned and unassigned: the gaps around U+FFF0, U+2065
# and plane 14 included), the categories format (Cf), nonspacing mark (Mn) and enclosing mark
# (Me), plus every code point in the lists below. A key or a url userinfo interleaved with
# combining marks, joiners or variation selectors is still found.
#
# Display view (:func:`is_hidden_in_display`, used to strip the text that is printed): only the
# genuinely invisible format characters and the explicit filler list. The mark categories are NOT
# stripped from displayed text: they carry the meaning of Thai, Devanagari, Hebrew niqqud, Arabic
# harakat, decomposed accents and emoji sequences. The zero width joiner and non-joiner (U+200D,
# U+200C) and the variation selectors are format or mark characters that real text needs, so
# they are in the matching view only. Format characters that draw something (the Arabic prefixed
# signs and end-of-ayah, the Syriac abbreviation mark, the Kaithi number signs, the Egyptian
# hieroglyph layout controls) stay in display as well.
INVISIBLE_CATEGORIES = frozenset({"Cf", "Mn", "Me"})
DISPLAY_STRIPPED_CATEGORIES = frozenset({"Cf"})
# Default_Ignorable_Code_Point (DerivedCoreProperties.txt, Unicode 16).
_DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
    (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)  # fmt: skip
# Hidden fillers that are stripped from displayed text: soft hyphen, combining grapheme joiner,
# Arabic letter mark, Hangul fillers, Khmer inherent vowels, the Mongolian vowel separator, zero
# width space and the directional marks, bidi embeddings and overrides, the word joiner block
# (invisible operators, isolates, deprecated format controls and the unassigned code point
# among them), the braille blank, the BOM, interlinear annotation marks, the object
# replacement character (U+FFFC, a placeholder that shows nothing), the unassigned specials
# block and the Unicode tag characters (valid flag sequences are kept, see below).
_DISPLAY_FILLER_RANGES = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
    (0x17B4, 0x17B5), (0x180E, 0x180E), (0x200B, 0x200B), (0x200E, 0x200F),
    (0x202A, 0x202E), (0x2060, 0x206F), (0x2800, 0x2800), (0x3164, 0x3164),
    (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFFC), (0xE0000, 0xE00FF), (0xE01F0, 0xE0FFF),
)  # fmt: skip
# Characters that stay in displayed text but are looked through when matching a secret: the
# zero width non-joiner and joiner, the Mongolian free variation selectors, the variation
# selectors and their supplement (emoji and ideographic variation sequences).
_MATCH_ONLY_RANGES = (
    (0x180B, 0x180D), (0x180F, 0x180F), (0x200C, 0x200D), (0xFE00, 0xFE0F), (0xE0100, 0xE01EF),
)  # fmt: skip
# Format characters (category Cf) that draw something and therefore stay in displayed text:
# Arabic number sign to sanah (U+0600-U+0605), the Arabic pound and piastre marks above
# (U+0890-U+0891), the Syriac abbreviation mark, the Arabic end of ayah (U+06DD, U+08E2), the
# Kaithi number signs and the Egyptian hieroglyph format controls. Still looked through when
# matching a secret (they are format characters).
_DISPLAY_KEPT_FORMAT_RANGES = (
    (0x0600, 0x0605), (0x06DD, 0x06DD), (0x070F, 0x070F), (0x0890, 0x0891), (0x08E2, 0x08E2),
    (0x110BD, 0x110BD), (0x110CD, 0x110CD), (0x13430, 0x1345F),
)  # fmt: skip
# An emoji tag sequence: the waving black flag, two to eight tag letters or digits (a
# subdivision flag such as ``gbsct``) and the cancel tag. Only this exact shape keeps its tag
# characters in displayed text; any other tag character is removed.
TAG_FLAG_SEQUENCE_RE = re.compile(
    "\U0001f3f4[\U000e0030-\U000e0039\U000e0061-\U000e007a]{2,8}\U000e007f"
)


def _expand(ranges: tuple[tuple[int, int], ...]) -> frozenset[int]:
    return frozenset(code for low, high in ranges for code in range(low, high + 1))


DEFAULT_IGNORABLE = _expand(_DEFAULT_IGNORABLE_RANGES)
DISPLAY_FILLERS = _expand(_DISPLAY_FILLER_RANGES)
MATCH_ONLY_INVISIBLE = _expand(_MATCH_ONLY_RANGES)
DISPLAY_KEPT_FORMAT = _expand(_DISPLAY_KEPT_FORMAT_RANGES)
EXTRA_INVISIBLE = DISPLAY_FILLERS | MATCH_ONLY_INVISIBLE | DEFAULT_IGNORABLE
SURROGATE_CATEGORY = "Cs"
# A fragment of only ASCII digits is an anchor or an issue number (``refs/heads/feature#12``),
# never masked: up to this many digits when no scheme precedes the anchor in its token.
MAX_NUMERIC_FRAGMENT_CHARS = 6
# With a scheme (``://``) in front, a long all-digit fragment has the shape of a one-time code
# (``https://host/verify#123456``) and is masked; only a short one (``https://host/docs#7``) stays.
MAX_SCHEME_NUMERIC_FRAGMENT_CHARS = 3
# Closers a fragment may sit in front of: ``)``, ``]``, ``}``, ``>``, ``|``, an ellipsis, curly
# closing quotes and CJK closing brackets and sentence punctuation. They are kept, never eaten.
CLOSING_PUNCTUATION = (
    ")]}>|\u2026\u201d\u2019\u3001\u3002\uff0c\uff01\uff1f\u300d\u300f\u3011\u3009\u300b\uff09"
)
# Punctuation that may trail a fragment in prose (``a/b#12,``, ``"a/b#12"``, ``(a/b#12)``,
# ``[a/b#12]``); it is stripped before the numeric test.
TRAILING_FRAGMENT_PUNCTUATION = ".,;:!?'\"" + CLOSING_PUNCTUATION
SCHEME_MARKER = "://"
# A word for the query and fragment masks. Before the flattening (``across_breaks``) only the
# plain space ends it, like the userinfo masks: a tab, line break or Unicode space inside a value
# would become a space later and split the value.
WORD_RE = re.compile(r"\S+")
WORD_ACROSS_BREAKS_RE = re.compile(r"[^ ]+")
# A ``)`` that closes a word (typer writes "unexpected extra argument (<value>)") is not part of
# a fragment, so it survives the fragment mask.
CLOSING_PARENTHESIS = ")"


def is_invisible(char: str) -> bool:
    """The MATCHING view: true for a character to look through when searching for a secret
    (Default_Ignorable_Code_Point, the format and mark categories, every listed filler and
    selector)."""
    return ord(char) in EXTRA_INVISIBLE or unicodedata.category(char) in INVISIBLE_CATEGORIES


def is_hidden_in_display(char: str) -> bool:
    """The DISPLAY view: true for a character removed from printed text (the genuinely
    invisible format characters except the joiners, plus the explicit filler list). Combining
    marks and the format characters that draw something (Arabic signs, Kaithi marks) are kept."""
    code = ord(char)
    if code in DISPLAY_FILLERS:
        return True
    if code in MATCH_ONLY_INVISIBLE or code in DISPLAY_KEPT_FORMAT:
        return False
    return unicodedata.category(char) in DISPLAY_STRIPPED_CATEGORIES


def _is_plain(text: str) -> bool:
    """Printable ASCII only: nothing invisible, nothing a terminal could act on."""
    return text.isascii() and text.isprintable()


def _strip_hidden(text: str) -> str:
    return "".join(char for char in text if not is_hidden_in_display(char))


def strip_invisible(text: str) -> str:
    """``text`` without the characters hidden in display (see :func:`is_hidden_in_display`);
    combining marks, joiners, variation selectors and the signs that draw something stay, and so
    does a well-formed emoji tag sequence (a subdivision flag)."""
    if _is_plain(text):
        return text
    out: list[str] = []
    pos = 0
    for flag in TAG_FLAG_SEQUENCE_RE.finditer(text):
        out.extend((_strip_hidden(text[pos : flag.start()]), flag.group(0)))
        pos = flag.end()
    out.append(_strip_hidden(text[pos:]))
    return "".join(out)


def _is_ignorable(char: str, spaces: int) -> bool:
    """A character to look through when matching a secret: invisible ones and control ones
    (ESC among them); the whitespace controls only with ``spaces`` (``True`` or
    ``CONTROL_SPACES``), and whitespace of any kind (the plain space, the Unicode space
    separators Zs, U+2028 and U+2029) only with ``ALL_SPACES`` (the exact api key)."""
    if is_invisible(char) or (spaces >= ALL_SPACES and char.isspace()):
        return True
    category = unicodedata.category(char)
    if category == SURROGATE_CATEGORY:
        return True
    return category == "Cc" and (spaces > NO_SPACES or not char.isspace())


# Inside a terminal sequence a plain space (any whitespace, in fact) is part of the sequence for
# matching purposes: the strip removes the sequence as a whole, so a space in it must not end a
# userinfo or a token. So are the bracket after ESC in an OSC or CSI introducer and the
# backslash of ESC \. The letters of the other introducers (P, X, ^, _) can be key characters
# and are not skipped.
SEQUENCE_OPENERS = "]["


def _sequence_skipped(text: str) -> frozenset[int]:
    """Positions inside terminal sequences that are looked through when matching a secret."""
    skipped: set[int] = set()
    for match in TERMINAL_SEQUENCE_RE.finditer(text):
        start, end = match.span()
        if text[start] == "\x1b" and end - start > 1 and text[start + 1] in SEQUENCE_OPENERS:
            skipped.add(start + 1)
        if text.endswith("\x1b\\", start, end):
            skipped.add(end - 1)
        skipped.update(pos for pos in range(start, end) if text[pos].isspace())
    return frozenset(skipped)


View = tuple[str, tuple[int, ...]]
VIEW_CACHE_SIZE = 64


@lru_cache(maxsize=VIEW_CACHE_SIZE)
def _view(text: str, spaces: int) -> View:
    """The MATCHING view: ``text`` without ignorable characters (and without the plain spaces and
    delimiters inside terminal sequences, whose other characters are kept), and the position of
    each kept character."""
    skipped = _sequence_skipped(text)
    kept = tuple(
        pos
        for pos, char in enumerate(text)
        if pos not in skipped and not _is_ignorable(char, spaces)
    )
    return "".join(text[pos] for pos in kept), kept


# A terminal sequence as a range of the text, and whether it is closed (a string sequence
# without its terminator is open: it swallows the text up to the next ESC or the end).
Sequence = tuple[int, int, bool]


def _is_open(sequence: str) -> bool:
    introducer = STRING_INTRODUCER_RE.match(sequence)
    return introducer is not None and STRING_TERMINATOR_RE.search(sequence) is None


@lru_cache(maxsize=VIEW_CACHE_SIZE)
def _display_sequences(text: str) -> tuple[Sequence, ...]:
    """The terminal sequences the strip will remove, as ranges of ``text``: found, like the
    pipeline does, after the characters hidden in display are removed (an invisible character
    between ESC and ``[`` does not keep the sequence from forming)."""
    if _is_plain(text):
        return ()
    shown = [pos for pos, char in enumerate(text) if not is_hidden_in_display(char)]
    compact = "".join(text[pos] for pos in shown)
    return tuple(
        (shown[match.start()], shown[match.end() - 1] + 1, not _is_open(match.group(0)))
        for match in TERMINAL_SEQUENCE_RE.finditer(compact)
    )


@lru_cache(maxsize=VIEW_CACHE_SIZE)
def _display_view(text: str, spaces: int) -> View:
    """The DISPLAYED view: what the strip leaves of ``text`` (terminal sequences removed whole),
    seen through ignorable characters, and the position of each kept character. A secret split
    by a sequence whose body would otherwise be read as part of it is found whole here."""
    inside = {pos for start, end, _ in _display_sequences(text) for pos in range(start, end)}
    kept = tuple(
        pos
        for pos, char in enumerate(text)
        if pos not in inside and not _is_ignorable(char, spaces)
    )
    return "".join(text[pos] for pos in kept), kept


Edit = tuple[int, int, str]
Edits = Callable[["re.Match[str]"], list[Edit]]
Span = Callable[["re.Match[str]"], Edit]


def _sequence_before(sequences: tuple[Sequence, ...], position: int) -> Sequence | None:
    """The last terminal sequence that starts before ``position``."""
    at = bisect.bisect_left(sequences, (position, -1, False)) - 1
    return sequences[at] if at >= 0 else None


def _widened(sequences: tuple[Sequence, ...], first: int, last: int) -> tuple[int, int]:
    """``[first, last)`` grown so that it never cuts a terminal sequence in two: a sequence that
    starts inside it and ends after it is taken whole (a mask never removes an introducer and
    leaves the body as text), and so is a closed sequence that starts before it and ends inside
    it (an ESC left in front of the replacement would eat the replacement). An open string
    sequence before the span is left as it is: the strip treats the text before it as cut."""
    tail = _sequence_before(sequences, last)
    if tail is not None and first <= tail[0] and tail[1] > last:
        last = tail[1]
    head = _sequence_before(sequences, first)
    if head is not None and first < head[1] <= last and head[2]:
        first = head[0]
    return first, last


def _apply_edits(text: str, edits: list[Edit]) -> str:
    """``text`` with every edit applied; overlapping edits are merged (the earliest replacement
    stands for the union)."""
    sequences = _display_sequences(text)
    merged: list[Edit] = []
    widened = (_widened(sequences, first, last) + (repl,) for first, last, repl in edits)
    for first, last, replacement in sorted(widened):
        if merged and first < merged[-1][1]:
            low, high, kept = merged[-1]
            merged[-1] = (low, max(high, last), kept)
        else:
            merged.append((first, last, replacement))
    out: list[str] = []
    pos = 0
    for first, last, replacement in merged:
        out.extend((text[pos:first], replacement))
        pos = last
    out.append(text[pos:])
    return "".join(out)


def _views_of(text: str, spaces: int) -> list[tuple[str, tuple[int, ...] | None]]:
    """The text as written, its matching view and its displayed view (those that differ)."""
    views: list[tuple[str, tuple[int, ...] | None]] = [(text, None)]
    # The exact api key is also looked for through a plain space (``spaces``), so printable
    # ASCII with a space in it has a matching view too.
    if not _is_plain(text) or (spaces >= ALL_SPACES and SPACE in text):
        for view, index in (_view(text, spaces), _display_view(text, spaces)):
            if view != text and all(view != seen for seen, _ in views):
                views.append((view, index))
    return views


def _edit_views(text: str, pattern: re.Pattern[str], edits_of: Edits, spaces: int) -> str:
    """Apply ``pattern`` to the text as written, to its matching view (through escape bytes,
    controls and invisible characters) and to its displayed view (terminal sequences removed),
    and edit the original once at the union of the matched spans (``edits_of`` gives start, end
    and replacement in the positions of the view it was given)."""
    edits: list[Edit] = []
    for view, index in _views_of(text, spaces):
        for match in pattern.finditer(view):
            for start, end, replacement in edits_of(match):
                if index is None:
                    edits.append((start, end, replacement))
                else:
                    edits.append((index[start], index[end - 1] + 1, replacement))
    return _apply_edits(text, edits) if edits else text


def _masked_sub(text: str, pattern: re.Pattern[str], span_of: Span, spaces: int) -> str:
    """:func:`_edit_views` for a pattern whose every match is one edit."""
    return _edit_views(text, pattern, lambda match: [span_of(match)], spaces)


def _after_group_one(match: "re.Match[str]") -> tuple[int, int, str]:
    return match.end(1), match.end(), ""


def _after_slashes(match: "re.Match[str]") -> tuple[int, int, str]:
    return match.start() + 2, match.end(), ""


def _whole_match(match: "re.Match[str]") -> tuple[int, int, str]:
    return match.start(), match.end(), ""


def _masked_match(match: "re.Match[str]") -> tuple[int, int, str]:
    return match.start(), match.end(), MASK


_SPACE_RE = re.compile(r"\s")


class _TokenTracker:
    """Whether the whitespace-delimited token ending at a mark has a scheme. Marks must be asked
    in increasing order; each call only scans the text since the previous mark, so a word costs
    linear time however many marks it has."""

    def __init__(self, word: str) -> None:
        self._word = word
        self._start = 0
        self._scanned = 0
        self._has_scheme = False

    def has_scheme_before(self, mark: int) -> bool:
        spaces = deque(_SPACE_RE.finditer(self._word, self._scanned, mark), maxlen=1)
        if spaces:
            self._start = spaces[0].end()
            self._has_scheme = False
            from_pos = self._start
        else:
            from_pos = max(self._start, self._scanned - len(SCHEME_MARKER) + 1)
        if not self._has_scheme:
            self._has_scheme = self._word.find(SCHEME_MARKER, from_pos, mark) != -1
        self._scanned = mark
        return self._has_scheme


# A numeric anchor: up to six ASCII digits, then only trailing punctuation up to the next
# whitespace character or the end of the word. Anchored at the position after the ``#``, so the
# test never slices the rest of the word and a possessive tail never backtracks.
_NUMERIC_ANCHOR_RE = re.compile(
    f"([0-9]{{1,{MAX_NUMERIC_FRAGMENT_CHARS}}})"
    f"[{re.escape(TRAILING_FRAGMENT_PUNCTUATION)}]*+(?=\\s|\\Z)"
)


def _is_numeric_anchor(digits: str, tokens: "_TokenTracker", mark: int) -> bool:
    """True for the ASCII digits of a numeric anchor (see ``_NUMERIC_ANCHOR_RE``): at most
    ``MAX_NUMERIC_FRAGMENT_CHARS`` of them in a scheme-less token, at most
    ``MAX_SCHEME_NUMERIC_FRAGMENT_CHARS`` when the text before the ``#`` at ``mark`` has a scheme
    in the same token (the last whitespace-delimited run)."""
    has_scheme = tokens.has_scheme_before(mark)
    limit = MAX_SCHEME_NUMERIC_FRAGMENT_CHARS if has_scheme else MAX_NUMERIC_FRAGMENT_CHARS
    return len(digits) <= limit


def _is_masked(value: str) -> bool:
    """True when ``value`` is the mask with at most hidden characters or whitespace around it
    (what another view of the same text left next to a mask it wrote)."""
    shown = (char for char in value if not (char.isspace() or _is_ignorable(char, CONTROL_SPACES)))
    return "".join(shown) == MASK


def _pair_edits(word: str, mark: int, end: int, base: int) -> list[Edit]:
    """One edit per pair of the query ``word[mark + 1 : end]`` whose value is not masked yet; an
    edit covers the separator before its pair, so an empty pair is masked too."""
    edits: list[Edit] = []
    at = mark
    for pair in word[mark + 1 : end].split("&"):
        name, equals, value = pair.partition("=")
        if not _is_masked(value if equals else pair):
            masked = f"{name}={MASK}" if equals else MASK
            edits.append((base + at, base + at + 1 + len(pair), word[at] + masked))
        at += 1 + len(pair)
    return edits


def _query_edits(match: "re.Match[str]") -> list[Edit]:
    word, base = match.group(0), match.start()
    edits: list[Edit] = []
    search = 0
    hash_at = word.find("#")
    scan = scan_word(word)
    bounds = scan_boundaries(word)
    ends = RunEnds(word)
    while (mark := word.find("?", search)) != -1:
        if 0 <= hash_at < mark:
            hash_at = word.find("#", mark)
        limit = len(word) if hash_at == -1 else hash_at
        search = mark + 1
        if limit > mark + 1 and _urlish_before(word, scan, bounds, mark, mark + 1, limit):
            end = ends.end(mark + 1, limit)
            if end > mark + 1:
                edits.extend(_pair_edits(word, mark, end, base))
                search = end
    return edits


def _fragment_edits(match: "re.Match[str]") -> list[Edit]:
    """The fragment of a word masked from the first ``#`` with a url-ish context before it (the
    same context a query needs), up to the end of the word or its trailing closers (see
    ``CLOSING_PUNCTUATION``: ``)``, ``]``, ``}``, ``>``, ``|`` and so on stay). A numeric
    anchor is exempt (no edit for that mark; text after its whitespace is judged on its own): up
    to six ASCII digits in a scheme-less token (``refs/heads/feature#12``), trailing punctuation
    ignored; with a scheme before the anchor only a short one (up to three digits) stays, so a
    one-time-code shape such as ``https://host/verify#123456`` is masked."""
    word, base = match.group(0), match.start()
    search = 0
    edits: list[Edit] = []
    tokens = _TokenTracker(word)
    first_query = word.find("?")
    scan = scan_word(word)
    bounds = scan_boundaries(word)
    ends = RunEnds(word)
    while (mark := word.find("#", search)) != -1:
        head_end = first_query if 0 <= first_query < mark else mark
        query_start = min(head_end + 1, mark)
        url_head = _urlish_before(word, scan, bounds, head_end, query_start, mark)
        search = mark + 1
        if mark + 1 < len(word) and url_head:
            stop = ends.end(mark + 1, len(word))
            anchor = _NUMERIC_ANCHOR_RE.match(word, mark + 1, stop)
            if anchor is not None and _is_numeric_anchor(anchor.group(1), tokens, mark):
                # Resume at the end of the anchor, not at ``stop``: with ``across_breaks`` the
                # run goes past the whitespace, and a later fragment there must still be judged
                # (see the reconciliation note at ``RUN_END_CATEGORIES`` in sanitise_hosts).
                search = anchor.end()
                continue
            body = word[mark + 1 : stop].rstrip(CLOSING_PUNCTUATION)
            end = mark + 1 + len(body) if body else stop
            if end > mark + 1 and not _is_masked(word[mark + 1 : end]):
                edits.append((base + mark, base + end, "#" + MASK))
            search = max(search, end)
    return edits


def _words(across_breaks: bool) -> re.Pattern[str]:
    return WORD_ACROSS_BREAKS_RE if across_breaks else WORD_RE


# A mask can change how the terminal sequences around it parse (it may remove the ESC that ended
# an open string sequence), so a mask stage runs until the text is stable: applying it twice
# gives the same text as once. Each round only masks more; the bound keeps the time linear.
MAX_MASK_ROUNDS = 4


def _until_stable(step: Callable[[str], str], text: str) -> str:
    for _ in range(MAX_MASK_ROUNDS):
        masked = step(text)
        if masked == text:
            break
        text = masked
    return text


def _queries_once(text: str, across_breaks: bool = False) -> str:
    if "?" not in text:
        return text
    return _edit_views(text, _words(across_breaks), _query_edits, False)


def _fragments_once(text: str, across_breaks: bool = False) -> str:
    if "#" not in text:
        return text
    return _edit_views(text, _words(across_breaks), _fragment_edits, False)


def mask_queries(text: str, *, across_breaks: bool = False) -> str:
    """``text`` with the query of every url-ish word masked (``?k=***``): a question mark needs a
    url-ish context before it, so prose such as ``what?`` in CJK or Thai text is left alone. The
    context is found through ignorable characters and with terminal sequences removed; with
    ``across_breaks`` only a plain space ends a value."""
    return _until_stable(lambda shown: _queries_once(shown, across_breaks), text)


def mask_fragments(text: str, *, across_breaks: bool = False) -> str:
    """``text`` with the fragment of every url-ish word masked (``#***``), with or without a
    scheme, also through ignorable characters and terminal sequences (a mark or an escape inside
    the marker must not hide it); with ``across_breaks`` only a plain space ends a fragment."""
    return _until_stable(lambda shown: _fragments_once(shown, across_breaks), text)
