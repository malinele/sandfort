"""Terminal escape sequences: the patterns the CLI strips before it decides a text is blank or
prints a server message (CSI, OSC, DCS, SOS, PM, APC and the short ESC forms; a lone ESC is left
to the caller)."""

import re
import unicodedata

from sandfort_cli.sanitise_stages import is_invisible

# The string sequences a terminal acts on: OSC (title, clipboard write, hyperlinks; ends in BEL,
# ESC \ or the C1 terminator) and DCS/SOS/PM/APC (end in ESC \ or the C1 terminator), in both
# the 7-bit (ESC ...) and the 8-bit C1 introducer form. One that never ends runs up to the next
# ESC or the end of the text, as it does in a terminal.
DANGEROUS_SEQUENCE_RE = re.compile(
    r"(?:\x1b\]|\x9d)[^\x07\x1b\x9c]*(?:\x07|\x1b\\|\x9c)?"
    r"|(?:\x1b[PX^_]|[\x90\x98\x9e\x9f])[^\x1b\x9c]*(?:\x1b\\|\x9c)?"
)

# A CSI sequence, in the sanitiser's form (``sanitise_stages.TERMINAL_SEQUENCE_RE``): the 7-bit
# introducer (``ESC [``) or the 8-bit C1 one (U+009B), parameters, intermediates and an OPTIONAL
# final byte. One cut off before its final byte (``\x9b31``, ``ESC [ 3``) is still removed, and
# the byte after a C1 introducer is taken as its final byte (``\x9bx``), as the sanitiser does.
CSI_SEQUENCE_RE = re.compile(r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]?")

# A short 7-bit sequence: ESC, any number of intermediate bytes (0x20-0x2F), one final byte
# (0x30-0x7E): ``ESC c``, ``ESC ( B``, ``ESC =``, ``ESC 7``, ``ESC M``, ``ESC ~``, ``ESC \``.
# The final byte is optional once an intermediate is there (``ESC !`` at the end of the text is
# removed, as the sanitiser does); ESC alone is not a sequence.
SHORT_ESCAPE_RE = re.compile(r"\x1b(?:[ -/]*[0-~]|[ -/]+)")

# All the forms in ONE alternation, longer forms first, so a single substitution removes them:
# what is left after one removal is never rescanned, and two pieces joined by a removal
# (``ESC`` + ``[`` around a C1 CSI) do not form a new sequence.
ANY_SEQUENCE_RE = re.compile(
    "|".join(r.pattern for r in (DANGEROUS_SEQUENCE_RE, CSI_SEQUENCE_RE, SHORT_ESCAPE_RE))
)

# Characters kept in the sequence view: the introducers, the terminators and BEL decide where a
# sequence starts and ends, so they stay even though they are control characters.
SEQUENCE_CONTROLS = frozenset("\x1b\x07") | frozenset(chr(code) for code in range(0x90, 0xA0))


def hides_inside_sequence(char: str) -> bool:
    """True for an invisible or control character that the sanitiser drops before it looks for
    sequences (so it cannot keep ``ESC <ZWSP> [`` from being one)."""
    if char in SEQUENCE_CONTROLS:
        return False
    return is_invisible(char) or unicodedata.category(char) == "Cc"


def without_escape_sequences(text: str) -> str:
    """``text`` without OSC, DCS, SOS, PM, APC, CSI and short ESC sequences, cut-off ones included
    (a lone ESC stays: it is a control character, which ``output.is_blank_char`` already counts
    as showing nothing).

    The patterns run on a view without invisible and control characters, as the sanitiser sees
    the text, so an invisible character between an introducer and its final byte does not hide
    the sequence. When the view holds no sequence, ``text`` is returned unchanged."""
    view = "".join(char for char in text if not hides_inside_sequence(char))
    stripped = ANY_SEQUENCE_RE.sub("", view)
    return text if stripped == view else stripped
