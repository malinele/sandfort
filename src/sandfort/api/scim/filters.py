"""SCIM filter parsing: the one supported form is ``userName eq "<value>"``.

Pure functions, no database, no http, no settings (``docs/scim-design.md``, Filter and
pagination). The attribute name and ``eq`` are matched case-insensitively and the value is
returned lowercased, because ``userName`` is stored as a lowercased email. Every other filter
(``and``, ``or``, ``co``, ``sw``, ``externalId``, grouping, fully qualified attribute names)
is refused with scimType ``invalidFilter``; nothing is guessed. The refusal message never
repeats the filter text.
"""

import json
import re
from dataclasses import dataclass
from typing import ClassVar, Final

from sandfort.errors import ValidationFailed

INVALID_FILTER: Final = "invalidFilter"

# ASCII only: without it IGNORECASE would let non-ASCII look-alikes (such as U+017F) match "s".
_USER_NAME_EQ: Final = re.compile(
    r'\s*userName\s+eq\s+("(?:[^"\\]|\\.)*")\s*',
    re.IGNORECASE | re.ASCII,
)


class FilterError(ValidationFailed):
    """The filter is not the supported ``userName eq`` form (HTTP 400, ``invalidFilter``)."""

    scim_type: ClassVar[str] = INVALID_FILTER


@dataclass(frozen=True, slots=True)
class UserNameFilter:
    """A parsed ``userName eq`` filter; ``user_name`` is already lowercased."""

    user_name: str


def parse_user_filter(text: str) -> UserNameFilter:
    """Parse ``text`` as ``userName eq "<value>"`` or raise ``FilterError``.

    The value is a double-quoted JSON string, so ``\\"`` and ``\\uXXXX`` escapes work and a
    raw control character does not.
    """
    match = _USER_NAME_EQ.fullmatch(text)
    if match is None:
        raise _unsupported()
    try:
        value = json.loads(match.group(1))
    except ValueError:
        raise _unsupported() from None
    if not isinstance(value, str):
        raise _unsupported()
    return UserNameFilter(user_name=value.lower())


def _unsupported() -> FilterError:
    return FilterError('Unsupported filter: only userName eq "<value>" is supported')
