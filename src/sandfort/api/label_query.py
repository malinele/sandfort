"""The ``label=k=v`` list filter, parsed once for every list route that takes it."""

from sandfort.api.pagination import QueryRefusal
from sandfort.api.schemas.text_checks import invisible_text_problem

ECHO_LIMIT = 63  # the label key bound; a longer key is echoed cut to this many characters
ELLIPSIS = "..."  # ASCII, so the message stays plain ASCII whatever the key holds


def _echo_key(key: str) -> str:
    """``key`` escaped with ``ascii()``, cut to ``ECHO_LIMIT`` characters plus an ellipsis."""
    shown = ascii(key[:ECHO_LIMIT])
    return shown if len(key) <= ECHO_LIMIT else shown + ELLIPSIS


def parse_label_filter(pairs: list[str]) -> dict[str, str]:
    """``k=v`` pairs as a mapping, or a 422 at ``query.label``.

    A pair without ``=``, with an empty key, or with a key that has invisible text is refused.
    ``k=`` is the key ``k`` with an empty value and ``a=b=c`` the key ``a`` with value ``b=c``.
    The exact same pair repeated counts once; one key with two different values is refused.
    That refusal echoes the key escaped with ``ascii()`` and cut at 63 characters.
    """
    labels: dict[str, str] = {}
    for pair in pairs:
        key, separator, value = pair.partition("=")
        if not separator or not key:
            raise QueryRefusal("label", f"label filter must be k=v, got {pair!r}")
        if (problem := invisible_text_problem(key)) is not None:
            # The text check create applies to label keys; same entry shape, no echo of the key.
            raise QueryRefusal("label", f"label names {problem}")
        if labels.get(key, value) != value:
            raise QueryRefusal(
                "label",
                f"label key {_echo_key(key)} is given more than once with different values",
            )
        labels[key] = value
    return labels
