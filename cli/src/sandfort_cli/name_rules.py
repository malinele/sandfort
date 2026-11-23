"""Plain wording for the server's name-rule errors (instead of the raw regex it echoes)."""

from typing import Any

# The pattern the API puts on sandbox, volume and process names (``NAME_PATTERN``).
SERVER_NAME_PATTERN = "^[A-Za-z0-9][A-Za-z0-9_.-]*$"
NAME_RULE_TEXT = "letters, digits, '.', '_' and '-', starting with a letter or digit, at most 63"
_MATCH_PHRASE = f"should match pattern '{SERVER_NAME_PATTERN}'"
_PLAIN_PHRASE = f"should be {NAME_RULE_TEXT}"
_PLAIN_MAX_DEPTH = 8


def plain_name_rule(text: str) -> str:
    """``text`` with the server's name pattern replaced by :data:`NAME_RULE_TEXT`.

    ``should match pattern '<regex>'`` becomes ``should be <description>``; the bare regex
    anywhere else (a ``ctx.pattern`` detail) becomes the description alone.
    """
    if SERVER_NAME_PATTERN not in text:
        return text
    return text.replace(_MATCH_PHRASE, _PLAIN_PHRASE).replace(SERVER_NAME_PATTERN, NAME_RULE_TEXT)


def plain_name_rules(value: Any, depth: int = 0) -> Any:
    """``value`` (json-like details) with :func:`plain_name_rule` applied to every string."""
    if isinstance(value, str):
        return plain_name_rule(value)
    if depth >= _PLAIN_MAX_DEPTH:
        return value
    if isinstance(value, dict):
        return {key: plain_name_rules(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [plain_name_rules(item, depth + 1) for item in value]
    return value
