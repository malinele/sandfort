"""A JSON response that survives lone UTF-16 surrogates in stored text (round 53).

A JSON string can carry a lone surrogate (the escape ``\\ud800``) and Python keeps it in the
``str``, but it has no UTF-8 encoding, so ``JSONResponse`` raised while rendering and every read
of a row holding one answered 500. ``SafeJSONResponse`` replaces each lone surrogate with
U+FFFD (the replacement character) before it encodes. It is a read-time fix only: nothing stored
is modified. A surrogate pair that forms a valid code point is already one character in a Python
``str``, and all other text is rendered exactly as ``JSONResponse`` renders it, so the bytes of
ordinary output are unchanged.

The application's default response class is this one (``create_app``), and the routes that
build a JSON response directly use it by name.
"""

import json
import re
from typing import Any

from starlette.responses import JSONResponse

REPLACEMENT_CHARACTER = "�"
# Any surrogate left in a ``str`` is a lone one: a valid pair is a single astral character.
LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def render_json(content: Any) -> bytes:
    """``content`` as compact UTF-8 JSON with lone surrogates replaced by U+FFFD.

    Same ``json.dumps`` arguments as Starlette's ``JSONResponse.render``.
    """
    text = json.dumps(
        content,
        ensure_ascii=False,
        allow_nan=False,
        indent=None,
        separators=(",", ":"),
    )
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        return LONE_SURROGATE.sub(REPLACEMENT_CHARACTER, text).encode("utf-8")


class SafeJSONResponse(JSONResponse):
    """``JSONResponse`` that renders a lone surrogate as U+FFFD instead of failing."""

    def render(self, content: Any) -> bytes:
        return render_json(content)
