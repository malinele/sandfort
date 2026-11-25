"""TypeScript SDK parity: ``SANDBOX_ERROR_CODES`` equals the server's ``ERROR_CODES``, in order."""

import re
from pathlib import Path

from sandfort.domain.sandbox import ERROR_CODES

TS_SRC = Path(__file__).resolve().parents[1] / "sdk" / "typescript" / "src"

# `export const SANDBOX_ERROR_CODES = [ "a", "b", ... ] as const;`, whitespace, trailing
# comma and line breaks free.
_ARRAY = re.compile(
    r"export\s+const\s+SANDBOX_ERROR_CODES\s*(?::[^=]*)?=\s*\[(?P<body>[^\]]*)\]\s*as\s+const",
)
_LITERAL = re.compile(r"""["']([^"']*)["']""")


def _ts_error_codes() -> tuple[str, ...]:
    found = [
        match
        for path in sorted(TS_SRC.rglob("*.ts"))
        if (match := _ARRAY.search(path.read_text(encoding="utf-8")))
    ]
    assert len(found) == 1, (
        "SANDBOX_ERROR_CODES must be declared exactly once in sdk/typescript/src"
    )
    return tuple(_LITERAL.findall(found[0].group("body")))


def test_ts_error_codes_match_the_server_set_and_order() -> None:
    assert _ts_error_codes() == ERROR_CODES


def test_ts_error_codes_have_no_duplicates() -> None:
    codes = _ts_error_codes()
    assert len(codes) == len(set(codes))
