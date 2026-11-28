"""B44: the TypeScript SDK warns once per client on an http:// base url to a remote host."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TS = ROOT / "sdk" / "typescript"
PY = ROOT / "sdk" / "python" / "src" / "sandfort_sdk" / "insecure_url.py"
MODULE = TS / "src" / "insecure-url.ts"
TAIL = "so the api key is sent in clear text"
CONSTRUCTOR = re.compile(
    r"constructor\(options: SandfortClientOptions\)\s*\{(.*?)\n  \}", re.DOTALL
)
INDEX_EXPORT = re.compile(
    r'export\s*\{[^}]*\bINSECURE_BASE_URL_WARNING\b[^}]*\}\s*from\s*"\./insecure-url\.js"'
)


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_module_exists_with_the_two_functions() -> None:
    src = text(MODULE)
    assert "export function insecureHost(" in src
    assert "export function warnIfInsecureBaseUrl(" in src
    assert 'export const INSECURE_BASE_URL_WARNING = "InsecureBaseUrlWarning"' in src
    assert "process.emitWarning(" in src
    assert "type: INSECURE_BASE_URL_WARNING" in src


def test_loopback_rules_match_the_python_sdk() -> None:
    assert 'LOOPBACK_NAME = "localhost"' in text(MODULE)
    assert 'LOOPBACK_NAME = "localhost"' in text(PY)
    assert r"127\." in text(MODULE)


def test_message_tail_matches_the_python_sdk() -> None:
    src = text(MODULE)
    assert TAIL in src
    assert TAIL in text(PY)
    assert "filter InsecureBaseUrlWarning if the network is private and trusted" in src


def test_name_is_exported_from_the_package_index() -> None:
    assert INDEX_EXPORT.search(text(TS / "src" / "index.ts"))


def test_client_constructor_warns_after_the_transport_is_built() -> None:
    base = text(TS / "src" / "client-base.ts")
    match = CONSTRUCTOR.search(base)
    assert match is not None
    body = match.group(1)
    assert "warnIfInsecureBaseUrl(options.baseUrl);" in body
    assert body.index("new Transport(options)") < body.index("warnIfInsecureBaseUrl(")
    assert 'from "./insecure-url.js"' in base


def test_the_warning_is_called_exactly_once_in_src() -> None:
    count = sum(
        text(path).count("warnIfInsecureBaseUrl(")
        for path in sorted((TS / "src").glob("*.ts"))
        if path.name != "insecure-url.ts"
    )
    assert count == 1


def test_vitest_file_and_readme_cover_it() -> None:
    assert (TS / "tests" / "insecure-url.test.ts").is_file()
    assert "InsecureBaseUrlWarning" in text(TS / "README.md")


def test_scaffold_pins_the_new_export() -> None:
    assert '"INSECURE_BASE_URL_WARNING"' in text(TS / "tests" / "scaffold.test.ts")
