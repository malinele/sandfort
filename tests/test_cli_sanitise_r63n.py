"""CLI review r63n: fullwidth and arrow separators before a host no longer leak the secret.

``＝`` (fullwidth equals), ``｜`` (fullwidth vertical line), ``→`` and ``⇒`` glued to a host
that is followed by ``#access_token=...``, and ``＝`` before an IPv4 address followed by
``?token=...``, read as the separators their ASCII twins (``=``, ``|``, ``>``) already are.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli.sanitise import mask_fragments, mask_queries, sanitise_text  # noqa: E402

TOKEN = "tok_9fK2mQx7LpR4vB8nZc3Wd5YhA1sE6uJt"
HOST = "host.example"
IPV4 = "203.0.113.9"
SEPARATORS = {
    "fullwidth equals": "＝",
    "fullwidth vertical line": "｜",
    "rightwards arrow": "→",
    "rightwards double arrow": "⇒",
    "ascii equals": "=",
    "ascii pipe": "|",
    "ascii arrow": "->",
    "ascii fat arrow": "=>",
}


@pytest.mark.parametrize("lead", ["redirect", "", "1", "(", "Ünï"], ids=repr)
@pytest.mark.parametrize("separator", SEPARATORS.values(), ids=SEPARATORS.keys())
def test_a_fragment_after_a_host_behind_the_separator_is_masked(separator: str, lead: str) -> None:
    line = f"{lead}{separator}{HOST}#access_token={TOKEN}&state=ok"

    for result in (mask_fragments(line), sanitise_text(line, api_key="", limit=10_000)):
        assert TOKEN not in result
        assert HOST in result


@pytest.mark.parametrize("separator", SEPARATORS.values(), ids=SEPARATORS.keys())
def test_a_fragment_after_a_spaced_separator_is_masked(separator: str) -> None:
    line = f"location {separator}{HOST}#access_token={TOKEN}"

    assert TOKEN not in sanitise_text(line, api_key="", limit=10_000)


@pytest.mark.parametrize("lead", ["url", "", "10", "v4:", "(", "Ünï"], ids=repr)
@pytest.mark.parametrize("separator", SEPARATORS.values(), ids=SEPARATORS.keys())
def test_a_query_after_an_ipv4_behind_the_separator_is_masked(separator: str, lead: str) -> None:
    line = f"{lead}{separator}{IPV4}?token={TOKEN}"

    for result in (mask_queries(line), sanitise_text(line, api_key="", limit=10_000)):
        assert TOKEN not in result
        assert IPV4 in result


@pytest.mark.parametrize("separator", SEPARATORS.values(), ids=SEPARATORS.keys())
def test_a_query_after_a_host_with_a_port_behind_the_separator_is_masked(separator: str) -> None:
    line = f"url{separator}{HOST}:8443?token={TOKEN}"

    assert TOKEN not in sanitise_text(line, api_key="", limit=10_000)


@pytest.mark.parametrize("separator", ["＝", "｜", "→", "⇒"])
def test_prose_around_these_characters_stays_visible(separator: str) -> None:
    line = f"price{separator}ten and a#12 are fine"

    assert sanitise_text(line, api_key="", limit=10_000) == line
