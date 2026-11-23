# ruff: noqa: F401, F811
"""Joiners are allowed in label and env values between visible characters (round 63).

The shared content rule refused every format character, so an emoji family sequence and
words in Devanagari, Malayalam, Sinhala or Persian, which need U+200D / U+200C, failed. In a
label or env VALUE the two joiners are accepted when both neighbours are visible; at either
end, next to whitespace, doubled or next to another format character they are refused with the
U+200D (or U+200C) message. Label keys and every other field still refuse them.
"""

from typing import Any

import httpx
import pytest
from tests.test_content_rules_r63 import (
    CREATED_STATUS,
    SANDBOXES,
    VALIDATION_STATUS,
    app,
    assert_refused,
    client,
    headers,
    migrated_db,
)

from sandfort.api.schemas.text_checks import content_problem

ZWJ = "\u200d"
ZWNJ = "\u200c"
FAMILY = "\U0001f468\u200d\U0001f469\u200d\U0001f467"
DEVANAGARI_KSHA = "\u0915\u094d\u200d\u0937"  # Devanagari ksha: ka, virama, ZWJ, ssa
PERSIAN_MIKHAHAM = "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645"  # mikhaham, ZWNJ
MALAYALAM_CHILLU = "\u0d28\u0d4d\u200d"  # na, virama, ZWJ: the chillu n
MALAYALAM_WORD = MALAYALAM_CHILLU + "\u0d28\u0d3e"  # chillu n, then na and the aa sign
SINHALA_YANSAYA = "\u0dc1\u0dca\u200d\u0dbb\u0dd3"  # shri: sha, al-lakuna, ZWJ, ra, ii
EMOJI_VS16 = "\u2764\ufe0f\u200d\U0001f525"  # heart on fire: variation selector, ZWJ
EMOJI_MODIFIER = "\U0001f9d1\U0001f3fb\u200d\U0001f4bb"  # technologist with a skin tone

ACCEPTED = [
    pytest.param(FAMILY, id="emoji-family"),
    pytest.param(DEVANAGARI_KSHA, id="devanagari-zwj"),
    pytest.param(PERSIAN_MIKHAHAM, id="persian-zwnj"),
    pytest.param(MALAYALAM_WORD, id="malayalam-chillu"),
    pytest.param(SINHALA_YANSAYA, id="sinhala-yansaya"),
    pytest.param(EMOJI_VS16, id="emoji-variation-selector"),
    pytest.param(EMOJI_MODIFIER, id="emoji-modifier"),
    pytest.param(f"x {FAMILY} y", id="family-in-a-sentence"),
]
# (value, joiner) refused: the joiner is the first or last character, doubled, next to a space
# or next to another format character.
REFUSED = [
    pytest.param(f"{ZWJ}ab", ZWJ, id="leading-zwj"),
    pytest.param(f"ab{ZWJ}", ZWJ, id="trailing-zwj"),
    pytest.param(f"a{ZWJ}{ZWJ}b", ZWJ, id="doubled-zwj"),
    pytest.param(f"a {ZWJ}b", ZWJ, id="space-before-zwj"),
    pytest.param(f"a{ZWJ} b", ZWJ, id="space-after-zwj"),
    pytest.param(f"a{ZWJ}\u00a0b", ZWJ, id="no-break-space-after-zwj"),
    pytest.param(f"a{ZWJ}\u3000b", ZWJ, id="ideographic-space-after-zwj"),
    pytest.param(f"a{ZWJ}\u200bb", ZWJ, id="zwj-then-zero-width-space"),
    pytest.param(f"a{ZWJ}\u2060b", ZWJ, id="zwj-then-word-joiner"),
    pytest.param(f"a{ZWJ}{ZWNJ}b", ZWJ, id="zwj-then-zwnj"),
    pytest.param(f"a{ZWJ}\u202eb", ZWJ, id="zwj-then-bidi-control"),
    pytest.param(f"a{ZWJ}\tb", ZWJ, id="tab-after-zwj"),
    pytest.param(ZWJ, ZWJ, id="only-zwj"),
    pytest.param(f"{ZWNJ}ab", ZWNJ, id="leading-zwnj"),
    pytest.param(f"ab{ZWNJ}", ZWNJ, id="trailing-zwnj"),
    pytest.param(f"a {ZWNJ}b", ZWNJ, id="space-before-zwnj"),
    pytest.param(f"a{ZWNJ}{ZWNJ}b", ZWNJ, id="doubled-zwnj"),
]


def code_point(char: str) -> str:
    return f"U+{ord(char):04X}"


@pytest.mark.parametrize("value", ACCEPTED)
def test_value_rule_accepts_a_joiner_between_visible_characters(value: str) -> None:
    assert content_problem(value, allow_joiners=True) is None
    assert content_problem(value, allow_tab=True, allow_joiners=True) is None


@pytest.mark.parametrize(("value", "joiner"), REFUSED)
def test_value_rule_refuses_a_joiner_anywhere_else(value: str, joiner: str) -> None:
    problem = content_problem(value, allow_tab=True, allow_joiners=True)

    assert problem is not None
    assert problem.startswith("contains an invisible format character"), problem
    assert code_point(joiner) in problem


@pytest.mark.parametrize("value", ACCEPTED)
def test_other_fields_still_refuse_every_joiner(value: str) -> None:
    problem = content_problem(value)

    assert problem is not None
    assert problem.startswith("contains an invisible format character")


# --- through the API -------------------------------------------------------------------------


@pytest.mark.parametrize("value", ACCEPTED)
async def test_label_values_accept_joiners_between_visible_characters(
    client: httpx.AsyncClient, headers: dict[str, str], value: str
) -> None:
    created = await client.post(SANDBOXES, json={"labels": {"naziv": value}}, headers=headers)

    assert created.status_code == CREATED_STATUS, created.text
    sandbox = created.json()["data"]
    read = await client.get(f"{SANDBOXES}/{sandbox['id']}", headers=headers)
    assert read.json()["data"]["labels"] == {"naziv": value}


@pytest.mark.parametrize("value", ACCEPTED)
async def test_env_values_accept_joiners_between_visible_characters(
    client: httpx.AsyncClient, headers: dict[str, str], value: str
) -> None:
    created = await client.post(SANDBOXES, json={"env": {"GREETING": value}}, headers=headers)

    assert created.status_code == CREATED_STATUS, created.text


@pytest.mark.parametrize(("value", "joiner"), REFUSED)
async def test_label_values_refuse_a_misplaced_joiner(
    client: httpx.AsyncClient, headers: dict[str, str], value: str, joiner: str
) -> None:
    response = await client.post(SANDBOXES, json={"labels": {"naziv": value}}, headers=headers)

    assert_refused(response, ["body", "labels"], joiner)
    assert (await client.get(SANDBOXES, headers=headers)).json()["data"] == []


@pytest.mark.parametrize(("value", "joiner"), REFUSED)
async def test_env_values_refuse_a_misplaced_joiner(
    client: httpx.AsyncClient, headers: dict[str, str], value: str, joiner: str
) -> None:
    response = await client.post(SANDBOXES, json={"env": {"K": value}}, headers=headers)

    assert_refused(response, ["body", "env"], joiner)


@pytest.mark.parametrize("joiner", [ZWJ, ZWNJ])
async def test_a_joiner_in_a_label_key_is_refused(
    client: httpx.AsyncClient, headers: dict[str, str], joiner: str
) -> None:
    body: dict[str, Any] = {"labels": {f"te{joiner}am": "v"}}

    response = await client.post(SANDBOXES, json=body, headers=headers)

    assert_refused(response, ["body", "labels"], joiner)


async def test_a_joiner_in_an_env_key_is_refused(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.post(SANDBOXES, json={"env": {f"K{ZWJ}X": "v"}}, headers=headers)

    assert_refused(response, ["body", "env"], ZWJ)


async def test_a_joiner_in_an_egress_host_is_refused(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    body = {"egress_allowlist": [f"exa{ZWJ}mple.com"]}

    response = await client.post(SANDBOXES, json=body, headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
