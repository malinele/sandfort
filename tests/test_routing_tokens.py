"""Route tokens: mint/verify round trip and every rejection path; hermetic, no Docker.

Several tests sign hand-built payloads with the real secret, so a rejection there proves the
canonical-spelling and claim checks rather than a signature mismatch.
"""

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import pytest

from sandfort.routing.tokens import (
    INVALID_ROUTE_MESSAGE,
    ROUTE_PREFIX,
    ROUTE_TOKEN_TTL_S,
    InvalidRouteToken,
    RouteClaims,
    mint_route_token,
    verify_route_token,
)

NOW = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
SECRET = "route-secret-for-tests-0123456789abcdef"
OTHER_SECRET = "a-different-route-secret-0123456789abc"
NODE = "beta"
OTHER_NODE = "alpha"
SANDBOX = "sbx_01JROUTETOKENTEST"
OTHER_SANDBOX = "sbx_01JSOMEOTHERSANDBOX"
B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _token(
    *, secret: str = SECRET, node_id: str = NODE, sandbox_id: str = SANDBOX, now: datetime = NOW
) -> str:
    return mint_route_token(secret, sandbox_id=sandbox_id, node_id=node_id, now=now)


def _verify(
    token: str,
    *,
    secret: str = SECRET,
    node_id: str = NODE,
    sandbox_id: str = SANDBOX,
    now: datetime = NOW,
) -> RouteClaims:
    return verify_route_token(secret, token, node_id=node_id, sandbox_id=sandbox_id, now=now)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _canonical(body: object) -> bytes:
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode("ascii")


def _claims(**overrides: object) -> dict[str, object]:
    issued = int(NOW.timestamp())
    body: dict[str, object] = {
        "sbx": SANDBOX,
        "node": NODE,
        "iat": issued,
        "exp": issued + ROUTE_TOKEN_TTL_S,
    }
    return {**body, **overrides}


def _without(key: str) -> dict[str, object]:
    return {name: value for name, value in _claims().items() if name != key}


def _signed(payload: str, *, secret: str = SECRET) -> str:
    """A token whose signature is genuine for ``payload``, however that payload is spelled."""
    digest = hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest()
    return f"{ROUTE_PREFIX}{payload}.{_b64(digest)}"


def _swap_char(token: str, index: int) -> str:
    replacement = "A" if token[index] != "A" else "B"
    return token[:index] + replacement + token[index + 1 :]


# ---- round trip


def test_round_trip_returns_the_sandbox_node_and_lifetime() -> None:
    claims = _verify(_token())

    assert claims.sandbox_id == SANDBOX
    assert claims.node_id == NODE
    assert claims.issued_at == NOW
    assert claims.expires_at - claims.issued_at == timedelta(seconds=ROUTE_TOKEN_TTL_S)
    assert ROUTE_TOKEN_TTL_S == 30


def test_the_payload_is_unpadded_canonical_json_with_exactly_four_claims() -> None:
    token = _token()
    payload = token.removeprefix(ROUTE_PREFIX).split(".")[0]

    assert ROUTE_PREFIX == "sfr_"
    assert token.startswith("sfr_")
    assert "=" not in token
    assert payload == _b64(_canonical(_claims()))
    assert sorted(_claims()) == ["exp", "iat", "node", "sbx"]


def test_a_hand_signed_canonical_payload_equals_the_minted_token() -> None:
    assert _signed(_b64(_canonical(_claims()))) == _token()


def test_a_token_is_still_live_one_second_before_expiry() -> None:
    later = NOW + timedelta(seconds=ROUTE_TOKEN_TTL_S - 1)

    assert _verify(_token(), now=later).sandbox_id == SANDBOX


def test_an_iat_up_to_five_seconds_ahead_is_tolerated() -> None:
    ahead = NOW + timedelta(seconds=5)

    assert _verify(_token(now=ahead)).issued_at == ahead


# ---- secret, node, sandbox and time


def test_wrong_secret_is_rejected() -> None:
    with pytest.raises(InvalidRouteToken):
        _verify(_token(), secret=OTHER_SECRET)


def test_an_empty_verifier_secret_is_rejected() -> None:
    with pytest.raises(InvalidRouteToken):
        _verify(_token(), secret="")


@pytest.mark.parametrize("expected_node", [OTHER_NODE, "BETA", "beta ", "bet", ""])
def test_a_token_is_accepted_only_by_its_exact_node(expected_node: str) -> None:
    with pytest.raises(InvalidRouteToken):
        _verify(_token(), node_id=expected_node)


@pytest.mark.parametrize("expected_sandbox", [OTHER_SANDBOX, SANDBOX.lower(), SANDBOX[:-1], ""])
def test_a_token_is_accepted_only_for_its_exact_sandbox(expected_sandbox: str) -> None:
    with pytest.raises(InvalidRouteToken):
        _verify(_token(), sandbox_id=expected_sandbox)


def test_a_token_minted_for_another_node_is_rejected() -> None:
    with pytest.raises(InvalidRouteToken):
        _verify(_token(node_id=OTHER_NODE))


def test_a_token_minted_for_another_sandbox_is_rejected() -> None:
    with pytest.raises(InvalidRouteToken):
        _verify(_token(sandbox_id=OTHER_SANDBOX))


def test_an_expired_token_is_rejected() -> None:
    expiry = NOW + timedelta(seconds=ROUTE_TOKEN_TTL_S)

    with pytest.raises(InvalidRouteToken):
        _verify(_token(), now=expiry)


def test_an_iat_more_than_five_seconds_ahead_is_rejected() -> None:
    with pytest.raises(InvalidRouteToken):
        _verify(_token(now=NOW + timedelta(seconds=6)))


# ---- tampering


def test_a_payload_forged_under_another_secret_is_rejected() -> None:
    forged_payload = _token(node_id=OTHER_NODE, secret=OTHER_SECRET).split(".")[0]
    genuine_signature = _token().split(".")[1]

    with pytest.raises(InvalidRouteToken):
        _verify(f"{forged_payload}.{genuine_signature}", node_id=OTHER_NODE)


def test_a_payload_rewritten_for_another_sandbox_is_rejected() -> None:
    rewritten = _b64(_canonical(_claims(sbx=OTHER_SANDBOX)))
    genuine_signature = _token().split(".")[1]

    with pytest.raises(InvalidRouteToken):
        _verify(f"{ROUTE_PREFIX}{rewritten}.{genuine_signature}", sandbox_id=OTHER_SANDBOX)


def test_tampered_payload_middle_character_is_rejected() -> None:
    token = _token()
    start = len(ROUTE_PREFIX)
    middle = start + (token.index(".") - start) // 2

    with pytest.raises(InvalidRouteToken):
        _verify(_swap_char(token, middle))


def test_tampered_signature_middle_character_is_rejected() -> None:
    token = _token()
    signature_start = token.index(".") + 1
    middle = signature_start + (len(token) - signature_start) // 2

    with pytest.raises(InvalidRouteToken):
        _verify(_swap_char(token, middle))


def test_tampered_signature_final_character_is_rejected() -> None:
    token = _token()

    with pytest.raises(InvalidRouteToken):
        _verify(_swap_char(token, len(token) - 1))


# ---- canonical spelling


def _reordered_json() -> str:
    return _b64(json.dumps(_claims(), separators=(",", ":")).encode("ascii"))


def _spaced_json() -> str:
    return _b64(json.dumps(_claims(), sort_keys=True).encode("ascii"))


def _escaped_key_json() -> str:
    canonical = _canonical(_claims()).decode("ascii")
    return _b64(canonical.replace('"sbx"', '"\\u0073bx"').encode("ascii"))


def _repadded_base64() -> str:
    return _b64(_canonical(_claims())) + "="


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(_reordered_json(), id="reordered-keys"),
        pytest.param(_spaced_json(), id="spaced-separators"),
        pytest.param(_escaped_key_json(), id="escaped-key"),
        pytest.param(_repadded_base64(), id="re-padded-base64"),
    ],
)
def test_a_genuinely_signed_non_canonical_spelling_is_rejected(payload: str) -> None:
    assert payload != _b64(_canonical(_claims()))

    with pytest.raises(InvalidRouteToken):
        _verify(_signed(payload))


def _spare_bits_spelling() -> tuple[str, str]:
    """A sandbox id and a payload spelling whose last base64 character sets a spare bit."""
    for extra in range(3):
        sandbox_id = SANDBOX + "X" * extra
        canonical = _b64(_canonical(_claims(sbx=sandbox_id)))
        if len(canonical) % 4 == 2:  # the last character holds 2 data bits and 4 spare bits
            last = B64URL_ALPHABET.index(canonical[-1])
            return sandbox_id, canonical[:-1] + B64URL_ALPHABET[last | 1]
    raise AssertionError("one of three consecutive payload lengths leaves spare bits")


def test_a_base64_spelling_with_a_spare_bit_set_is_rejected() -> None:
    sandbox_id, payload = _spare_bits_spelling()
    decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))

    assert decoded == _canonical(_claims(sbx=sandbox_id))  # same bytes, other spelling
    with pytest.raises(InvalidRouteToken):
        _verify(_signed(payload), sandbox_id=sandbox_id)


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(_claims(org="org_x"), id="extra-claim"),
        pytest.param(_without("node"), id="missing-node"),
        pytest.param(_claims(node=""), id="empty-node"),
        pytest.param(_claims(sbx=7), id="numeric-sandbox"),
        pytest.param(_claims(iat="2026-11-02T12:00:00Z"), id="text-iat"),
        pytest.param(_claims(exp=True), id="boolean-exp"),
        pytest.param(_claims(exp=int(NOW.timestamp()) + 3600), id="lifetime-over-ttl"),
        pytest.param([SANDBOX, NODE], id="not-an-object"),
    ],
)
def test_genuinely_signed_malformed_claims_are_rejected(body: object) -> None:
    with pytest.raises(InvalidRouteToken):
        _verify(_signed(_b64(_canonical(body))))


# ---- prefix and shape


@pytest.mark.parametrize("prefix", ["", "sfe_", "sf_", "SFR_", "sfr", "sfr-"])
def test_the_sfr_prefix_is_required(prefix: str) -> None:
    body = _token().removeprefix(ROUTE_PREFIX)

    with pytest.raises(InvalidRouteToken):
        _verify(prefix + body)


@pytest.mark.parametrize(
    "token", ["", "garbage", "sfr_", "sfr_abc", "sfr_a.b.c", "sfr_.abc", "sfr_abc.", "sf_a.b"]
)
def test_malformed_tokens_raise_the_generic_error(token: str) -> None:
    with pytest.raises(InvalidRouteToken) as caught:
        _verify(token)

    assert str(caught.value) == INVALID_ROUTE_MESSAGE


def test_rejections_carry_no_token_material() -> None:
    token = _token()

    with pytest.raises(InvalidRouteToken) as caught:
        _verify(token, node_id=OTHER_NODE)

    assert caught.value.args == (INVALID_ROUTE_MESSAGE,)
    assert token.split(".")[0] not in repr(caught.value)
    assert token.split(".")[1] not in repr(caught.value)


@pytest.mark.parametrize(
    ("secret", "node_id", "sandbox_id"),
    [("", NODE, SANDBOX), (SECRET, "", SANDBOX), (SECRET, NODE, "")],
)
def test_mint_refuses_empty_inputs(secret: str, node_id: str, sandbox_id: str) -> None:
    with pytest.raises(ValueError):
        mint_route_token(secret, sandbox_id=sandbox_id, node_id=node_id, now=NOW)

