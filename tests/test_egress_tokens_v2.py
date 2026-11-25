"""Signed v2 egress tokens (``sfe2_``): claims, derived key, refusals; hermetic, no I/O.

Expected values are derived here from the documented contract (docs/egress-v2-design.md
section 5.1): the signing key is HMAC-SHA-256(secret, b"sandfort/egress/token/v2"), the payload is
sorted-key compact JSON in unpadded base64url, the signature is HMAC-SHA-256 of the payload text.
"""

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from sandfort.egress.policy_wire import token_v2_key
from sandfort.egress.tokens import (
    EGRESS_TOKEN_TTL_S,
    INVALID_EGRESS_MESSAGE,
    InvalidEgressToken,
    mint_egress_token,
    verify_egress_token,
)
from sandfort.egress.tokens_v2 import (
    EGRESS_V2_PREFIX,
    EgressClaimsV2,
    mint_egress_token_v2,
    verify_egress_token_v2,
)

SECRET = "test-egress-secret-v2"
SANDBOX = "sbx_v2"
EPOCH = 3
NOW = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)
TOKEN_LABEL = b"sandfort/egress/token/v2"
B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _mint(**overrides: Any) -> str:
    arguments: dict[str, Any] = {"sandbox_id": SANDBOX, "epoch": EPOCH, "now": NOW}
    arguments.update(overrides)
    return mint_egress_token_v2(SECRET, **arguments)


def _derived_key(secret: str = SECRET) -> bytes:
    return hmac.new(secret.encode(), TOKEN_LABEL, hashlib.sha256).digest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _parts(token: str) -> tuple[str, str]:
    payload, _, signature = token.removeprefix(EGRESS_V2_PREFIX).partition(".")
    return payload, signature


def _signed(payload: str, key: bytes) -> str:
    mac = hmac.new(key, payload.encode(), hashlib.sha256).digest()
    return f"{EGRESS_V2_PREFIX}{payload}.{_b64(mac)}"


def _forged(claims: dict[str, Any], key: bytes | None = None) -> str:
    """A token with arbitrary claims and a genuine signature over them."""
    payload = _b64(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    return _signed(payload, _derived_key() if key is None else key)


def _claims(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "v": 2,
        "sbx": SANDBOX,
        "ep": EPOCH,
        "iat": int(NOW.timestamp()),
        "exp": int(NOW.timestamp()) + 3600,
    }
    base.update(overrides)
    return base


def _swap_char(token: str, index: int) -> str:
    replacement = "A" if token[index] != "A" else "B"
    return token[:index] + replacement + token[index + 1 :]


def _assert_refused(token: str, now: datetime = NOW, max_lifetime_s: int | None = None) -> None:
    with pytest.raises(InvalidEgressToken) as raised:
        verify_egress_token_v2(SECRET, token, now, max_lifetime_s)
    assert str(raised.value) == INVALID_EGRESS_MESSAGE


# ---- mint and verify ----------------------------------------------------------------------


def test_roundtrip_returns_the_minted_claims() -> None:
    claims = verify_egress_token_v2(SECRET, _mint(ttl_s=900), NOW)

    assert claims == EgressClaimsV2(
        sandbox_id=SANDBOX,
        epoch=EPOCH,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=900),
    )


def test_token_starts_with_sfe2_prefix() -> None:
    assert EGRESS_V2_PREFIX == "sfe2_"
    assert _mint().startswith("sfe2_")


def test_payload_is_exactly_the_five_claims_in_canonical_form() -> None:
    token = _mint(ttl_s=900)
    payload, signature = _parts(token)

    decoded = json.loads(_unb64(payload))

    iat = int(NOW.timestamp())
    assert decoded == {"v": 2, "sbx": SANDBOX, "ep": EPOCH, "iat": iat, "exp": iat + 900}
    assert set(decoded) == {"v", "sbx", "ep", "iat", "exp"}
    assert _unb64(payload) == json.dumps(decoded, separators=(",", ":"), sort_keys=True).encode()
    assert "=" not in token
    assert _b64(_unb64(payload)) == payload
    assert _b64(_unb64(signature)) == signature


def test_signature_is_the_hmac_under_the_derived_key() -> None:
    payload, signature = _parts(_mint())

    expected = hmac.new(_derived_key(), payload.encode(), hashlib.sha256).digest()

    assert _unb64(signature) == expected
    assert token_v2_key(SECRET) == _derived_key()


def test_signature_does_not_verify_under_the_raw_secret() -> None:
    payload, signature = _parts(_mint())

    under_raw = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).digest()

    assert _unb64(signature) != under_raw


def test_a_v1_style_signature_over_the_same_payload_is_refused() -> None:
    payload, _ = _parts(_mint())

    _assert_refused(_signed(payload, SECRET.encode()))


def test_default_ttl_is_the_egress_token_ttl() -> None:
    claims = verify_egress_token_v2(SECRET, _mint(), NOW)

    assert claims.expires_at - claims.issued_at == timedelta(seconds=EGRESS_TOKEN_TTL_S)


def test_wrong_secret_is_refused() -> None:
    with pytest.raises(InvalidEgressToken):
        verify_egress_token_v2("another-secret", _mint(), NOW)


def test_empty_secret_is_refused() -> None:
    with pytest.raises(InvalidEgressToken):
        verify_egress_token_v2("", _mint(), NOW)


# ---- expiry and lifetime cap --------------------------------------------------------------


def test_expired_token_is_refused_at_and_after_expiry() -> None:
    token = _mint(ttl_s=60)

    verify_egress_token_v2(SECRET, token, NOW + timedelta(seconds=59))
    _assert_refused(token, NOW + timedelta(seconds=60))
    _assert_refused(token, NOW + timedelta(days=1))


def test_lifetime_over_the_cap_is_refused() -> None:
    token = _mint(ttl_s=3600)

    verify_egress_token_v2(SECRET, token, NOW, 3600)
    _assert_refused(token, NOW, 3599)


# ---- K2: the two verifiers keep apart -----------------------------------------------------


def test_v2_token_given_to_the_v1_verifier_is_refused() -> None:
    with pytest.raises(InvalidEgressToken) as raised:
        verify_egress_token(SECRET, _mint(), NOW)
    assert str(raised.value) == INVALID_EGRESS_MESSAGE


def test_v1_token_given_to_the_v2_verifier_is_refused() -> None:
    v1 = mint_egress_token(SECRET, sandbox_id=SANDBOX, allowlist=["a.test"], now=NOW)

    assert v1.startswith("sfe_")
    _assert_refused(v1)


def test_token_without_the_prefix_is_refused() -> None:
    _assert_refused(_mint().removeprefix(EGRESS_V2_PREFIX))


# ---- tampering ----------------------------------------------------------------------------


def test_tampered_payload_character_is_refused() -> None:
    token = _mint()
    index = len(EGRESS_V2_PREFIX) + len(_parts(token)[0]) // 2

    _assert_refused(_swap_char(token, index))


def test_tampered_signature_character_is_refused() -> None:
    token = _mint()
    signature_start = token.index(".") + 1
    middle = signature_start + (len(token) - signature_start) // 2

    _assert_refused(_swap_char(token, middle))


def test_forged_payload_with_a_genuine_signature_is_refused() -> None:
    forged_payload = _parts(_forged(_claims(sbx="sbx_other", ep=99), key=b"attacker-key"))[0]
    genuine_signature = _parts(_mint())[1]

    _assert_refused(f"{EGRESS_V2_PREFIX}{forged_payload}.{genuine_signature}")


def test_a_genuine_forgery_helper_token_does_verify() -> None:
    # guards the helpers: a token built by hand under the derived key is accepted
    claims = verify_egress_token_v2(SECRET, _forged(_claims()), NOW)

    assert (claims.sandbox_id, claims.epoch) == (SANDBOX, EPOCH)


# ---- non-canonical spellings --------------------------------------------------------------


def test_non_canonical_signature_spelling_is_refused() -> None:
    payload, signature = _parts(_mint())
    # 32 bytes encode to 43 characters whose last one carries two unused bits; set one of them
    last = B64URL_ALPHABET.index(signature[-1])
    assert last % 4 == 0
    sloppy = signature[:-1] + B64URL_ALPHABET[last + 1]
    assert _unb64(sloppy) == _unb64(signature)  # same bytes, other spelling

    _assert_refused(f"{EGRESS_V2_PREFIX}{payload}.{sloppy}")


def test_non_canonical_payload_spelling_is_refused_even_when_signed() -> None:
    for index in range(40):
        payload, _ = _parts(_mint(sandbox_id=f"sbx_{'x' * index}"))
        if len(payload) % 4 in (2, 3):
            break
    last = B64URL_ALPHABET.index(payload[-1])
    sloppy = payload[:-1] + B64URL_ALPHABET[last ^ 1]
    assert _unb64(sloppy) == _unb64(payload)

    _assert_refused(_signed(sloppy, _derived_key()))


def test_padding_and_standard_alphabet_are_refused() -> None:
    payload, signature = _parts(_mint())

    _assert_refused(f"{EGRESS_V2_PREFIX}{payload}=.{signature}")
    _assert_refused(f"{EGRESS_V2_PREFIX}{payload}.{signature}=")
    _assert_refused(f"{EGRESS_V2_PREFIX}{payload}.{signature[:-3]}+/A")


def test_malformed_shapes_are_refused() -> None:
    payload, signature = _parts(_mint())

    for token in (
        EGRESS_V2_PREFIX,
        f"{EGRESS_V2_PREFIX}{payload}",
        f"{EGRESS_V2_PREFIX}{payload}.{signature}.{signature}",
        f"{EGRESS_V2_PREFIX}.{signature}",
        f"{EGRESS_V2_PREFIX}{payload}.",
        "",
    ):
        _assert_refused(token)


# ---- claim validation (genuinely signed, bad claims) --------------------------------------


def test_bool_epoch_is_refused() -> None:
    _assert_refused(_forged(_claims(ep=True)))


@pytest.mark.parametrize(
    "overrides",
    [
        {"v": 1},
        {"v": 3},
        {"v": True},
        {"v": "2"},
        {"sbx": ""},
        {"sbx": 7},
        {"ep": -1},
        {"ep": "1"},
        {"ep": 1.5},
        {"iat": True},
        {"iat": "0"},
        {"exp": 1.5},
    ],
)
def test_bad_claim_types_are_refused(overrides: dict[str, Any]) -> None:
    _assert_refused(_forged(_claims(**overrides)))


@pytest.mark.parametrize("missing", ["v", "sbx", "ep", "iat", "exp"])
def test_missing_claim_is_refused(missing: str) -> None:
    claims = _claims()
    del claims[missing]

    _assert_refused(_forged(claims))


def test_non_object_payload_is_refused() -> None:
    payload = _b64(b"[1,2,3]")

    _assert_refused(_signed(payload, _derived_key()))
    _assert_refused(_signed(_b64(b"not json"), _derived_key()))
