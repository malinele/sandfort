"""Wire format of the internal egress policy route (docs/egress-v2-design.md section 3.6).

Expected MACs and keys are recomputed here with ``hmac``/``hashlib`` from the documented labels
and message layouts; nothing is taken from the code under test. Hermetic, no I/O.
"""

import base64
import hashlib
import hmac
import json
import re
from typing import Any

import pytest

from sandfort.egress import policy_wire
from sandfort.egress.policy_wire import (
    AUTH_HEADER,
    MAC_WINDOW_S,
    MAX_POLICY_IDS,
    POLICY_PATH,
    SIGNATURE_HEADER,
    PolicyRecord,
    encode_policy_request,
    parse_policy_response,
    request_key,
    response_key,
    sign_request,
    sign_response,
    token_v2_key,
    verify_request,
    verify_response,
)

SECRET = "test-egress-secret-wire"
NOW = 1_795_000_000
TOKEN_LABEL = "sandfort/egress/token/v2"
REQUEST_LABEL = "sandfort/egress/policy/request/v1"
RESPONSE_LABEL = "sandfort/egress/policy/response/v1"
HEADER_SHAPE = re.compile(r"t=(\d+),s=([A-Za-z0-9_-]+)")
B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _derive(label: str, secret: str = SECRET) -> bytes:
    return hmac.new(secret.encode(), label.encode(), hashlib.sha256).digest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _hex_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _header(key: bytes, stamp: int, request_body: bytes, body: bytes) -> str:
    """A response header built by hand: MAC over the request and response body digests.

    The message is ``"<t>\\n<hex sha256 of request body>\\n<hex sha256 of response body>"``.
    """
    message = f"{stamp}\n{_hex_digest(request_body)}\n{_hex_digest(body)}"
    mac = hmac.new(key, message.encode(), hashlib.sha256).digest()
    return f"t={stamp},s={_b64(mac)}"


def _body(*records: dict[str, Any], issued_at: int = NOW) -> bytes:
    return json.dumps({"issued_at": issued_at, "policies": list(records)}).encode()


FOUND = {
    "sandbox_id": "sbx_1",
    "found": True,
    "generation": 4,
    "epoch": 1,
    "rules": ["api.example.com", "198.51.100.0/24"],
}
MISSING = {"sandbox_id": "sbx_2", "found": False}
NONCE = "AAAAAAAAAAAAAAAAAAAAAA"
REQUEST = encode_policy_request(["sbx_1", "sbx_2"], NONCE)


# ---- derived keys and constants -----------------------------------------------------------


def test_each_key_is_the_hmac_of_its_exact_label() -> None:
    assert token_v2_key(SECRET) == _derive(TOKEN_LABEL)
    assert request_key(SECRET) == _derive(REQUEST_LABEL)
    assert response_key(SECRET) == _derive(RESPONSE_LABEL)


def test_label_constants_are_the_documented_strings() -> None:
    assert policy_wire.TOKEN_V2_LABEL == TOKEN_LABEL
    assert policy_wire.REQUEST_LABEL == REQUEST_LABEL
    assert policy_wire.RESPONSE_LABEL == RESPONSE_LABEL


def test_the_three_keys_differ_from_each_other_and_from_the_raw_secret() -> None:
    keys = [token_v2_key(SECRET), request_key(SECRET), response_key(SECRET), SECRET.encode()]

    assert len(set(keys)) == 4
    assert all(len(key) == 32 for key in keys[:3])


def test_keys_depend_on_the_secret() -> None:
    assert request_key("another-secret") != request_key(SECRET)
    assert request_key("another-secret") == _derive(REQUEST_LABEL, "another-secret")


def test_route_constants() -> None:
    assert POLICY_PATH == "/internal/egress/v1/policies"
    assert MAX_POLICY_IDS == 256
    assert AUTH_HEADER == "X-Sandfort-Egress-Auth"
    assert SIGNATURE_HEADER == "X-Sandfort-Egress-Signature"
    assert MAC_WINDOW_S == 30


# ---- request body and request MAC ---------------------------------------------------------


def test_encode_policy_request_carries_exactly_the_ids() -> None:
    body = encode_policy_request(["sbx_1", "sbx_2"], NONCE)

    assert json.loads(body) == {"nonce": NONCE, "sandbox_ids": ["sbx_1", "sbx_2"]}
    assert body == f'{{"nonce":"{NONCE}","sandbox_ids":["sbx_1","sbx_2"]}}'.encode()


def test_encode_policy_request_accepts_the_bounds() -> None:
    one = encode_policy_request(["sbx_1"], NONCE)
    top = encode_policy_request([f"sbx_{n}" for n in range(MAX_POLICY_IDS)], NONCE)

    assert json.loads(one) == {"nonce": NONCE, "sandbox_ids": ["sbx_1"]}
    assert len(json.loads(top)["sandbox_ids"]) == 256


@pytest.mark.parametrize("count", [0, 257])
def test_encode_policy_request_refuses_counts_outside_one_to_256(count: int) -> None:
    with pytest.raises(ValueError):
        encode_policy_request([f"sbx_{n}" for n in range(count)], NONCE)


@pytest.mark.parametrize("nonce", ["", "a b", "a+b", "a=", "x" * 65, "nonce\n", "n\u00f6nce"])
def test_encode_policy_request_refuses_a_nonce_that_is_not_short_base64url(nonce: str) -> None:
    with pytest.raises(ValueError):
        encode_policy_request(["sbx_1"], nonce)


def test_encode_policy_request_accepts_a_nonce_of_64_characters() -> None:
    body = encode_policy_request(["sbx_1"], "x" * 64)

    assert json.loads(body)["nonce"] == "x" * 64


def test_sign_request_header_shape_and_mac() -> None:
    body = encode_policy_request(["sbx_1", "sbx_2"], NONCE)
    key = request_key(SECRET)

    header = sign_request(key, body, NOW)

    match = HEADER_SHAPE.fullmatch(header)
    assert match is not None
    assert int(match.group(1)) == NOW
    assert "=" not in match.group(2)
    message = f"POST\n/internal/egress/v1/policies\n{NOW}\n{_hex_digest(body)}"
    expected = hmac.new(_derive(REQUEST_LABEL), message.encode(), hashlib.sha256).digest()
    assert _unb64(match.group(2)) == expected
    assert header == f"t={NOW},s={_b64(expected)}"


def test_sign_request_mac_covers_body_time_and_key() -> None:
    key = request_key(SECRET)
    body = encode_policy_request(["sbx_1"], NONCE)
    header = sign_request(key, body, NOW)

    assert sign_request(key, encode_policy_request(["sbx_2"], NONCE), NOW) != header
    assert sign_request(key, body, NOW + 1).split(",s=")[1] != header.split(",s=")[1]
    assert sign_request(response_key(SECRET), body, NOW) != header


# ---- response signature -------------------------------------------------------------------


def test_sign_response_matches_the_documented_mac() -> None:
    body = _body(FOUND)

    assert sign_response(response_key(SECRET), REQUEST, body, NOW) == _header(
        _derive(RESPONSE_LABEL), NOW, REQUEST, body
    )


def test_sign_and_verify_roundtrip() -> None:
    key = response_key(SECRET)
    body = _body(FOUND, MISSING)

    assert verify_response(key, sign_response(key, REQUEST, body, NOW), REQUEST, body, NOW) is True
    header = _header(_derive(RESPONSE_LABEL), NOW, REQUEST, body)
    assert verify_response(key, header, REQUEST, body, NOW) is True


def test_a_signature_for_one_request_is_refused_for_another_request() -> None:
    key = response_key(SECRET)
    body = _body(FOUND)
    header = sign_response(key, encode_policy_request(["sbx_1"], NONCE), body, NOW)

    assert verify_response(key, header, encode_policy_request(["sbx_1"], NONCE), body, NOW) is True
    assert verify_response(key, header, encode_policy_request(["sbx_2"], NONCE), body, NOW) is False
    assert verify_response(key, header, b"", body, NOW) is False


def test_a_captured_response_cannot_be_replayed_against_a_new_request_for_the_same_ids() -> None:
    key = response_key(SECRET)
    request_a = encode_policy_request(["sbx_1"], "nonce-a")
    request_b = encode_policy_request(["sbx_1"], "nonce-b")  # same ids, fresh nonce
    body = _body(FOUND)
    captured = sign_response(key, request_a, body, NOW)  # a pre-PATCH answer, say

    assert request_a != request_b
    assert verify_response(key, captured, request_a, body, NOW) is True
    assert verify_response(key, captured, request_b, body, NOW) is False


def test_issued_at_differing_from_the_header_timestamp_is_refused() -> None:
    key = response_key(SECRET)
    body = _body(FOUND, issued_at=NOW - 5)  # correctly signed at NOW, but the body says NOW - 5

    assert verify_response(key, sign_response(key, REQUEST, body, NOW), REQUEST, body, NOW) is False
    assert verify_response(key, sign_response(key, REQUEST, body, NOW - 5), REQUEST, body, NOW)


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"",
        b"[]",
        b'{"policies": []}',
        b'{"issued_at": "1795000000", "policies": []}',
        b'{"issued_at": true, "policies": []}',
    ],
)
def test_a_signed_body_without_an_integer_issued_at_is_refused(body: bytes) -> None:
    key = response_key(SECRET)

    assert verify_response(key, sign_response(key, REQUEST, body, NOW), REQUEST, body, NOW) is False


# ---- header freshness --------------------------------------------------------------------


def test_header_is_fresh_for_a_well_formed_header_inside_the_window() -> None:
    header = sign_request(request_key(SECRET), REQUEST, NOW)

    assert policy_wire.header_is_fresh(header, NOW) is True
    assert policy_wire.header_is_fresh(header, NOW + MAC_WINDOW_S) is True
    assert policy_wire.header_is_fresh(header, NOW - MAC_WINDOW_S) is True


def test_header_is_fresh_refuses_stale_future_missing_and_malformed_headers() -> None:
    header = sign_request(request_key(SECRET), REQUEST, NOW)

    assert policy_wire.header_is_fresh(header, NOW + MAC_WINDOW_S + 1) is False
    assert policy_wire.header_is_fresh(header, NOW - MAC_WINDOW_S - 1) is False
    for bad in (None, "", "garbage", "t=abc,s=AAAA", f"t={NOW},s=", f"t={NOW},s=a+b"):
        assert policy_wire.header_is_fresh(bad, NOW) is False


# ---- request verification -----------------------------------------------------------------


def test_verify_request_roundtrips_against_sign_request() -> None:
    key = request_key(SECRET)
    body = encode_policy_request(["sbx_1", "sbx_2"], NONCE)

    assert verify_request(key, sign_request(key, body, NOW), body, NOW) is True


def test_verify_request_refuses_a_missing_header() -> None:
    assert verify_request(request_key(SECRET), None, REQUEST, NOW) is False


@pytest.mark.parametrize(
    "header", ["", "garbage", "t=abc,s=AAAA", "t=1795000000,s=", "t=-5,s=AAAA"]
)
def test_verify_request_refuses_a_malformed_header_without_raising(header: str) -> None:
    assert verify_request(request_key(SECRET), header, REQUEST, NOW) is False


def test_verify_request_refuses_a_mac_under_the_wrong_key() -> None:
    for wrong in (response_key(SECRET), token_v2_key(SECRET), SECRET.encode(), request_key("x")):
        header = sign_request(wrong, REQUEST, NOW)
        assert verify_request(request_key(SECRET), header, REQUEST, NOW) is False


def test_verify_request_refuses_a_tampered_body() -> None:
    key = request_key(SECRET)
    header = sign_request(key, REQUEST, NOW)

    assert verify_request(key, header, encode_policy_request(["sbx_3"], NONCE), NOW) is False
    assert verify_request(key, header, REQUEST + b" ", NOW) is False


def test_verify_request_freshness_is_thirty_seconds_either_way() -> None:
    key = request_key(SECRET)

    def verdict(age: int) -> bool:
        return verify_request(key, sign_request(key, REQUEST, NOW - age), REQUEST, NOW)

    assert verdict(29) is True
    assert verdict(30) is True
    assert verdict(31) is False
    assert verdict(-31) is False


def test_verify_uses_a_constant_time_compare(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    real = hmac.compare_digest

    def spy(left: Any, right: Any) -> bool:
        calls.append(1)
        return real(left, right)

    monkeypatch.setattr(policy_wire.hmac, "compare_digest", spy)
    key = response_key(SECRET)
    body = _body(FOUND)

    assert verify_response(key, sign_response(key, REQUEST, body, NOW), REQUEST, body, NOW)
    assert calls


def test_missing_header_is_refused() -> None:
    assert verify_response(response_key(SECRET), None, REQUEST, _body(FOUND), NOW) is False


@pytest.mark.parametrize(
    "header",
    [
        "",
        "garbage",
        "t=abc,s=AAAA",
        "t=,s=AAAA",
        "s=AAAA,t=1795000000",
        "t=1795000000",
        "t=1795000000,s=",
        "t=1795000000,s=!!!!",
        "t=1795000000,s=AA==",
        "t=1795000000,s=a+b/",
        "t=-5,s=AAAA",
    ],
)
def test_malformed_header_is_refused_without_raising(header: str) -> None:
    assert verify_response(response_key(SECRET), header, REQUEST, _body(FOUND), NOW) is False


def test_non_canonical_signature_spelling_is_refused() -> None:
    key = response_key(SECRET)
    body = _body(FOUND)
    _, _, mac = sign_response(key, REQUEST, body, NOW).partition(",s=")
    last = B64URL_ALPHABET.index(mac[-1])
    sloppy = mac[:-1] + B64URL_ALPHABET[last ^ 1]  # same bytes, trailing bit set
    assert _unb64(sloppy) == _unb64(mac)

    assert verify_response(key, f"t={NOW},s={sloppy}", REQUEST, body, NOW) is False


def test_mac_under_the_wrong_key_is_refused() -> None:
    body = _body(FOUND)

    for wrong in (
        request_key(SECRET),
        token_v2_key(SECRET),
        SECRET.encode(),
        response_key("other"),
    ):
        header = sign_response(wrong, REQUEST, body, NOW)
        assert verify_response(response_key(SECRET), header, REQUEST, body, NOW) is False


def test_tampered_body_is_refused() -> None:
    key = response_key(SECRET)
    body = _body(FOUND)
    header = sign_response(key, REQUEST, body, NOW)

    tampered = body.replace(b"api.example.com", b"evil.example.com")
    assert verify_response(key, header, REQUEST, tampered, NOW) is False
    assert verify_response(key, header, REQUEST, body + b" ", NOW) is False


def test_tampered_timestamp_is_refused() -> None:
    key = response_key(SECRET)
    body = _body(FOUND)
    header = sign_response(key, REQUEST, body, NOW)
    _, _, mac = header.partition(",s=")

    assert verify_response(key, f"t={NOW + 1},s={mac}", REQUEST, body, NOW) is False


def test_freshness_window_is_thirty_seconds_either_way() -> None:
    key = response_key(SECRET)

    def verdict(age: int) -> bool:
        body = _body(FOUND, issued_at=NOW - age)  # issued_at must equal the signature t
        header = sign_response(key, REQUEST, body, NOW - age)
        return verify_response(key, header, REQUEST, body, NOW)

    assert verdict(29) is True  # U7 at wire level
    assert verdict(30) is True
    assert verdict(31) is False
    assert verdict(-29) is True
    assert verdict(-31) is False


# ---- response parsing ---------------------------------------------------------------------


def test_parse_returns_issued_at_and_records_by_sandbox_id() -> None:
    issued_at, records = parse_policy_response(_body(FOUND, MISSING))

    assert issued_at == NOW
    assert set(records) == {"sbx_1", "sbx_2"}
    assert records["sbx_1"] == PolicyRecord(
        sandbox_id="sbx_1",
        found=True,
        generation=4,
        epoch=1,
        rules=("api.example.com", "198.51.100.0/24"),
    )


def test_parse_found_false_record_has_no_generation_epoch_or_rules() -> None:
    _, records = parse_policy_response(_body(MISSING))

    assert records["sbx_2"] == PolicyRecord(sandbox_id="sbx_2", found=False)
    assert records["sbx_2"].generation == 0
    assert records["sbx_2"].epoch == 0
    assert records["sbx_2"].rules == ()


def test_parse_ignores_unknown_fields() -> None:
    record = {**FOUND, "future": {"x": 1}}
    body = json.dumps({"issued_at": NOW, "policies": [record], "extra": True}).encode()

    _, records = parse_policy_response(body)

    assert records["sbx_1"] == parse_policy_response(_body(FOUND))[1]["sbx_1"]


def test_parse_accepts_an_empty_rule_list() -> None:
    _, records = parse_policy_response(_body({**FOUND, "rules": []}))

    assert records["sbx_1"].found is True
    assert records["sbx_1"].rules == ()


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not json",
        b"\xff\xfe",
        b"[]",
        b'"policies"',
        b'{"issued_at": 1}',
        b'{"issued_at": 1, "policies": {"sbx_1": {}}}',
        b'{"issued_at": 1, "policies": "none"}',
        b'{"policies": []}',
        b'{"issued_at": true, "policies": []}',
        b'{"issued_at": 1, "policies": ["sbx_1"]}',
        b'{"issued_at": 1, "policies": [{"found": true}]}',
        b'{"issued_at": 1, "policies": [{"sandbox_id": "sbx_1"}]}',
        b'{"issued_at": 1, "policies": [{"sandbox_id": "sbx_1", "found": "yes"}]}',
        b'{"issued_at": 1, "policies": [{"sandbox_id": "sbx_1", "found": true}]}',
        b'{"issued_at": 1, "policies": [{"sandbox_id": "sbx_1", "found": true, '
        b'"generation": true, "epoch": 1, "rules": []}]}',
        b'{"issued_at": 1, "policies": [{"sandbox_id": "sbx_1", "found": true, '
        b'"generation": 1, "epoch": 1, "rules": "a.test"}]}',
        b'{"issued_at": 1, "policies": [{"sandbox_id": "sbx_1", "found": true, '
        b'"generation": 1, "epoch": 1, "rules": [1]}]}',
    ],
)
def test_parse_raises_on_malformed_bodies(body: bytes) -> None:
    with pytest.raises(ValueError):
        parse_policy_response(body)
