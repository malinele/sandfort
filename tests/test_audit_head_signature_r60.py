"""Auditor-verifiable Ed25519 signature on the audit head (round 60).

``SANDFORT_AUDIT_SIGNING_KEY`` (raw 32 bytes in urlsafe base64, or a PEM block) adds ``alg``,
``public_key``, ``signed_at`` and ``signature`` to the ``audit_head`` line next to the HMAC. The
public key is exposed on ``GET /v1/status`` (``audit_public_key``), so an auditor can check a
head without any secret. The REST export and the operator ``audit-export`` carry the signature.

Review fix: the signer comes from ``Settings`` only (never the process environment), the key
is validated when ``Settings`` is built, and the leaf lives in ``sandfort.audit_signing`` so
``sandfort.config`` does not import ``sandfort.services``.
"""

import ast
import base64
import json
import sys
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi import FastAPI

from sandfort import admin_cli, audit_signing
from sandfort.api.app import create_app
from sandfort.api.routes import health
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services import audit_head_signing
from sandfort.services.audit_chain_head import (
    HEAD_TYPE,
    HeadSignatureError,
    parse_heads,
    sign_head,
    verify_head_signature,
)

ROOT = Path(__file__).resolve().parents[1]
PEPPER = "test-pepper"
EXPORT = "/v1/audit-events/export"
KEYS = "/v1/api-keys"
SIGN_ENV = "SANDFORT_AUDIT_SIGNING_KEY"
CHAIN_ENV = "SANDFORT_AUDIT_CHAIN_KEY"
CHAIN_KEY = "c" * 40
MAC_KEY = b"k" * 32
ORG = "org_test"
ROW = "aud_00000000000000000007"
HASH = "ab" * 32
SCOPES = [Scope.API_KEYS_ADMIN.value, Scope.AUDIT_READ.value]
MINTED = 3
SIGNED_FIELDS = {"alg", "public_key", "signature", "signed_at"}
SIGNED_AT = datetime(2026, 11, 11, 4, 52, 33, tzinfo=UTC)
# The key of the signing REST app (parametrized by value, so it exists at import time).
APP_KEY = Ed25519PrivateKey.generate()


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode()


def raw_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def pem_private(key: Ed25519PrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def signer_of(key: Ed25519PrivateKey) -> audit_signing.HeadSigner:
    found = Settings(audit_signing_key=b64(raw_private(key))).audit_signer()
    assert found is not None
    return found


@pytest.fixture
def private() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def signing_key(private: Ed25519PrivateKey) -> Ed25519PrivateKey:
    """The private key the head helpers below sign with (through Settings, not the env)."""
    return private


def head_record(line: str) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(line)
    return record


def forged(line: str, **changes: object) -> str:
    return json.dumps({**head_record(line), **changes}, sort_keys=True, separators=(",", ":"))


def signed_line(
    key: Ed25519PrivateKey | None = None, signed_at: datetime | None = None
) -> str:
    signer = None if key is None else signer_of(key)
    return sign_head(MAC_KEY, ORG, ROW, HASH, signer, signed_at).to_line()


# --- setting parsing -------------------------------------------------------------------------


def test_default_is_unset() -> None:
    assert Settings().audit_signing_key == ""
    assert Settings.from_env({}).audit_signing_key == ""
    assert Settings.from_env({SIGN_ENV: "   "}).audit_signing_key == ""


def test_raw_urlsafe_base64_key_is_accepted(private: Ed25519PrivateKey) -> None:
    text = b64(raw_private(private))

    settings = Settings.from_env({SIGN_ENV: f" {text} "})

    assert settings.audit_signing_key == text


def test_unpadded_base64_key_is_accepted(private: Ed25519PrivateKey) -> None:
    text = b64(raw_private(private)).rstrip("=")

    assert Settings.from_env({SIGN_ENV: text}).audit_signing_key == text


def test_pem_key_is_accepted(private: Ed25519PrivateKey) -> None:
    settings = Settings.from_env({SIGN_ENV: pem_private(private)})

    assert "BEGIN PRIVATE KEY" in settings.audit_signing_key


def test_pem_with_escaped_newlines_is_accepted(private: Ed25519PrivateKey) -> None:
    escaped = pem_private(private).strip().replace("\n", "\\n")

    assert Settings.from_env({SIGN_ENV: escaped}).audit_signing_key == escaped


def test_raw_and_pem_forms_derive_the_same_public_key(private: Ed25519PrivateKey) -> None:
    keys: list[str] = []
    for text in (b64(raw_private(private)), pem_private(private)):
        signer = Settings.from_env({SIGN_ENV: text}).audit_signer()
        line = sign_head(MAC_KEY, ORG, ROW, HASH, signer).to_line()
        keys.append(head_record(line)["public_key"])

    assert keys[0] == keys[1] == b64(raw_public(private))


@pytest.mark.parametrize(
    "bad",
    [
        "not base64 at all!",
        b64(b"short"),
        b64(b"x" * 33),
        "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----",
    ],
)
def test_malformed_key_is_refused_without_echoing_it(bad: str) -> None:
    with pytest.raises(ValueError, match=SIGN_ENV) as caught:
        Settings.from_env({SIGN_ENV: bad})

    assert bad not in str(caught.value)


@pytest.mark.parametrize("bad", ["not base64 at all!", b64(b"x" * 33)])
def test_malformed_key_in_code_built_settings_is_refused_at_load(bad: str) -> None:
    with pytest.raises(ValueError, match=SIGN_ENV) as caught:
        Settings(audit_signing_key=bad)

    assert bad not in str(caught.value)


def test_replace_with_a_malformed_key_is_refused(private: Ed25519PrivateKey) -> None:
    settings = Settings(audit_signing_key=b64(raw_private(private)))

    with pytest.raises(ValueError, match=SIGN_ENV):
        replace(settings, audit_signing_key="nope")


def test_pem_of_another_key_type_is_refused() -> None:
    other = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    with pytest.raises(ValueError, match=SIGN_ENV):
        Settings.from_env({SIGN_ENV: other.decode()})


def test_public_key_pem_is_refused(private: Ed25519PrivateKey) -> None:
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with pytest.raises(ValueError, match=SIGN_ENV):
        Settings.from_env({SIGN_ENV: public_pem.decode()})


def test_settings_signer_is_none_without_a_key() -> None:
    assert Settings().audit_signer() is None
    assert Settings(audit_signing_key="  ").audit_signer() is None


def test_settings_signer_repr_does_not_show_the_key(private: Ed25519PrivateKey) -> None:
    text = b64(raw_private(private))

    assert text not in repr(Settings(audit_signing_key=text).audit_signer())


def test_settings_repr_does_not_show_the_key(private: Ed25519PrivateKey) -> None:
    text = b64(raw_private(private))

    assert text not in repr(Settings(audit_signing_key=text))


# --- the signed head line --------------------------------------------------------------------


def test_head_line_has_no_signature_fields_without_a_key() -> None:
    record = head_record(signed_line())

    assert SIGNED_FIELDS.isdisjoint(record)
    assert record["type"] == HEAD_TYPE
    assert set(record) == {"type", "org_id", "row_id", "hash", "hmac"}


def test_sign_head_ignores_the_environment(
    private: Ed25519PrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(SIGN_ENV, b64(raw_private(private)))

    record = head_record(sign_head(MAC_KEY, ORG, ROW, HASH).to_line())

    assert SIGNED_FIELDS.isdisjoint(record)


def test_head_line_gains_alg_public_key_and_signature(signing_key: Ed25519PrivateKey) -> None:
    record = head_record(signed_line(signing_key))

    assert record["alg"] == "ed25519"
    assert record["public_key"] == b64(raw_public(signing_key))
    assert len(base64.urlsafe_b64decode(record["signature"])) == 64
    assert {"type", "org_id", "row_id", "hash", "hmac"} <= set(record)


def test_mac_is_unchanged_by_the_signature(signing_key: Ed25519PrivateKey) -> None:
    signed = sign_head(MAC_KEY, ORG, ROW, HASH, signer_of(signing_key))
    plain = sign_head(MAC_KEY, ORG, ROW, HASH)

    assert signed.mac == plain.mac
    assert signed.valid(MAC_KEY)
    assert not signed.valid(b"o" * 32)


def test_parse_heads_round_trips_the_signature_fields(signing_key: Ed25519PrivateKey) -> None:
    head = sign_head(MAC_KEY, ORG, ROW, HASH, signer_of(signing_key))

    (parsed,) = parse_heads([head.to_line()])

    assert parsed == head
    assert parsed.signature is not None
    assert parsed.signed_at is not None
    assert parsed.valid(MAC_KEY)


@pytest.mark.parametrize("dropped", ["alg", "public_key", "signature"])
def test_parse_heads_rejects_a_partial_signature_block(
    signing_key: Ed25519PrivateKey, dropped: str
) -> None:
    record = head_record(signed_line(signing_key))
    del record[dropped]

    with pytest.raises(ValueError, match="signature"):
        parse_heads([json.dumps(record)])


def legacy_line(key: Ed25519PrivateKey) -> str:
    """A head as beta.60 to beta.64 exported it: alg, public_key and signature, no signed_at."""
    record = head_record(signed_line(key))
    del record["signed_at"], record["signature"]
    record["signature"] = b64(key.sign(audit_signing.canonical_payload(record)))
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def test_parse_heads_accepts_the_legacy_three_field_signature_block(
    signing_key: Ed25519PrivateKey,
) -> None:
    line = legacy_line(signing_key)

    (parsed,) = parse_heads([line])

    assert parsed.signed_at is None
    assert (parsed.alg, parsed.public_key) == ("ed25519", b64(raw_public(signing_key)))
    assert parsed.signature == head_record(line)["signature"]
    assert parsed.valid(MAC_KEY)
    assert parsed.to_line() == line  # re-written without a signed_at it never had


def test_parse_heads_rejects_signed_at_without_the_rest_of_the_block(
    signing_key: Ed25519PrivateKey,
) -> None:
    record = head_record(signed_line(signing_key))
    del record["alg"], record["public_key"], record["signature"]

    with pytest.raises(ValueError, match="signature"):
        parse_heads([json.dumps(record)])


def test_parse_heads_rejects_an_empty_signed_at(signing_key: Ed25519PrivateKey) -> None:
    record = {**head_record(signed_line(signing_key)), "signed_at": ""}

    with pytest.raises(ValueError, match="signature"):
        parse_heads([json.dumps(record)])


def test_legacy_head_verifies_as_undated(signing_key: Ed25519PrivateKey) -> None:
    claim = verify_head_signature(legacy_line(signing_key), raw_public(signing_key))

    assert claim.signed_at is None
    assert (claim.org_id, claim.row_id, claim.entry_hash) == (ORG, ROW, HASH)


def test_legacy_head_with_a_bad_signature_still_fails(signing_key: Ed25519PrivateKey) -> None:
    line = forged(legacy_line(signing_key), row_id="aud_00000000000000000008")

    with pytest.raises(HeadSignatureError):
        verify_head_signature(line, raw_public(signing_key))


# --- signed_at -------------------------------------------------------------------------------


def test_signed_head_carries_signed_at_in_utc(signing_key: Ed25519PrivateKey) -> None:
    before = datetime.now(UTC).replace(microsecond=0)

    record = head_record(signed_line(signing_key))

    stamped = datetime.fromisoformat(record["signed_at"])
    assert stamped.utcoffset() == timedelta(0)
    assert before <= stamped <= datetime.now(UTC)


def test_signed_at_may_be_given(signing_key: Ed25519PrivateKey) -> None:
    record = head_record(signed_line(signing_key, SIGNED_AT))

    assert datetime.fromisoformat(record["signed_at"]) == SIGNED_AT


def test_verification_returns_signed_at(signing_key: Ed25519PrivateKey) -> None:
    claim = verify_head_signature(signed_line(signing_key, SIGNED_AT), raw_public(signing_key))

    assert claim.signed_at == SIGNED_AT


def test_signed_at_is_covered_by_the_signature(signing_key: Ed25519PrivateKey) -> None:
    newer = (SIGNED_AT + timedelta(days=1)).isoformat()
    line = forged(signed_line(signing_key, SIGNED_AT), signed_at=newer)

    with pytest.raises(HeadSignatureError):
        verify_head_signature(line, raw_public(signing_key))


def test_signed_at_is_in_the_canonical_payload(signing_key: Ed25519PrivateKey) -> None:
    record = head_record(signed_line(signing_key, SIGNED_AT))

    assert b'"signed_at"' in audit_signing.canonical_payload(record)


def test_dropping_signed_at_from_a_dated_head_breaks_the_signature(
    signing_key: Ed25519PrivateKey,
) -> None:
    record = head_record(signed_line(signing_key))
    del record["signed_at"]  # a downgrade to the legacy shape without re-signing

    with pytest.raises(HeadSignatureError, match="does not verify"):
        verify_head_signature(json.dumps(record), raw_public(signing_key))


def test_signed_head_with_an_empty_signed_at_is_refused(signing_key: Ed25519PrivateKey) -> None:
    line = forged(signed_line(signing_key), signed_at="")

    with pytest.raises(HeadSignatureError):
        verify_head_signature(line, raw_public(signing_key))


def test_naive_signed_at_is_refused(signing_key: Ed25519PrivateKey) -> None:
    with pytest.raises(ValueError, match="UTC"):
        signed_line(signing_key, SIGNED_AT.replace(tzinfo=None))


# --- public verification ---------------------------------------------------------------------


def test_signature_verifies_with_the_derived_public_key(signing_key: Ed25519PrivateKey) -> None:
    claim = verify_head_signature(signed_line(signing_key), raw_public(signing_key))

    assert (claim.row_id, claim.entry_hash, claim.org_id) == (ROW, HASH, ORG)


def test_public_key_may_be_given_as_base64_text(signing_key: Ed25519PrivateKey) -> None:
    claim = verify_head_signature(signed_line(signing_key), b64(raw_public(signing_key)))

    assert claim.row_id == ROW


def test_an_auditor_can_verify_with_nothing_but_the_line_and_cryptography(
    signing_key: Ed25519PrivateKey,
) -> None:
    record = head_record(signed_line(signing_key))
    signature = base64.urlsafe_b64decode(record.pop("signature"))
    record.pop("hmac")
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    public = Ed25519PublicKey.from_public_bytes(raw_public(signing_key))
    public.verify(signature, canonical.encode())


def test_another_public_key_fails(signing_key: Ed25519PrivateKey) -> None:
    other = raw_public(Ed25519PrivateKey.generate())

    with pytest.raises(HeadSignatureError):
        verify_head_signature(signed_line(signing_key), other)


@pytest.mark.parametrize(
    "change",
    [
        {"row_id": "aud_00000000000000000008"},
        {"hash": "cd" * 32},
        {"org_id": "org_other"},
        {"alg": "none"},
    ],
)
def test_tampered_head_fails(signing_key: Ed25519PrivateKey, change: dict[str, str]) -> None:
    line = forged(signed_line(signing_key), **change)

    with pytest.raises(HeadSignatureError):
        verify_head_signature(line, raw_public(signing_key))


def test_head_naming_another_signer_fails_even_with_a_valid_signature(
    signing_key: Ed25519PrivateKey,
) -> None:
    attacker = Ed25519PrivateKey.generate()
    record = head_record(signed_line(signing_key))
    record["public_key"] = b64(raw_public(attacker))
    del record["signature"], record["hmac"]
    body = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    record["signature"] = b64(attacker.sign(body))
    record["hmac"] = "0" * 64

    with pytest.raises(HeadSignatureError):
        verify_head_signature(json.dumps(record), raw_public(signing_key))


def test_a_changed_hmac_does_not_affect_the_signature(signing_key: Ed25519PrivateKey) -> None:
    line = forged(signed_line(signing_key), hmac="0" * 64)

    assert verify_head_signature(line, raw_public(signing_key)).row_id == ROW


def test_unsigned_head_and_garbage_are_refused(signing_key: Ed25519PrivateKey) -> None:
    public = raw_public(signing_key)
    unsigned = signed_line()

    for bad in (unsigned, "not json", json.dumps({"type": "export_summary"}), "[]"):
        with pytest.raises(HeadSignatureError):
            verify_head_signature(bad, public)
    with pytest.raises(HeadSignatureError):
        verify_head_signature(unsigned, b"short")


def test_signature_with_invalid_base64_is_refused(signing_key: Ed25519PrivateKey) -> None:
    line = forged(signed_line(signing_key), signature="@@@")

    with pytest.raises(HeadSignatureError):
        verify_head_signature(line, raw_public(signing_key))


# --- GET /v1/status --------------------------------------------------------------------------


def make_settings(**extra: str) -> Settings:
    return Settings(
        driver="fake",
        database_url="sqlite+aiosqlite:///:memory:",
        api_key_pepper=PEPPER,
        **extra,
    )


def test_status_exposes_the_public_key(
    private: Ed25519PrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)  # status reads the chain key as the export does
    secret = b64(raw_private(private))

    data = health.status_payload(make_settings(audit_signing_key=secret))

    assert data["audit_public_key"] == b64(raw_public(private))
    assert secret not in json.dumps(data)


def test_status_public_key_is_null_with_a_signing_key_but_no_chain_key(
    private: Ed25519PrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(CHAIN_ENV, raising=False)
    secret = b64(raw_private(private))

    data = health.status_payload(make_settings(audit_signing_key=secret))

    assert "audit_public_key" in data
    assert data["audit_public_key"] is None


def test_status_public_key_is_null_when_unset() -> None:
    data = health.status_payload(make_settings())

    assert "audit_public_key" in data
    assert data["audit_public_key"] is None


def test_status_public_key_matches_the_signed_head(
    private: Ed25519PrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    text = pem_private(private)
    published = health.status_payload(make_settings(audit_signing_key=text))["audit_public_key"]

    assert verify_head_signature(signed_line(private), published).entry_hash == HASH


def test_signer_and_status_agree_for_code_built_settings(
    private: Ed25519PrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = Ed25519PrivateKey.generate()
    monkeypatch.setenv(SIGN_ENV, b64(raw_private(other)))
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    settings = make_settings(audit_signing_key=pem_private(private))

    head = sign_head(MAC_KEY, ORG, ROW, HASH, settings.audit_signer()).to_line()
    published = health.status_payload(settings)["audit_public_key"]

    assert published == head_record(head)["public_key"] == b64(raw_public(private))
    assert verify_head_signature(head, published).row_id == ROW
    with pytest.raises(HeadSignatureError):
        verify_head_signature(head, raw_public(other))


def test_status_never_raises_for_a_bad_key() -> None:
    settings = make_settings()
    # Bypass the load-time check to model a corrupted value; the route must still answer.
    object.__setattr__(settings, "audit_signing_key", "not a key")

    assert health.status_payload(settings)["audit_public_key"] is None


# --- exports ---------------------------------------------------------------------------------


@pytest.fixture
async def database(tmp_path: Path) -> str:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'head.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    return url


@pytest.fixture
def app_signing_key() -> str:
    """The signing key of the app's Settings ("" = none); signing tests parametrize it."""
    return ""


SIGNED_APP = pytest.mark.parametrize("app_signing_key", [b64(raw_private(APP_KEY))])


@pytest.fixture
async def app(database: str, app_signing_key: str) -> AsyncIterator[FastAPI]:
    settings = Settings(
        driver="fake",
        database_url=database,
        api_key_pepper=PEPPER,
        audit_signing_key=app_signing_key,
    )
    application = create_app(settings)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as http:
        yield http


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="School", slug="school", created_at=datetime.now(UTC))
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


@pytest.fixture
async def root_key(app: FastAPI, org_id: str) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="root",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset(Scope(value) for value in SCOPES),
        created_at=datetime.now(UTC),
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


async def seeded_export(
    client: httpx.AsyncClient, caller: str, params: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    headers = {"Authorization": f"Bearer {caller}"}
    for index in range(MINTED):
        made = await client.post(
            KEYS, json={"name": f"child-{index}", "scopes": SCOPES}, headers=headers
        )
        assert made.status_code == 201
    response = await client.get(EXPORT, params=params or {}, headers=headers)
    assert response.status_code == 200
    return [json.loads(line) for line in response.text.splitlines() if line.strip()]


@SIGNED_APP
async def test_rest_export_trailer_carries_the_signature(
    client: httpx.AsyncClient,
    root_key: str,
    org_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    # Another key in the environment is ignored: the app's Settings name the signer.
    monkeypatch.setenv(SIGN_ENV, b64(raw_private(Ed25519PrivateKey.generate())))

    *rows, trailer = await seeded_export(client, root_key)

    assert trailer["type"] == HEAD_TYPE
    assert trailer["alg"] == "ed25519"
    assert trailer["public_key"] == b64(raw_public(APP_KEY))
    assert datetime.fromisoformat(trailer["signed_at"]).utcoffset() == timedelta(0)
    claim = verify_head_signature(json.dumps(trailer), raw_public(APP_KEY))
    assert claim.org_id == org_id
    assert claim.row_id == rows[-1]["id"]
    assert claim.entry_hash == rows[-1]["hash"]
    (parsed,) = parse_heads([json.dumps(trailer)])
    assert parsed.valid(CHAIN_KEY.encode())


@SIGNED_APP
async def test_rest_export_signer_matches_the_status_route(
    client: httpx.AsyncClient, root_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)

    *_, trailer = await seeded_export(client, root_key)
    status = await client.get("/v1/status")

    assert status.status_code == 200
    published = status.json()["data"]["audit_public_key"]
    assert published == trailer["public_key"]
    assert verify_head_signature(json.dumps(trailer), published).signed_at is not None


@SIGNED_APP
async def test_exported_rows_relink_up_to_the_signed_head(
    client: httpx.AsyncClient,
    root_key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)

    *rows, trailer = await seeded_export(client, root_key)
    claim = verify_head_signature(json.dumps(trailer), raw_public(APP_KEY))

    assert len(rows) == MINTED
    for previous, row in zip(rows, rows[1:], strict=False):
        assert row["prev_hash"] == previous["hash"]
    assert rows[-1]["id"] == claim.row_id
    assert rows[-1]["hash"] == claim.entry_hash


async def test_rest_export_trailer_has_no_signature_without_the_signing_key(
    client: httpx.AsyncClient,
    root_key: str,
    private: Ed25519PrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    # The environment is not consulted: only the app's Settings name a signing key.
    monkeypatch.setenv(SIGN_ENV, b64(raw_private(private)))

    *_, trailer = await seeded_export(client, root_key)

    assert trailer["type"] == HEAD_TYPE
    assert SIGNED_FIELDS.isdisjoint(trailer)


@SIGNED_APP
async def test_filtered_export_head_is_signed_and_marked_filtered(
    client: httpx.AsyncClient,
    root_key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)

    *_, trailer = await seeded_export(client, root_key, {"outcome": "success"})

    assert trailer["type"] == HEAD_TYPE and trailer["filtered"] is True
    assert SIGNED_FIELDS <= set(trailer)
    verify_head_signature(json.dumps(trailer), raw_public(APP_KEY))


async def test_operator_export_carries_the_signature(
    client: httpx.AsyncClient,
    root_key: str,
    database: str,
    org_id: str,
    signing_key: Ed25519PrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    monkeypatch.delenv(SIGN_ENV, raising=False)
    await seeded_export(client, root_key)
    lines: list[str] = []
    settings = Settings(
        driver="fake",
        database_url=database,
        api_key_pepper=PEPPER,
        audit_chain_key=CHAIN_KEY,
        audit_signing_key=b64(raw_private(signing_key)),
    )

    await admin_cli._audit_export_async(settings, org_id, lines.append)

    assert head_record(lines[-1])["type"] == HEAD_TYPE
    claim = verify_head_signature(lines[-1], raw_public(signing_key))
    assert (claim.org_id, claim.row_id) == (org_id, head_record(lines[-2])["id"])
    assert claim.signed_at.utcoffset() == timedelta(0)


async def test_operator_export_ignores_the_environment_key(
    client: httpx.AsyncClient,
    root_key: str,
    database: str,
    org_id: str,
    private: Ed25519PrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    monkeypatch.setenv(SIGN_ENV, b64(raw_private(private)))
    await seeded_export(client, root_key)
    lines: list[str] = []
    settings = Settings(
        driver="fake", database_url=database, api_key_pepper=PEPPER, audit_chain_key=CHAIN_KEY
    )

    await admin_cli._audit_export_async(settings, org_id, lines.append)

    assert head_record(lines[-1])["type"] == HEAD_TYPE
    assert SIGNED_FIELDS.isdisjoint(head_record(lines[-1]))


# --- import layering -------------------------------------------------------------------------


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            found.add(node.module)
    return found


def test_config_does_not_import_services() -> None:
    modules = imported_modules(ROOT / "src" / "sandfort" / "config.py")

    assert "sandfort.audit_signing" in modules
    assert not any(name.startswith("sandfort.services") for name in modules)


def test_signing_leaf_imports_only_stdlib_and_cryptography() -> None:
    modules = imported_modules(ROOT / "src" / "sandfort" / "audit_signing.py")

    roots = {name.split(".")[0] for name in modules}
    assert "sandfort" not in roots
    assert roots - set(sys.stdlib_module_names) == {"cryptography"}


def test_services_module_re_exports_the_leaf() -> None:
    for name in ("HeadSigner", "parse_signing_key", "canonical_payload", "signer_from_text"):
        assert getattr(audit_head_signing, name) is getattr(audit_signing, name)
