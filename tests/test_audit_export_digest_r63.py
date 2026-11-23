"""Server side of round 63: the signed export head binds the export's content.

The head the server writes at the end of an export now carries ``row_count``, ``first_row_id``
and ``export_sha256`` (hex SHA-256 over the exact UTF-8 bytes of every event line, each with its
newline, in order, not the trailer). They are covered by the HMAC and the Ed25519 signature, are
computed while the lines stream, and filtered or period exports are signed too.
"""

import base64
import hashlib
import json
import sys
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from sandfort_sdk import verify_export  # noqa: E402

from sandfort import admin_cli  # noqa: E402
from sandfort.api.app import create_app  # noqa: E402
from sandfort.auth.api_keys import generate_api_key  # noqa: E402
from sandfort.config import Settings  # noqa: E402
from sandfort.db.unit_of_work import UnitOfWork  # noqa: E402
from sandfort.domain.org import ApiKey, Org, Scope  # noqa: E402
from sandfort.ids import new_api_key_id, new_org_id  # noqa: E402
from sandfort.services.audit_chain_head import (  # noqa: E402
    HEAD_TYPE,
    HeadSignatureError,
    parse_heads,
    sign_head,
    verify_head_signature,
)
from sandfort.services.audit_export_digest import ExportBinding, ExportDigest  # noqa: E402
from sandfort.services.audit_head_signing import canonical_payload, verify_payload  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PEPPER = "test-pepper"
EXPORT = "/v1/audit-events/export"
KEYS = "/v1/api-keys"
CHAIN_ENV = "SANDFORT_AUDIT_CHAIN_KEY"
CHAIN_KEY = "c" * 40
MAC_KEY = b"k" * 32
SCOPES = [Scope.API_KEYS_ADMIN.value, Scope.AUDIT_READ.value]
MINTED = 4
BINDING_FIELDS = {"row_count", "first_row_id", "export_sha256"}
APP_KEY = Ed25519PrivateKey.generate()
ORG = "org_test"
ROW = "aud_00000000000000000007"
HASH = "ab" * 32


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode()


def raw_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def signer_of(key: Ed25519PrivateKey):  # type: ignore[no-untyped-def]
    found = Settings(audit_signing_key=b64(raw_private(key))).audit_signer()
    assert found is not None
    return found


def digest_of(lines: list[str]) -> ExportBinding:
    digest = ExportDigest()
    for number, line in enumerate(lines, start=1):
        digest.add(f"aud_{number}", line)
    return digest.binding()


# --- the streaming digest ----------------------------------------------------------------------


def test_digest_equals_a_recomputation_over_the_joined_bytes() -> None:
    lines = ['{"id":"a","x":"é"}\n', '{"id":"b"}\n', '{"id":"c"}\n']

    binding = digest_of(lines)

    assert binding.row_count == 3 and binding.first_row_id == "aud_1"
    assert binding.export_sha256 == hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def test_digest_of_no_lines_is_the_empty_hash_with_no_first_row() -> None:
    binding = ExportDigest().binding()

    assert binding == ExportBinding(0, None, hashlib.sha256(b"").hexdigest())


def test_digest_depends_on_order_content_and_the_newline() -> None:
    base = digest_of(['{"id":"a"}\n', '{"id":"b"}\n']).export_sha256

    assert digest_of(['{"id":"b"}\n', '{"id":"a"}\n']).export_sha256 != base
    assert digest_of(['{"id":"a"}\n', '{"id":"c"}\n']).export_sha256 != base
    assert digest_of(['{"id":"a"}', '{"id":"b"}']).export_sha256 != base


def test_digest_keeps_constant_state() -> None:
    digest = ExportDigest()
    for number in range(2000):
        digest.add(f"aud_{number}", f'{{"id":"aud_{number}"}}\n')

    assert not hasattr(digest, "__dict__")  # no per-line list or dict hangs off the object
    assert digest.binding().row_count == 2000


# --- the head ----------------------------------------------------------------------------------


def bound_head(key: Ed25519PrivateKey | None = None, **kwargs: Any):  # type: ignore[no-untyped-def]
    binding = digest_of(['{"id":"a"}\n', '{"id":"b"}\n'])
    signer = None if key is None else signer_of(key)
    return sign_head(MAC_KEY, ORG, ROW, HASH, signer, None, binding, **kwargs)


def test_head_record_carries_the_three_fields() -> None:
    record = bound_head().to_record()

    assert BINDING_FIELDS <= set(record)
    assert record["row_count"] == 2 and record["first_row_id"] == "aud_1"
    assert len(record["export_sha256"]) == 64


def test_a_head_without_a_binding_is_the_legacy_shape() -> None:
    record = sign_head(MAC_KEY, ORG, ROW, HASH).to_record()

    assert BINDING_FIELDS.isdisjoint(record)
    assert "filtered" not in record


def test_hmac_covers_the_binding_fields() -> None:
    head = bound_head()
    forged = [
        json.loads(head.to_line()) | {"row_count": 3},
        json.loads(head.to_line()) | {"export_sha256": "0" * 64},
        json.loads(head.to_line()) | {"first_row_id": "aud_9"},
    ]

    assert head.valid(MAC_KEY)
    for record in forged:
        (parsed,) = parse_heads([json.dumps(record)])
        assert not parsed.valid(MAC_KEY)


def test_legacy_and_bound_heads_both_parse_and_validate() -> None:
    legacy = sign_head(MAC_KEY, ORG, ROW, HASH)
    bound = bound_head()

    legacy_parsed, bound_parsed = parse_heads([legacy.to_line(), bound.to_line()])

    assert legacy_parsed.valid(MAC_KEY) and not legacy_parsed.binds_content
    assert bound_parsed.valid(MAC_KEY) and bound_parsed.binds_content
    assert bound_parsed.to_record() == bound.to_record()


def test_a_partial_binding_is_refused() -> None:
    record = json.loads(bound_head().to_line())
    del record["export_sha256"]

    with pytest.raises(ValueError, match="content binding"):
        parse_heads([json.dumps(record)])


@pytest.mark.parametrize(
    "change",
    [{"row_count": -1}, {"row_count": True}, {"row_count": "2"}, {"export_sha256": "abc"}],
)
def test_a_malformed_binding_is_refused(change: dict[str, Any]) -> None:
    record = json.loads(bound_head().to_line()) | change

    with pytest.raises(ValueError, match="content binding"):
        parse_heads([json.dumps(record)])


def test_signature_covers_the_binding_fields() -> None:
    key = Ed25519PrivateKey.generate()
    line = bound_head(key).to_line()

    assert verify_head_signature(line, raw_public(key)).row_id == ROW
    for change in ({"row_count": 5}, {"export_sha256": "1" * 64}, {"first_row_id": "aud_2"}):
        forged = json.dumps(json.loads(line) | change)
        with pytest.raises(HeadSignatureError):
            verify_head_signature(forged, raw_public(key))


def test_dropping_the_binding_from_a_signed_head_breaks_the_signature() -> None:
    key = Ed25519PrivateKey.generate()
    record = json.loads(bound_head(key).to_line())
    for name in BINDING_FIELDS:
        del record[name]

    with pytest.raises(HeadSignatureError):
        verify_head_signature(json.dumps(record), raw_public(key))


def test_binding_is_part_of_the_canonical_signed_payload() -> None:
    key = Ed25519PrivateKey.generate()
    record = json.loads(bound_head(key).to_line())

    assert BINDING_FIELDS <= set(json.loads(canonical_payload(record)))
    assert verify_payload(key.public_key(), canonical_payload(record), record["signature"])


def test_filtered_head_records_its_filters_and_is_covered() -> None:
    key = Ed25519PrivateKey.generate()
    head = bound_head(key, filters={"outcome": "failure"})
    record = json.loads(head.to_line())

    assert record["filtered"] is True and record["filters"] == {"outcome": "failure"}
    assert verify_head_signature(head.to_line(), raw_public(key)).row_id == ROW
    (parsed,) = parse_heads([head.to_line()])
    assert parsed.valid(MAC_KEY) and parsed.filtered
    altered = json.dumps(record | {"filters": {"outcome": "success"}})
    with pytest.raises(HeadSignatureError):
        verify_head_signature(altered, raw_public(key))
    (reparsed,) = parse_heads([altered])
    assert not reparsed.valid(MAC_KEY)


def test_a_filtered_marker_without_the_binding_is_refused() -> None:
    record = {"type": HEAD_TYPE, "org_id": ORG, "row_id": ROW, "hash": HASH, "hmac": "a" * 64}
    record |= {"filtered": True, "filters": {}}

    with pytest.raises(ValueError, match="filtered marker"):
        parse_heads([json.dumps(record)])


# --- REST export -------------------------------------------------------------------------------


@pytest.fixture
async def database(tmp_path: Path) -> str:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'digest.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    return url


@pytest.fixture
async def app(database: str) -> AsyncIterator[FastAPI]:
    settings = Settings(
        driver="fake",
        database_url=database,
        api_key_pepper=PEPPER,
        audit_signing_key=b64(raw_private(APP_KEY)),
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


async def export_body(
    client: httpx.AsyncClient, caller: str, params: dict[str, str] | None = None, mint: bool = True
) -> str:
    headers = {"Authorization": f"Bearer {caller}"}
    for index in range(MINTED if mint else 0):
        body = {"name": f"child-{index}", "scopes": SCOPES}
        assert (await client.post(KEYS, json=body, headers=headers)).status_code == 201
    response = await client.get(EXPORT, params=params or {}, headers=headers)
    assert response.status_code == 200
    return response.text


def split(body: str) -> tuple[list[str], dict[str, Any]]:
    *rows, trailer = body.splitlines(keepends=True)
    return rows, json.loads(trailer)


async def test_rest_head_digest_equals_a_recomputation_over_the_streamed_lines(
    client: httpx.AsyncClient, root_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)

    rows, trailer = split(await export_body(client, root_key))

    assert trailer["type"] == HEAD_TYPE
    assert trailer["row_count"] == len(rows) == MINTED
    assert trailer["first_row_id"] == json.loads(rows[0])["id"]
    assert trailer["export_sha256"] == hashlib.sha256("".join(rows).encode()).hexdigest()
    assert all(line.endswith("\n") for line in rows)


async def test_rest_head_signature_covers_the_binding_and_the_hmac_validates(
    client: httpx.AsyncClient, root_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)

    rows, trailer = split(await export_body(client, root_key))
    line = json.dumps(trailer)

    assert BINDING_FIELDS <= set(
        canonical_payload(trailer) and json.loads(canonical_payload(trailer))
    )
    assert verify_head_signature(line, raw_public(APP_KEY)).row_id == json.loads(rows[-1])["id"]
    (parsed,) = parse_heads([line])
    assert parsed.valid(CHAIN_KEY.encode())
    with pytest.raises(HeadSignatureError):
        verify_head_signature(json.dumps(trailer | {"row_count": MINTED + 1}), raw_public(APP_KEY))


async def test_the_sdk_verifies_a_real_rest_export_and_catches_an_edited_line(
    client: httpx.AsyncClient, root_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    body = await export_body(client, root_key)
    public = b64(raw_public(APP_KEY))

    good = verify_export(body, public)
    edited = verify_export(body.replace('"outcome":"success"', '"outcome":"failure"', 1), public)

    assert good.ok and good.content_bound and good.rows == MINTED
    assert edited.reason == "content_mismatch"


async def test_a_period_closed_export_is_signed_over_its_own_last_row(
    client: httpx.AsyncClient, root_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    full, _ = split(await export_body(client, root_key))
    stamps = [json.loads(line)["occurred_at"] for line in full]
    cut = stamps[2]  # `to` is exclusive: the export holds the first two rows

    rows, trailer = split(await export_body(client, root_key, {"to": cut}, mint=False))

    assert 0 < len(rows) < MINTED
    assert trailer["type"] == HEAD_TYPE and "filtered" not in trailer
    assert trailer["row_id"] == json.loads(rows[-1])["id"]
    assert trailer["hash"] == json.loads(rows[-1])["hash"]
    assert trailer["row_count"] == len(rows)
    assert trailer["export_sha256"] == hashlib.sha256("".join(rows).encode()).hexdigest()
    verify_head_signature(json.dumps(trailer), raw_public(APP_KEY))
    assert verify_export("".join([*rows, json.dumps(trailer) + "\n"]), b64(raw_public(APP_KEY))).ok


async def test_a_filtered_export_is_signed_with_a_filtered_marker(
    client: httpx.AsyncClient, root_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)

    rows, trailer = split(await export_body(client, root_key, {"outcome": "success"}))

    assert trailer["type"] == HEAD_TYPE
    assert trailer["filtered"] is True and trailer["filters"] == {"outcome": "success"}
    assert trailer["row_count"] == len(rows)
    assert trailer["export_sha256"] == hashlib.sha256("".join(rows).encode()).hexdigest()
    verify_head_signature(json.dumps(trailer), raw_public(APP_KEY))
    (parsed,) = parse_heads([json.dumps(trailer)])
    assert parsed.valid(CHAIN_KEY.encode())


async def test_an_empty_export_keeps_the_unsigned_summary(
    client: httpx.AsyncClient, root_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)

    rows, trailer = split(await export_body(client, root_key, {"to": "2000-01-01T00:00:00Z"}))

    assert rows == [] and trailer == {"type": "export_summary", "rows": 0, "filters": ["to"]}


async def test_without_a_chain_key_the_trailer_is_the_summary(
    client: httpx.AsyncClient, root_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(CHAIN_ENV, raising=False)

    _, trailer = split(await export_body(client, root_key))

    assert trailer["type"] == "export_summary"


# --- operator export ---------------------------------------------------------------------------


async def test_operator_export_head_binds_that_orgs_lines(
    client: httpx.AsyncClient,
    root_key: str,
    database: str,
    org_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    await export_body(client, root_key)
    written: list[str] = []
    settings = Settings(
        driver="fake",
        database_url=database,
        api_key_pepper=PEPPER,
        audit_chain_key=CHAIN_KEY,
        audit_signing_key=b64(raw_private(APP_KEY)),
    )

    await admin_cli._audit_export_async(settings, org_id, written.append)

    *rows, trailer = written
    record = json.loads(trailer)
    assert record["row_count"] == len(rows) and record["first_row_id"] == json.loads(rows[0])["id"]
    assert (
        record["export_sha256"]
        == hashlib.sha256("".join(line + "\n" for line in rows).encode()).hexdigest()
    )
    verify_head_signature(trailer, raw_public(APP_KEY))


async def test_admin_head_parsing_accepts_both_shapes_and_the_signature_check(
    client: httpx.AsyncClient,
    root_key: str,
    database: str,
    org_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    await export_body(client, root_key)
    written: list[str] = []
    settings = Settings(
        driver="fake",
        database_url=database,
        api_key_pepper=PEPPER,
        audit_chain_key=CHAIN_KEY,
        audit_signing_key=b64(raw_private(APP_KEY)),
    )
    await admin_cli._audit_export_async(settings, org_id, written.append)
    (bound,) = parse_heads([written[-1]])
    legacy = sign_head(
        CHAIN_KEY.encode(), bound.org_id, bound.row_id, bound.entry_hash, signer_of(APP_KEY)
    )
    public = admin_cli.load_public_key(b64(raw_public(APP_KEY)))

    assert bound.binds_content and not legacy.binds_content
    for head in (bound, legacy):
        assert head.valid(CHAIN_KEY.encode())
        assert admin_cli._head_signature_finding(head, public) is None
    _, findings, *_ = await admin_cli._audit_verify_async(settings, [bound, legacy], public)
    assert findings == []
