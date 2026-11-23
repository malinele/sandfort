"""Round 63: status publishes the audit key fingerprint; capacity refusals are coalesced.

``GET /v1/status`` carries ``audit_key_fingerprint`` next to ``audit_public_key`` (first 16 hex
of sha256 over the raw public key, as the CLI and the doctor print it). A 503 CAPACITY refusal
writes at most one ``sandbox.create_refused`` / ``sandbox.start_refused`` row per API key and
reason per 60 seconds; the suppressed ones are counted into the next row (``refusals_coalesced``).
"""

import base64
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI

from sandfort.admin_doctor_rows import key_fingerprint as doctor_fingerprint
from sandfort.api.routes import health
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey
from sandfort.ids import new_api_key_id
from sandfort.services.admission import (
    COALESCE_WINDOW,
    RefusalCoalescer,
    refusal_key,
)
from test_capacity_audit_r60 import (  # noqa: E402
    ADMIN,
    CREATE_REFUSED,
    HOST_MILLICORES,
    PEPPER,
    START_REFUSED,
    auth,
    create,
    events,
    fill_host,
    make_app,
    seed_org_key,
    serve,
)

CHAIN_ENV = "SANDFORT_AUDIT_CHAIN_KEY"
CHAIN_KEY = "c" * 40
ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
FINGERPRINT = re.compile(r"[0-9a-f]{16}")


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode()


def raw_public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def raw_private(private: Ed25519PrivateKey) -> bytes:
    return private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def make_settings(**extra: str) -> Settings:
    return Settings(
        driver="fake",
        database_url="sqlite+aiosqlite:///:memory:",
        api_key_pepper="test-pepper",
        **extra,
    )


# --- GET /v1/status: audit_key_fingerprint --------------------------------------------------


def test_status_fingerprint_is_the_first_16_hex_of_sha256_over_the_raw_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    private = Ed25519PrivateKey.generate()

    data = health.status_payload(make_settings(audit_signing_key=b64(raw_private(private))))

    expected = hashlib.sha256(raw_public(private)).hexdigest()[:16]
    assert FINGERPRINT.fullmatch(data["audit_key_fingerprint"])
    assert data["audit_key_fingerprint"] == expected
    assert data["audit_key_fingerprint"] == doctor_fingerprint(data["audit_public_key"])
    assert data["audit_public_key"] == b64(raw_public(private))


def test_status_fingerprint_is_null_while_the_key_is_null(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(CHAIN_ENV, raising=False)
    private = Ed25519PrivateKey.generate()

    unsigned = health.status_payload(make_settings())
    no_chain_key = health.status_payload(make_settings(audit_signing_key=b64(raw_private(private))))

    for data in (unsigned, no_chain_key):
        assert "audit_key_fingerprint" in data
        assert data["audit_public_key"] is None
        assert data["audit_key_fingerprint"] is None


async def test_status_route_serves_the_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    private = Ed25519PrivateKey.generate()
    app = make_app(tmp_path, audit_signing_key=b64(raw_private(private)))
    async with serve(app) as client:
        response = await client.get("/v1/status")

    data = response.json()["data"]
    assert data["audit_key_fingerprint"] == doctor_fingerprint(b64(raw_public(private)))


# --- the coalescer, with a fake clock -----------------------------------------------------------


def coalescer(clock: FrozenClock) -> RefusalCoalescer:
    return RefusalCoalescer(clock)


KEY = refusal_key(CREATE_REFUSED, "org_1", "key_1", "capacity")


def test_first_refusal_is_written_and_repeats_in_the_window_are_suppressed() -> None:
    clock = FrozenClock(T0)
    refusals = coalescer(clock)

    first = refusals.claim(KEY)
    clock.advance(timedelta(seconds=10))
    second = refusals.claim(KEY)
    clock.advance(timedelta(seconds=49))
    third = refusals.claim(KEY)

    assert first == 0  # written, nothing was suppressed before it
    assert second is None
    assert third is None


def test_next_row_after_the_window_carries_the_suppressed_count() -> None:
    clock = FrozenClock(T0)
    refusals = coalescer(clock)
    refusals.claim(KEY)
    for _ in range(3):
        clock.advance(timedelta(seconds=5))
        assert refusals.claim(KEY) is None

    clock.advance(COALESCE_WINDOW)

    assert refusals.claim(KEY) == 3
    clock.advance(COALESCE_WINDOW)
    assert refusals.claim(KEY) == 0  # the count was consumed


def test_the_window_is_per_key_action_and_reason() -> None:
    clock = FrozenClock(T0)
    refusals = coalescer(clock)
    others = [
        refusal_key(CREATE_REFUSED, "org_1", "key_2", "capacity"),  # another API key
        refusal_key(START_REFUSED, "org_1", "key_1", "capacity"),  # a start, not a create
        refusal_key(CREATE_REFUSED, "org_1", "key_1", "other"),  # another reason
    ]

    assert refusals.claim(KEY) == 0
    assert [refusals.claim(other) for other in others] == [0, 0, 0]
    assert refusals.claim(KEY) is None


def test_failed_write_gives_the_slot_and_the_count_back() -> None:
    clock = FrozenClock(T0)
    refusals = coalescer(clock)
    refusals.claim(KEY)
    clock.advance(timedelta(seconds=1))
    assert refusals.claim(KEY) is None
    clock.advance(COALESCE_WINDOW)
    carried = refusals.claim(KEY)
    assert carried == 1

    refusals.release(KEY, carried)

    assert refusals.claim(KEY) == 1  # the row was not written, so the next one still owes it


def test_the_map_is_bounded() -> None:
    clock = FrozenClock(T0)
    refusals = RefusalCoalescer(clock, max_keys=3)

    for number in range(10):
        refusals.claim(refusal_key(CREATE_REFUSED, "org", f"key_{number}", "capacity"))

    assert refusals.size() == 3


# --- end to end: one row per key per minute -------------------------------------------------


def frozen_app(tmp_path: Path, clock: FrozenClock, monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    """An app whose services run on ``clock`` (the wiring builds its clock from SystemClock)."""
    monkeypatch.setattr("sandfort.api.wiring.SystemClock", lambda: clock)
    return make_app(tmp_path, host_capacity_cpu_millicores=HOST_MILLICORES)


async def test_repeated_create_refusals_write_one_row_per_minute_and_count_the_rest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FrozenClock(T0)
    app = frozen_app(tmp_path, clock, monkeypatch)
    async with serve(app) as client:
        _, _, key = await seed_org_key(app, "acme")
        await fill_host(client, key)

        for _ in range(5):
            assert (await create(client, key)).status_code == 503
            clock.advance(timedelta(seconds=5))
        first = await events(client, key, CREATE_REFUSED)
        no_request_denied = await events(client, key, "request.denied")

        clock.advance(COALESCE_WINDOW)
        assert (await create(client, key)).status_code == 503
        rows = await events(client, key, CREATE_REFUSED)

    assert len(first) == 1
    assert "refusals_coalesced" not in first[0]["details"]
    assert no_request_denied == []  # a suppressed refusal gets no handler row either
    assert len(rows) == 2
    assert rows[1]["details"]["refusals_coalesced"] == 4


async def test_another_key_in_the_same_minute_still_gets_its_own_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FrozenClock(T0)
    app = frozen_app(tmp_path, clock, monkeypatch)
    async with serve(app) as client:
        org_id, _, key = await seed_org_key(app, "acme")
        other = await second_key(app, org_id)
        await fill_host(client, key)

        for secret in (key, other, key, other):
            assert (await create(client, secret)).status_code == 503
        rows = await events(client, key, CREATE_REFUSED)

    assert len(rows) == 2
    assert {row["actor_id"] for row in rows} != {None}
    assert len({row["actor_id"] for row in rows}) == 2


async def test_start_refusals_are_coalesced_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FrozenClock(T0)
    app = frozen_app(tmp_path, clock, monkeypatch)
    async with serve(app) as client:
        _, _, key = await seed_org_key(app, "acme")
        stopped = (await create(client, key)).json()["data"]["id"]
        stop = await client.post(f"/v1/sandboxes/{stopped}/stop", headers=auth(key))
        assert stop.status_code == 200
        await fill_host(client, key)

        for _ in range(3):
            refused = await client.post(f"/v1/sandboxes/{stopped}/start", headers=auth(key))
            assert refused.status_code == 503
        first = await events(client, key, START_REFUSED)
        clock.advance(COALESCE_WINDOW)
        await client.post(f"/v1/sandboxes/{stopped}/start", headers=auth(key))
        rows = await events(client, key, START_REFUSED)

    assert len(first) == 1
    assert len(rows) == 2
    assert rows[1]["details"]["refusals_coalesced"] == 2


async def second_key(app: FastAPI, org_id: str) -> str:
    """A second API key in the same org, stored directly."""
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="second",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=ADMIN,
        created_at=T0,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


# --- docs ---------------------------------------------------------------------------------------


def read(name: str) -> str:
    return (ROOT / "docs" / name).read_text(encoding="utf-8")


def test_security_page_describes_the_signed_head_and_the_row_rule() -> None:
    text = read("security.md")

    assert "exactly one row" not in text
    for needle in (
        "audit_head",
        "signed_at",
        "audit_public_key",
        "audit_key_fingerprint",
        "verify-head",
        "stored unhashed",
    ):
        assert needle in text, needle


def test_governance_row_rule_and_fingerprint_pinning() -> None:
    text = " ".join(read("governance.md").split())

    assert "Every non-GET call writes one event (a meta-test" not in text
    assert "audit_key_fingerprint" in text
    assert "out of band" in text
    assert "refusals_coalesced" in text


def test_operations_says_to_pin_the_fingerprint_out_of_band() -> None:
    text = " ".join(read("operations.md").split())

    assert "audit_key_fingerprint" in text
    assert "out of band" in text


def test_action_table_lists_the_refusal_and_stream_actions() -> None:
    text = read("governance.md")

    for action in (
        "sandbox.create_refused",
        "sandbox.start_refused",
        "toolbox.code_contexts.run_stream",
    ):
        assert re.search(rf"^\s*\| `{re.escape(action)}`", text, re.MULTILINE), action


def test_status_response_is_json_serialisable_with_the_new_field() -> None:
    data = health.status_payload(make_settings())

    assert json.loads(json.dumps(data))["audit_key_fingerprint"] is None
