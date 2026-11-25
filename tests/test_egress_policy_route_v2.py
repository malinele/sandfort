"""Egress v2 round 3 (round 86a): the internal policy route (docs/egress-v2-design.md 3.6, 12.4).

``POST /internal/egress/v1/policies``: request MAC under K_req, response MAC under K_resp over
``"<t>\\n<sha256 of request body>\\n<sha256 of response body>"`` (the round 3 amendment), 1 to 256
ids, batch read semantics, spec exclusion. Cases A10, A12, the spec half of A11 and U9. MACs are
computed here from the documented labels, never through the code under test (policy_wire is only
the second opinion in the verify test). Hermetic: FakeDriver, temp SQLite, httpx ASGITransport.
"""

import base64
import hashlib
import hmac
import json
import time
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI, Request
from sqlalchemy import text

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.egress import admission
from sandfort.egress.auth import EgressCredential
from sandfort.egress.policy_client import PolicyClient
from sandfort.egress.policy_wire import verify_response
from sandfort.egress.relay import Deny
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
PATH = "/internal/egress/v1/policies"
AUTH, SIGNATURE = "X-Sandfort-Egress-Auth", "X-Sandfort-Egress-Signature"
SECRET = "e" * 40
READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
PROXY_SETTINGS = {"egress_proxy_address": "proxy.internal:3128", "egress_secret": SECRET}
RULES = ["api.example.com", ".example.org", "8.8.8.0/24"]
UNAUTHORIZED = {"detail": "unauthorized"}

AppFactory = Callable[..., FastAPI]


def derived(secret: str, label: str) -> bytes:
    return hmac.new(secret.encode(), label.encode(), hashlib.sha256).digest()


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def request_header(body: bytes, *, at: int | None = None, key: bytes | None = None) -> str:
    """``X-Sandfort-Egress-Auth`` for ``body``: the documented request MAC under K_req."""
    stamp = int(time.time()) if at is None else at
    key = derived(SECRET, "sandfort/egress/policy/request/v1") if key is None else key
    message = f"POST\n{PATH}\n{stamp}\n{sha(body)}"
    return f"t={stamp},s={b64url(hmac.new(key, message.encode(), hashlib.sha256).digest())}"


def response_mac(stamp: int, request: bytes, response: bytes, key: bytes | None = None) -> str:
    """The documented response MAC (amended message) under K_resp, as a header value."""
    key = derived(SECRET, "sandfort/egress/policy/response/v1") if key is None else key
    message = f"{stamp}\n{sha(request)}\n{sha(response)}"
    return f"t={stamp},s={b64url(hmac.new(key, message.encode(), hashlib.sha256).digest())}"


NONCE = "bm9uY2UtMDAwMDAwMDAwMA"


def body_of(ids: list[Any], nonce: Any = NONCE) -> bytes:
    """The request body the client sends: ``nonce`` first, ``sandbox_ids`` second."""
    return json.dumps({"nonce": nonce, "sandbox_ids": ids}, separators=(",", ":")).encode()


@pytest.fixture
async def make_app(tmp_path: Path) -> AsyncIterator[AppFactory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    built: list[FastAPI] = []

    def build(**overrides: Any) -> FastAPI:
        url = f"sqlite+aiosqlite:///{tmp_path / 'egress-route.db'}"
        config = Config(str(ROOT / "alembic.ini"))
        config.set_main_option("sqlalchemy.url", url)
        command.upgrade(config, "head")
        settings = Settings(
            driver="fake",
            database_url=url,
            api_key_pepper=PEPPER,
            autostop_enabled=False,
            **{"egress_policy_route_enabled": True, **PROXY_SETTINGS, **overrides},
        )
        app = create_app(settings)
        built.append(app)
        return app

    yield build
    for app in built:
        await app.state.engine.dispose()


async def connect(app: FastAPI, slug: str = "acme") -> str:
    """A fresh org with a read-write API key; returns the plaintext key."""
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored_key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=READ_WRITE,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored_key)
        await uow.commit()
    return generated.key


async def api(app: FastAPI, key: str, method: str, path: str, **kwargs: Any) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        return await http.request(
            method, path, headers={"Authorization": f"Bearer {key}"}, **kwargs
        )


async def create(app: FastAPI, key: str, name: str, **payload: Any) -> str:
    response = await api(app, key, "POST", BASE, json={"name": name, **payload})
    assert response.status_code == 201, response.text
    return str(response.json()["data"]["id"])


async def execute(app: FastAPI, statement: str, **values: Any) -> None:
    async with app.state.session_factory() as session:
        await session.execute(text(statement), values)
        await session.commit()


async def lookup(app: FastAPI, content: bytes, header: str | None = "signed") -> httpx.Response:
    """POST ``content``; ``"signed"`` stands for a valid request MAC, ``None`` for no header."""
    headers = {"Content-Type": "application/json"}
    if header is not None:
        headers[AUTH] = request_header(content) if header == "signed" else header
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://policy.test") as http:
        return await http.post(PATH, content=content, headers=headers)


def assert_unsigned_401(response: httpx.Response) -> None:
    assert response.status_code == 401, response.text
    assert response.json() == UNAUTHORIZED
    assert SIGNATURE not in response.headers


# -- the 200: records, order, signature -------------------------------------------------------


async def test_a_valid_request_answers_records_in_request_order_with_a_bound_signature(
    make_app: AppFactory,
) -> None:
    app = make_app()
    key = await connect(app)
    first = await create(app, key, "first", egress_allowlist=RULES)
    other_org = await connect(app, "globex")  # the read crosses orgs: a proxy serves them all
    second = await create(app, other_org, "second", egress_allowlist=["only.example.net"])
    ids = [second, "sbx_doesnotexist", first]
    content = body_of(ids)
    before = int(time.time())

    response = await lookup(app, content)

    assert response.status_code == 200, response.text
    document = response.json()
    only = ["only.example.net"]
    assert document["policies"] == [
        {"sandbox_id": second, "found": True, "generation": 1, "epoch": 0, "rules": only},
        {"sandbox_id": "sbx_doesnotexist", "found": False},
        {"sandbox_id": first, "found": True, "generation": 1, "epoch": 0, "rules": RULES},
    ]
    header = response.headers[SIGNATURE]
    stamp = int(header.split(",")[0].removeprefix("t="))
    assert document["issued_at"] == stamp
    assert before <= stamp <= int(time.time())
    assert header == response_mac(stamp, content, response.content)


async def test_the_signature_verifies_through_the_amended_policy_wire(
    make_app: AppFactory,
) -> None:
    app = make_app()
    sandbox = await create(app, await connect(app), "one", egress_allowlist=RULES)
    content = body_of([sandbox])

    response = await lookup(app, content)

    key = derived(SECRET, "sandfort/egress/policy/response/v1")
    now = int(time.time())
    header = response.headers[SIGNATURE]
    assert verify_response(key, header, content, response.content, now)
    assert not verify_response(key, header, body_of(["sbx_other"]), response.content, now)


# -- A12: what is found -----------------------------------------------------------------------


async def test_a12_a_generation_zero_row_is_found_with_its_stored_rules(
    make_app: AppFactory,
) -> None:
    app = make_app()
    sandbox = await create(app, await connect(app), "legacy", egress_allowlist=RULES)
    await execute(
        app, "UPDATE sandboxes SET egress_policy_generation = 0 WHERE id = :id", id=sandbox
    )

    response = await lookup(app, body_of([sandbox]))

    assert response.json()["policies"] == [
        {"sandbox_id": sandbox, "found": True, "generation": 0, "epoch": 0, "rules": RULES}
    ]


async def test_a12_no_allowlist_is_not_found_but_an_empty_one_is_found_with_no_rules(
    make_app: AppFactory,
) -> None:
    app = make_app()
    key = await connect(app)
    plain = await create(app, key, "plain")
    closed = await create(app, key, "closed", egress_allowlist=[])

    response = await lookup(app, body_of([plain, closed]))

    records = response.json()["policies"]
    assert records[0] == {"sandbox_id": plain, "found": False}  # no generation, epoch or rules
    assert records[1]["found"] is True
    assert records[1]["rules"] == []


@pytest.mark.parametrize("state", ["destroying", "destroyed"])
async def test_a12_a_sandbox_on_its_way_out_is_not_found(make_app: AppFactory, state: str) -> None:
    app = make_app()
    key = await connect(app)
    leaving = await create(app, key, "leaving", egress_allowlist=RULES)
    staying = await create(app, key, "staying", egress_allowlist=RULES)
    await execute(
        app, "UPDATE sandboxes SET state = :state WHERE id = :id", state=state, id=leaving
    )

    response = await lookup(app, body_of([leaving, staying]))

    found = {record["sandbox_id"]: record["found"] for record in response.json()["policies"]}
    assert found == {leaving: False, staying: True}


# -- A10: authentication and bounds -----------------------------------------------------------


async def test_a10_a_request_without_a_mac_is_an_unsigned_401(make_app: AppFactory) -> None:
    assert_unsigned_401(await lookup(make_app(), body_of(["sbx_1"]), header=None))


def forged(label: str, secret: str = SECRET, raw: bool = False) -> Callable[[bytes], str]:
    key = secret.encode() if raw else derived(secret, label)
    return lambda content: request_header(content, key=key)


FORGERIES: dict[str, Callable[[bytes], str]] = {
    "response key": forged("sandfort/egress/policy/response/v1"),
    "token v2 key": forged("sandfort/egress/token/v2"),
    "v1 token key": forged("", raw=True),  # the v1 token key is the raw secret
    "other secret": forged("sandfort/egress/policy/request/v1", "x" * 40),
    "other body": lambda content: request_header(body_of(["sbx_2"])),
    "33 s old": lambda content: request_header(content, at=int(time.time()) - 33),
    "33 s ahead": lambda content: request_header(content, at=int(time.time()) + 33),
    "short mac": lambda content: "t=1,s=AAAA",
    "garbage": lambda content: "garbage",
    "empty": lambda content: "",
}


@pytest.mark.parametrize("forge", FORGERIES.values(), ids=FORGERIES.keys())
async def test_a10_a_bad_or_stale_mac_is_an_unsigned_401(
    make_app: AppFactory, forge: Callable[[bytes], str]
) -> None:
    content = body_of(["sbx_1"])

    assert_unsigned_401(await lookup(make_app(), content, header=forge(content)))


async def test_without_an_egress_secret_the_route_is_not_mounted(
    make_app: AppFactory,
) -> None:
    app = make_app(egress_secret="")
    content = body_of(["sbx_1"])

    for header in ("signed", request_header(content, key=derived("", "x")), None):
        response = await lookup(app, content, header)
        assert response.status_code == 404, response.text
        assert SIGNATURE not in response.headers


async def test_the_route_is_absent_unless_the_setting_enables_it(make_app: AppFactory) -> None:
    app = make_app(egress_policy_route_enabled=False)
    content = body_of(["sbx_1"])

    response = await lookup(app, content)

    assert response.status_code == 404, response.text
    assert SIGNATURE not in response.headers


async def test_the_route_is_present_when_the_setting_and_the_secret_are_set(
    make_app: AppFactory,
) -> None:
    response = await lookup(make_app(egress_policy_route_enabled=True), body_of(["sbx_1"]))

    assert response.status_code == 200, response.text


def test_the_setting_defaults_to_off_and_reads_its_environment_variable() -> None:
    assert Settings().egress_policy_route_enabled is False
    assert Settings.from_env({}).egress_policy_route_enabled is False
    enabled = Settings.from_env({"SANDFORT_EGRESS_POLICY_ROUTE_ENABLED": "true"})
    assert enabled.egress_policy_route_enabled is True


@pytest.mark.parametrize(
    "stale", [lambda c: request_header(c, at=int(time.time()) - 33), lambda c: "garbage", None]
)
async def test_a_stale_or_malformed_header_is_refused_before_the_body_is_read(
    make_app: AppFactory, monkeypatch: pytest.MonkeyPatch, stale: Callable[[bytes], str] | None
) -> None:
    async def forbidden(self: Request) -> bytes:
        raise AssertionError("the body was read before the header was checked")

    monkeypatch.setattr(Request, "body", forbidden)
    content = body_of(["sbx_1"])
    header = None if stale is None else stale(content)

    assert_unsigned_401(await lookup(make_app(), content, header=header))


@pytest.mark.parametrize(
    "ids",
    [[], [f"sbx_{index}" for index in range(257)]],
    ids=["zero ids", "257 ids"],
)
async def test_a10_a_signed_request_outside_one_to_256_ids_answers_422(
    make_app: AppFactory, ids: list[str]
) -> None:
    response = await lookup(make_app(), body_of(ids))

    assert response.status_code == 422, response.text
    assert SIGNATURE not in response.headers  # only the 200 is signed


async def test_the_response_signature_binds_to_each_request_nonce(make_app: AppFactory) -> None:
    app = make_app()
    sandbox = await create(app, await connect(app), "one", egress_allowlist=RULES)
    first, second = body_of([sandbox], "nonce-a"), body_of([sandbox], "nonce-b")

    answer = await lookup(app, first)
    key = derived(SECRET, "sandfort/egress/policy/response/v1")
    now = int(time.time())

    assert verify_response(key, answer.headers[SIGNATURE], first, answer.content, now)
    assert not verify_response(key, answer.headers[SIGNATURE], second, answer.content, now)


@pytest.mark.parametrize(
    "content",
    [
        b"not json",
        b"[]",
        b"{}",
        b'{"sandbox_ids": "sbx_1"}',
        b'{"sandbox_ids": [1]}',
        b"",
        b'{"sandbox_ids": ["sbx_1"]}',  # no nonce: the replay defence needs one
        b'{"nonce": "", "sandbox_ids": ["sbx_1"]}',
        b'{"nonce": "a b", "sandbox_ids": ["sbx_1"]}',
        b'{"nonce": "a+b", "sandbox_ids": ["sbx_1"]}',
        b'{"nonce": 7, "sandbox_ids": ["sbx_1"]}',
        b'{"nonce": null, "sandbox_ids": ["sbx_1"]}',
        b'{"nonce": "' + b"x" * 65 + b'", "sandbox_ids": ["sbx_1"]}',
        b'{"nonce": "n", "sandbox_ids": ["sbx_1"], "extra": 1}',  # exactly two keys
    ],
)
async def test_a_signed_request_with_a_malformed_body_answers_422(
    make_app: AppFactory, content: bytes
) -> None:
    response = await lookup(make_app(), content)

    assert response.status_code == 422, response.text
    assert SIGNATURE not in response.headers


# -- A11, spec half ---------------------------------------------------------------------------


async def test_a11_the_internal_route_is_not_in_the_openapi_document(
    make_app: AppFactory,
) -> None:
    paths = make_app().openapi()["paths"]
    committed = json.loads((ROOT / "openapi" / "sandfort.v1.json").read_text())["paths"]

    assert PATH not in paths
    assert PATH not in committed
    assert not [path for path in paths if path.startswith("/internal")]
    assert not [path for path in committed if path.startswith("/internal")]


# -- U9 end to end ----------------------------------------------------------------------------


def v2_credential(sandbox_id: str, epoch: int) -> EgressCredential:
    issued = datetime.now(UTC)
    return EgressCredential(sandbox_id, 2, (), epoch, issued, issued + timedelta(days=1))


async def test_u9_a_reset_revokes_the_previous_credential_through_the_policy_lookup(
    make_app: AppFactory,
) -> None:
    app = make_app()
    key = await connect(app)
    sandbox = await create(app, key, "revoked", egress_allowlist=RULES)
    reset = await api(app, key, "POST", f"{BASE}/{sandbox}/reset")
    assert reset.status_code == 200, reset.text
    client = PolicyClient(
        "http://policy.test",
        SECRET,
        cache_s=5.0,
        timeout_s=5.0,
        max_stale_s=60.0,
        transport=httpx.ASGITransport(app=app),
    )
    try:
        entry = await client.lookup(sandbox)
    finally:
        await client.aclose()

    assert entry.found is True
    assert (entry.epoch, entry.rules) == (1, tuple(RULES))
    assert entry.generation >= 1
    with pytest.raises(Deny) as raised:
        admission.decide(v2_credential(sandbox, 0), entry, policy_configured=True)
    assert (raised.value.status, raised.value.detail) == (407, "credential epoch mismatch")
    rules, _ = admission.decide(v2_credential(sandbox, 1), entry, policy_configured=True)
    assert rules.admits_name("api.example.com")
