"""Round 66b: a resolver failure is never reported as "the host does not resolve".

NXDOMAIN and NoData are a verdict (422 ``not_resolved``). A timeout, SERVFAIL (EAI_AGAIN,
EAI_FAIL) or any other resolver OSError is not: the guard retries once, and a second failure
answers 503 ``DNS_UNAVAILABLE`` with ``Retry-After``. The resolver is a fake; no test touches
the network, and the retry pause and the per-attempt cap are shrunk so the suite stays fast.
"""

import asyncio
import socket
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.webhooks import ssrf
from sandfort.webhooks.ssrf import HostNotResolved, ResolverUnavailable, UrlRejected, vet_url

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
PUBLIC_IP = "93.184.216.34"
HOOKS = "/v1/webhooks"
AUDIT = "/v1/audit-events"
URL = "https://example.com/audit"
SCOPES = frozenset({Scope.WEBHOOKS_WRITE, Scope.AUDIT_READ})
DEFAULT_ATTEMPT_TIMEOUT_S = ssrf.ATTEMPT_TIMEOUT_S  # read before the fixture shrinks the pause
DEFAULT_RETRY_PAUSE_S = ssrf.RETRY_PAUSE_S
TRANSIENT = [
    socket.gaierror(socket.EAI_AGAIN, "temporary failure in name resolution"),
    socket.gaierror(socket.EAI_FAIL, "non-recoverable failure in name resolution"),
    TimeoutError(),
    OSError("resolver socket closed"),
]
TRANSIENT_IDS = ["eai_again", "eai_fail", "timeout", "oserror"]

type Step = list[str] | BaseException


class ScriptedResolver:
    """Answers each call from ``steps`` in order (the last repeats); counts the calls."""

    def __init__(self, *steps: Step) -> None:
        self.steps = list(steps)
        self.calls = 0

    async def __call__(self, host: str) -> list[str]:
        step = self.steps[min(self.calls, len(self.steps) - 1)]
        self.calls += 1
        if isinstance(step, BaseException):
            raise step
        return step


@pytest.fixture(autouse=True)
def fast_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ssrf, "RETRY_PAUSE_S", 0.01)


def install(monkeypatch: pytest.MonkeyPatch, *steps: Step) -> ScriptedResolver:
    resolver = ScriptedResolver(*steps)
    monkeypatch.setattr("sandfort.webhooks.ssrf.resolve_host", resolver)
    return resolver


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'dns.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(
        Settings(driver="fake", database_url=url, api_key_pepper=PEPPER, rate_limit_enabled=False)
    )
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
async def key(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def create(client: httpx.AsyncClient, key: str, request_id: str) -> httpx.Response:
    return await client.post(
        HOOKS,
        headers={**auth(key), "X-Request-Id": request_id},
        json={"url": URL, "enabled": False},
    )


async def refusal_row(client: httpx.AsyncClient, key: str, request_id: str) -> dict[str, Any]:
    response = await client.get(
        AUDIT, headers=auth(key), params={"limit": 100, "request_id": request_id}
    )
    assert response.status_code == 200, response.text
    [row] = response.json()["data"]
    found: dict[str, Any] = row
    return found


# --- the API answers ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        socket.gaierror(socket.EAI_NONAME, "unknown host"),
        socket.gaierror(socket.EAI_NODATA, "no address"),
        [],
    ],
    ids=["nxdomain", "nodata", "empty_answer"],
)
async def test_a_host_that_does_not_resolve_is_422_without_a_retry(
    client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch, failure: Step
) -> None:
    resolver = install(monkeypatch, failure)

    response = await create(client, key, "req-nx")

    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "UNPROCESSABLE"
    assert response.json()["error"]["message"] == "webhook url rejected: host does not resolve"
    assert resolver.calls == 1
    row = await refusal_row(client, key, "req-nx")
    assert row["outcome"] == "denied"
    assert row["details"]["reason"] == "not_resolved"


@pytest.mark.parametrize("failure", TRANSIENT, ids=TRANSIENT_IDS)
async def test_a_transient_failure_then_an_answer_creates_the_endpoint(
    client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch, failure: Step
) -> None:
    resolver = install(monkeypatch, failure, [PUBLIC_IP])

    response = await create(client, key, "req-recovered")

    assert response.status_code == 201, response.text
    assert resolver.calls == 2


@pytest.mark.parametrize("failure", TRANSIENT, ids=TRANSIENT_IDS)
async def test_two_transient_failures_answer_503_dns_unavailable_with_retry_after(
    client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch, failure: Step
) -> None:
    resolver = install(monkeypatch, failure)

    response = await create(client, key, "req-dns-down")

    assert response.status_code == 503, response.text
    error = response.json()["error"]
    assert error["code"] == "DNS_UNAVAILABLE"
    assert error["message"] == ("could not verify the webhook host: DNS lookup failed; try again")
    assert "does not resolve" not in response.text
    assert error["details"]["reason"] == "dns_unavailable"
    assert int(response.headers["Retry-After"]) >= 1
    assert resolver.calls == 2
    row = await refusal_row(client, key, "req-dns-down")
    assert row["outcome"] == "error"
    assert row["details"]["reason"] == "dns_unavailable"
    assert row["details"]["error_code"] == "DNS_UNAVAILABLE"


async def test_a_nxdomain_after_a_transient_failure_is_still_a_verdict(
    client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(monkeypatch, TRANSIENT[0], socket.gaierror(socket.EAI_NONAME, "unknown host"))

    response = await create(client, key, "req-late-nx")

    assert response.status_code == 422, response.text


async def test_the_patch_route_answers_503_too(
    client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(monkeypatch, [PUBLIC_IP])
    created = await create(client, key, "req-seed")
    endpoint_id = created.json()["data"]["id"]
    install(monkeypatch, TRANSIENT[2])

    response = await client.patch(
        f"{HOOKS}/{endpoint_id}", headers=auth(key), json={"url": "https://example.org/x"}
    )

    assert response.status_code == 503, response.text
    assert response.json()["error"]["code"] == "DNS_UNAVAILABLE"


# --- the guard itself -----------------------------------------------------------------------


async def test_vet_url_raises_host_not_resolved_for_nxdomain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(monkeypatch, socket.gaierror(socket.EAI_NONAME, "unknown host"))

    with pytest.raises(HostNotResolved) as raised:
        await vet_url(URL)

    assert isinstance(raised.value, UrlRejected)
    assert str(raised.value) == "host does not resolve"


async def test_vet_url_raises_resolver_unavailable_not_url_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(monkeypatch, TRANSIENT[0])

    with pytest.raises(ResolverUnavailable) as raised:
        await vet_url(URL)

    assert not isinstance(raised.value, UrlRejected)


async def test_vet_url_still_rejects_a_private_answer_after_a_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(monkeypatch, TRANSIENT[2], ["10.1.2.3"])

    with pytest.raises(UrlRejected, match="private"):
        await vet_url(URL)


async def test_a_stalled_resolver_is_cut_at_the_attempt_cap_and_retried_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempt_cap_s = 0.05
    monkeypatch.setattr(ssrf, "ATTEMPT_TIMEOUT_S", attempt_cap_s)
    calls = 0

    async def stall(host: str) -> list[str]:
        nonlocal calls
        calls += 1
        await asyncio.Event().wait()
        return []

    monkeypatch.setattr("sandfort.webhooks.ssrf.resolve_host", stall)
    started = time.monotonic()

    with pytest.raises(ResolverUnavailable):
        await vet_url(URL)

    elapsed = time.monotonic() - started
    assert calls == 2
    assert 2 * attempt_cap_s <= elapsed < 2 * attempt_cap_s + 1.0


def test_the_worst_case_validation_time_stays_under_six_seconds() -> None:
    worst_s = 2 * DEFAULT_ATTEMPT_TIMEOUT_S + DEFAULT_RETRY_PAUSE_S

    assert DEFAULT_ATTEMPT_TIMEOUT_S == 2.5
    assert DEFAULT_RETRY_PAUSE_S == 0.5
    assert worst_s < 6.0
