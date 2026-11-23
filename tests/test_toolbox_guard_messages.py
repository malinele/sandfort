"""``load_started_sandbox`` messages: a deleted sandbox says so, other states keep the old text.

Daemon-free: a stub unit of work serves one sandbox; nothing touches a database or driver.
"""

from datetime import UTC, datetime
from typing import cast

import pytest

from sandfort.clock import FrozenClock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.errors import NO_CONTAINER, Conflict, NotFound
from sandfort.toolbox.guards import load_started_sandbox

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
ORG = "org_1"
SANDBOX_ID = "sbx_1"
DELETED_MESSAGE = "the sandbox was deleted; create a new one"


class _StubSandboxes:
    def __init__(self, sandbox: Sandbox | None) -> None:
        self._sandbox = sandbox
        self.updates = 0

    async def get(self, org_id: str, sandbox_id: str) -> Sandbox | None:
        return self._sandbox

    async def update(self, org_id: str, sandbox: Sandbox, *, expected_version: int) -> Sandbox:
        self.updates += 1
        return sandbox


class _StubUow:
    def __init__(self, sandbox: Sandbox | None) -> None:
        self.sandboxes = _StubSandboxes(sandbox)
        self.commits = 0

    async def commit(self) -> None:
        self.commits += 1


def _sandbox(state: SandboxState, driver_ref: str | None = "ctr_1") -> Sandbox:
    return Sandbox(
        id=SANDBOX_ID,
        org_id=ORG,
        name="guard",
        state=state,
        image_ref="alpine:3.20",
        driver="fake",
        driver_ref=driver_ref,
        created_at=NOW,
        updated_at=NOW,
    )


async def _load(uow: _StubUow) -> Sandbox:
    port = cast(UnitOfWorkPort, uow)
    return await load_started_sandbox(port, ORG, SANDBOX_ID, FrozenClock(NOW))


async def _conflict(uow: _StubUow) -> Conflict:
    with pytest.raises(Conflict) as caught:
        await _load(uow)
    return caught.value


@pytest.mark.parametrize("state", [SandboxState.DESTROYED, SandboxState.DESTROYING])
async def test_deleted_sandbox_says_it_was_deleted(state: SandboxState) -> None:
    error = await _conflict(_StubUow(_sandbox(state)))

    assert error.status == 409
    assert error.message == DELETED_MESSAGE
    assert error.reason == NO_CONTAINER
    assert error.details == {"reason": NO_CONTAINER, "state": state.value}


async def test_destroyed_sandbox_without_driver_ref_still_says_it_was_deleted() -> None:
    error = await _conflict(_StubUow(_sandbox(SandboxState.DESTROYED, driver_ref=None)))

    assert error.message == DELETED_MESSAGE
    assert error.details["state"] == "destroyed"


async def test_stopped_sandbox_keeps_the_started_requirement_message() -> None:
    error = await _conflict(_StubUow(_sandbox(SandboxState.STOPPED)))

    assert error.status == 409
    assert error.message == "sandbox is stopped; toolbox calls require a started sandbox"
    assert error.reason == NO_CONTAINER
    assert error.details == {
        "reason": NO_CONTAINER,
        "state": "stopped",
        "stop_cause": "unknown",
    }


async def test_started_sandbox_without_driver_ref_keeps_the_message_for_its_state() -> None:
    error = await _conflict(_StubUow(_sandbox(SandboxState.STARTED, driver_ref=None)))

    assert error.message == "sandbox is started; toolbox calls require a started sandbox"
    assert error.reason == NO_CONTAINER
    assert error.details == {"reason": NO_CONTAINER, "state": "started"}


async def test_started_sandbox_with_driver_ref_is_returned_and_touched() -> None:
    uow = _StubUow(_sandbox(SandboxState.STARTED))

    loaded = await _load(uow)

    assert loaded.state is SandboxState.STARTED
    assert uow.sandboxes.updates == 1
    assert uow.commits == 1


async def test_missing_sandbox_is_not_found() -> None:
    with pytest.raises(NotFound):
        await _load(_StubUow(None))
