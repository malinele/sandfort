"""Round 96 (B8): a driver answer that is not a real exit code is written as unknown.

``bool`` is a subclass of ``int`` in Python, so a driver that answers ``True`` for the exit
code would otherwise land in the audit row as ``exit_code: true``. The row must say ``null``
(unknown) instead, as it does for any other answer that is not an integer.
"""

from __future__ import annotations

import pytest

from sandfort.drivers.fake import FakeDriver
from sandfort.workers.stop_facts import StopFacts, gather_stop_facts


class _OddExitDriver(FakeDriver):
    """Answers the exit code with a value chosen by the test."""

    def __init__(self, answer: object) -> None:
        super().__init__()
        self._answer = answer

    async def container_oom_killed(self, ref: str) -> bool:
        return False

    async def container_exit_code(self, ref: str) -> int | None:
        return self._answer  # type: ignore[return-value]


@pytest.mark.parametrize("answer", [True, False, "137", 137.0])
async def test_an_exit_code_that_is_not_an_integer_is_written_as_unknown(answer: object) -> None:
    facts = await gather_stop_facts(_OddExitDriver(answer), "ref", "sbx")

    assert facts == StopFacts(oom_killed=None, exit_code=None)


async def test_a_real_integer_exit_code_is_kept() -> None:
    facts = await gather_stop_facts(_OddExitDriver(0), "ref", "sbx")

    assert facts == StopFacts(oom_killed=None, exit_code=0)
