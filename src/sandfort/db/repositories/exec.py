"""SQLAlchemy implementations of ``ExecSessionRepository`` and ``ExecCommandRepository``.

Every method filters on ``org_id`` in SQL, so another org's row is indistinguishable from a
missing one. ``ExecCommandRepository.finish`` only moves a command out of ``running``: the
first outcome (natural exit or kill) wins and later calls return the stored record unchanged.
"""

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.models.exec import ExecCommandRow, ExecCommandState, ExecSessionRow
from sandfort.db.repositories.ports import ExecCommandRecord, ExecSessionRecord
from sandfort.db.support import as_utc, flush_or_conflict, opt_utc, rowcount


def _session_record(row: ExecSessionRow) -> ExecSessionRecord:
    return ExecSessionRecord(
        id=row.id,
        org_id=row.org_id,
        sandbox_id=row.sandbox_id,
        cwd=row.cwd,
        env={str(name): str(value) for name, value in row.env.items()},
        state=row.state,
        created_at=as_utc(row.created_at),
        updated_at=as_utc(row.updated_at),
    )


def _command_record(row: ExecCommandRow) -> ExecCommandRecord:
    return ExecCommandRecord(
        id=row.id,
        org_id=row.org_id,
        sandbox_id=row.sandbox_id,
        session_id=row.session_id,
        argv=list(row.argv),
        state=row.state,
        exit_code=row.exit_code,
        stdout_bytes=row.stdout_bytes,
        stderr_bytes=row.stderr_bytes,
        created_at=as_utc(row.created_at),
        finished_at=opt_utc(row.finished_at),
    )


class SqlExecSessionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, session: ExecSessionRecord) -> None:
        self._session.add(
            ExecSessionRow(
                id=session.id,
                org_id=session.org_id,
                sandbox_id=session.sandbox_id,
                cwd=session.cwd,
                env=dict(session.env),
                state=session.state,
                created_at=as_utc(session.created_at),
                updated_at=as_utc(session.updated_at),
            )
        )
        await flush_or_conflict(self._session, "exec session id already exists")

    async def get(self, org_id: str, session_id: str) -> ExecSessionRecord | None:
        stmt = (
            select(ExecSessionRow)
            .where(ExecSessionRow.org_id == org_id, ExecSessionRow.id == session_id)
            .execution_options(populate_existing=True)
        )
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return None if row is None else _session_record(row)

    async def list_for_sandbox(self, org_id: str, sandbox_id: str) -> Sequence[ExecSessionRecord]:
        stmt = (
            select(ExecSessionRow)
            .where(ExecSessionRow.org_id == org_id, ExecSessionRow.sandbox_id == sandbox_id)
            .order_by(ExecSessionRow.id)
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_session_record(row) for row in rows]

    async def set_state(
        self, org_id: str, session_id: str, state: str, at: datetime
    ) -> ExecSessionRecord | None:
        return await self._update(org_id, session_id, {"state": state, "updated_at": as_utc(at)})

    async def set_cwd(
        self, org_id: str, session_id: str, cwd: str | None, at: datetime
    ) -> ExecSessionRecord | None:
        return await self._update(org_id, session_id, {"cwd": cwd, "updated_at": as_utc(at)})

    async def delete(self, org_id: str, session_id: str) -> bool:
        stmt = (
            delete(ExecSessionRow)
            .where(ExecSessionRow.org_id == org_id, ExecSessionRow.id == session_id)
            .execution_options(synchronize_session=False)
        )
        return rowcount(await self._session.execute(stmt)) > 0

    async def _update(
        self, org_id: str, session_id: str, values: dict[str, Any]
    ) -> ExecSessionRecord | None:
        stmt = (
            update(ExecSessionRow)
            .where(ExecSessionRow.org_id == org_id, ExecSessionRow.id == session_id)
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        if rowcount(await self._session.execute(stmt)) == 0:
            return None
        return await self.get(org_id, session_id)


class SqlExecCommandRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, command: ExecCommandRecord) -> None:
        self._session.add(
            ExecCommandRow(
                id=command.id,
                org_id=command.org_id,
                sandbox_id=command.sandbox_id,
                session_id=command.session_id,
                argv=list(command.argv),
                state=command.state,
                exit_code=command.exit_code,
                stdout_bytes=command.stdout_bytes,
                stderr_bytes=command.stderr_bytes,
                created_at=as_utc(command.created_at),
                finished_at=opt_utc(command.finished_at),
            )
        )
        await flush_or_conflict(self._session, "exec command id already exists")

    async def get(self, org_id: str, command_id: str) -> ExecCommandRecord | None:
        stmt = (
            select(ExecCommandRow)
            .where(ExecCommandRow.org_id == org_id, ExecCommandRow.id == command_id)
            .execution_options(populate_existing=True)
        )
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return None if row is None else _command_record(row)

    async def list_for_session(self, org_id: str, session_id: str) -> Sequence[ExecCommandRecord]:
        stmt = (
            select(ExecCommandRow)
            .where(ExecCommandRow.org_id == org_id, ExecCommandRow.session_id == session_id)
            .order_by(ExecCommandRow.id)
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_command_record(row) for row in rows]

    async def finish(
        self,
        org_id: str,
        command_id: str,
        *,
        state: str,
        exit_code: int | None,
        stdout_bytes: int,
        stderr_bytes: int,
        at: datetime,
    ) -> ExecCommandRecord | None:
        stmt = (
            update(ExecCommandRow)
            .where(
                ExecCommandRow.org_id == org_id,
                ExecCommandRow.id == command_id,
                ExecCommandRow.state == ExecCommandState.RUNNING.value,
            )
            .values(
                state=state,
                exit_code=exit_code,
                stdout_bytes=stdout_bytes,
                stderr_bytes=stderr_bytes,
                finished_at=as_utc(at),
            )
            .execution_options(synchronize_session=False)
        )
        await self._session.execute(stmt)
        return await self.get(org_id, command_id)

    async def delete_for_session(self, org_id: str, session_id: str) -> int:
        stmt = (
            delete(ExecCommandRow)
            .where(ExecCommandRow.org_id == org_id, ExecCommandRow.session_id == session_id)
            .execution_options(synchronize_session=False)
        )
        return rowcount(await self._session.execute(stmt))
