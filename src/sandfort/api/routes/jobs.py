"""``GET /v1/jobs``: read-only, org-scoped, cursor-paginated view of background jobs."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, Protocol, cast

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict

from sandfort.api.deps import get_uow
from sandfort.api.envelope import Envelope, ok
from sandfort.api.pagination import JOBS, decode_cursor, encode_cursor
from sandfort.api.query_guard import KnownQuery, single_valued
from sandfort.api.schemas.common import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, Meta
from sandfort.auth.label_scope import current_label_scope
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.db.models.jobs import JobState
from sandfort.db.repositories.ports import JobRecord, UnitOfWorkPort
from sandfort.domain.org import Scope
from sandfort.errors import NotFound
from sandfort.services.image_builds import IMAGE_BUILD
from sandfort.services.snapshots import SNAPSHOT_CREATE, snapshot_in_label_scope

router = APIRouter(prefix="/v1/jobs", tags=["jobs"])

SPEC_KEY = "spec"  # payload key of an image build job: never returned to a label-scoped caller
SNAPSHOT_JOB_KINDS = frozenset({IMAGE_BUILD, SNAPSHOT_CREATE})
SCAN_CAP = 10 * MAX_PAGE_SIZE  # rows a filtered list scans per request

Reader = Annotated[Principal, Depends(require_scopes(Scope.SANDBOXES_READ))]
Uow = Annotated[UnitOfWorkPort, Depends(get_uow)]
ListOnce = Annotated[None, Depends(single_valued("state", "cursor", "limit"))]


class OrgJobReader(Protocol):
    """Tenant-facing reads the SQL job repository adds to the frozen queue port."""

    async def get_for_org(self, org_id: str, job_id: str) -> JobRecord | None: ...

    async def list_for_org(
        self, org_id: str, *, state: str | None = None, cursor: str | None = None, limit: int = 50
    ) -> Sequence[JobRecord]: ...


class JobResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    kind: str
    state: str
    attempts: int
    payload: dict[str, Any]
    run_after: datetime
    last_error: str | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_record(cls, job: JobRecord) -> "JobResponse":
        """The wire form of ``job``; a label-scoped caller never receives an image build spec."""
        payload = dict(job.payload)
        if current_label_scope() is not None:
            payload.pop(SPEC_KEY, None)
        return cls(
            id=job.id,
            kind=job.kind,
            state=job.state,
            attempts=job.attempts,
            payload=payload,
            run_after=job.run_after,
            last_error=job.last_error,
            created_at=job.created_at,
            updated_at=job.updated_at,
        )


def _reader(uow: UnitOfWorkPort) -> OrgJobReader:
    return cast(OrgJobReader, uow.jobs)


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Visible jobs found by one filtered scan, and where an interrupted scan stopped."""

    rows: list[JobRecord]
    resume_after: str | None  # last scanned job id when the scan cap cut it short, else None


def _needs_filtering(principal: Principal) -> bool:
    """True when some job may be hidden from this caller, so the list must be scanned."""
    return current_label_scope() is not None or Scope.SNAPSHOTS_READ not in principal.scopes


async def _job_visible(uow: UnitOfWorkPort, principal: Principal, job: JobRecord) -> bool:
    """True when the caller may see ``job``.

    Image build and snapshot create jobs need ``snapshots:read`` from every caller. Unscoped
    requests otherwise see every job. A label-scoped one sees a job whose payload ``sandbox_id``
    (if any) resolves through the scoped sandbox repository and whose ``snapshot_id`` or
    ``snapshot`` (if any) passes the snapshot scope check; jobs naming neither (e.g. warm-pool
    refills) stay visible.
    """
    if job.kind in SNAPSHOT_JOB_KINDS and Scope.SNAPSHOTS_READ not in principal.scopes:
        return False
    if current_label_scope() is None:
        return True
    org_id = principal.org_id
    sandbox_id = job.payload.get("sandbox_id")
    if sandbox_id is not None and await uow.sandboxes.get(org_id, str(sandbox_id)) is None:
        return False
    snapshot_id = job.payload.get("snapshot_id", job.payload.get("snapshot"))
    if snapshot_id is None:
        return True
    snapshot = await uow.snapshots.get(org_id, str(snapshot_id))
    return snapshot is not None and await snapshot_in_label_scope(uow, snapshot)


async def _filtered_rows(
    uow: UnitOfWorkPort, principal: Principal, state: str | None, cursor: str | None, want: int
) -> ScanResult:
    """Up to ``want`` visible jobs after ``cursor``, scanning past the ones hidden from the caller.

    At most ``SCAN_CAP`` rows are scanned per call; when that bound stops the scan early,
    ``resume_after`` is the id of the last scanned row so the client can continue from there.
    """
    visible: list[JobRecord] = []
    scanned = 0
    while len(visible) < want:
        rows = await _reader(uow).list_for_org(
            principal.org_id, state=state, cursor=cursor, limit=MAX_PAGE_SIZE
        )
        for row in rows:
            if await _job_visible(uow, principal, row):
                visible.append(row)
                if len(visible) == want:
                    return ScanResult(visible, None)
        scanned += len(rows)
        if len(rows) < MAX_PAGE_SIZE:
            break
        cursor = rows[-1].id
        if scanned >= SCAN_CAP:
            return ScanResult(visible, cursor)
    return ScanResult(visible, None)


@router.get("")
async def list_jobs(
    principal: Reader,
    uow: Uow,
    _known: KnownQuery,
    _once: ListOnce,
    state: JobState | None = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
) -> Envelope[list[JobResponse]]:
    """List jobs, newest cursor page first.

    A caller that cannot see every job (a label-scoped key, or one without ``snapshots:read``)
    gets a filtered list. The server scans at most ``10 x`` the max page size
    (``SCAN_CAP`` = 1000) rows per request; when that bound is reached before the page is full,
    the page may be short or empty and ``meta.next_cursor`` points at the last scanned row, so
    the client continues from the cursor until it is ``null``. A cursor is bound to this list
    and to the ``state`` filter; another list or state answers 422 naming the differing field.
    """
    state_value = None if state is None else state.value
    bound = {"state": state_value}
    after = None if cursor is None else decode_cursor(cursor, bound, resource=JOBS)
    resume_after: str | None = None
    async with uow:
        # Fetch one extra row to learn whether another page exists.
        if _needs_filtering(principal):
            scan = await _filtered_rows(uow, principal, state_value, after, limit + 1)
            rows, resume_after = scan.rows, scan.resume_after
        else:
            rows = list(
                await _reader(uow).list_for_org(
                    principal.org_id, state=state_value, cursor=after, limit=limit + 1
                )
            )
    page = [JobResponse.from_record(row) for row in rows[:limit]]
    if resume_after is not None:
        next_cursor: str | None = encode_cursor(resume_after, bound, resource=JOBS)
    elif len(rows) > limit:
        next_cursor = encode_cursor(page[-1].id, bound, resource=JOBS)
    else:
        next_cursor = None
    return ok(page, meta=Meta(next_cursor=next_cursor))


@router.get("/{job_id}")
async def get_job(job_id: str, principal: Reader, uow: Uow) -> Envelope[JobResponse]:
    async with uow:
        job = await _reader(uow).get_for_org(principal.org_id, job_id)
        visible = job is not None and await _job_visible(uow, principal, job)
    if job is None or not visible:
        raise NotFound(f"job {job_id} not found")
    return ok(JobResponse.from_record(job))
