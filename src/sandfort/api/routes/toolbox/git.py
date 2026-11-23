"""``/git`` toolbox routes: clone, status, add, commit, push and pull.

Authentication, org scoping and the error envelope are the same as the process routes;
the work (validation, guard, audit, ephemeral credentials, driver exec) lives in
``toolbox.git.GitToolbox``. A request credential is handed to that one call and never
echoed: no response model carries it and every surfaced text is scrubbed. Status is
served both as ``GET ?path=`` and as ``POST`` with a ``GitStatusRequest`` body.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from sandfort.api.deps import get_audit_recorder, get_driver, get_uow
from sandfort.api.envelope import Envelope, ok
from sandfort.api.query_guard import KnownQuery, single_valued
from sandfort.api.routes.toolbox.scope_guard import require_visible_sandbox
from sandfort.api.schemas import toolbox_git as schemas
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.clock import SystemClock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.org import Scope
from sandfort.drivers.base import SandboxDriver
from sandfort.services.audit import AuditRecorder
from sandfort.toolbox.fs import Actor
from sandfort.toolbox.git import GitOutput, GitToolbox, RepoStatus

router = APIRouter(
    prefix="/v1/sandboxes/{sandbox_id}/toolbox/git",
    tags=["toolbox"],
    dependencies=[Depends(require_visible_sandbox)],
)

_CLOCK = SystemClock()

ToolboxUser = Annotated[Principal, Depends(require_scopes(Scope.TOOLBOX))]
Uow = Annotated[UnitOfWorkPort, Depends(get_uow)]
Driver = Annotated[SandboxDriver, Depends(get_driver)]
Recorder = Annotated[AuditRecorder, Depends(get_audit_recorder)]
PathQuery = Annotated[str, Query()]
PathOnce = Annotated[None, Depends(single_valued("path"))]


def _toolbox(driver: SandboxDriver, recorder: AuditRecorder) -> GitToolbox:
    return GitToolbox(driver, recorder, _CLOCK)


def _actor(principal: Principal) -> Actor:
    return Actor(org_id=principal.org_id, key_id=principal.key_id)


def _operation(result: GitOutput) -> schemas.GitOperationResponse:
    return schemas.GitOperationResponse(path=result.path, output=result.output)


def _status(result: RepoStatus) -> schemas.GitStatusResponse:
    return schemas.GitStatusResponse(
        branch=result.branch,
        ahead=result.ahead,
        behind=result.behind,
        files=[
            schemas.GitFileStatus(path=item.path, index=item.index, worktree=item.worktree)
            for item in result.files
        ],
    )


@router.post("/clone")
async def clone_repository(
    sandbox_id: str,
    body: schemas.GitCloneRequest,
    principal: ToolboxUser,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
) -> Envelope[schemas.GitOperationResponse]:
    result = await _toolbox(driver, recorder).clone(
        uow,
        _actor(principal),
        sandbox_id,
        body.url,
        body.path,
        branch=body.branch,
        depth=body.depth,
        credential=body.credential,
    )
    return ok(_operation(result))


@router.get("/status")
async def repository_status(
    sandbox_id: str,
    path: PathQuery,
    principal: ToolboxUser,
    _known: KnownQuery,
    _once: PathOnce,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
) -> Envelope[schemas.GitStatusResponse]:
    result = await _toolbox(driver, recorder).status(uow, _actor(principal), sandbox_id, path)
    return ok(_status(result))


@router.post("/status")
async def repository_status_by_body(
    sandbox_id: str,
    body: schemas.GitStatusRequest,
    principal: ToolboxUser,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
) -> Envelope[schemas.GitStatusResponse]:
    result = await _toolbox(driver, recorder).status(
        uow, _actor(principal), sandbox_id, body.path
    )
    return ok(_status(result))


@router.post("/add")
async def add_files(
    sandbox_id: str,
    body: schemas.GitAddRequest,
    principal: ToolboxUser,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
) -> Envelope[schemas.GitOperationResponse]:
    result = await _toolbox(driver, recorder).add(
        uow, _actor(principal), sandbox_id, body.path, body.files
    )
    return ok(_operation(result))


@router.post("/commit")
async def commit_changes(
    sandbox_id: str,
    body: schemas.GitCommitRequest,
    principal: ToolboxUser,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
) -> Envelope[schemas.GitCommitResponse]:
    sha = await _toolbox(driver, recorder).commit(
        uow,
        _actor(principal),
        sandbox_id,
        body.path,
        body.message,
        author_name=body.author_name,
        author_email=body.author_email,
    )
    return ok(schemas.GitCommitResponse(sha=sha))


@router.post("/push")
async def push_changes(
    sandbox_id: str,
    body: schemas.GitPushRequest,
    principal: ToolboxUser,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
) -> Envelope[schemas.GitOperationResponse]:
    result = await _toolbox(driver, recorder).push(
        uow,
        _actor(principal),
        sandbox_id,
        body.path,
        remote=body.remote,
        branch=body.branch,
        credential=body.credential,
        remote_url=body.remote_url,
    )
    return ok(_operation(result))


@router.post("/pull")
async def pull_changes(
    sandbox_id: str,
    body: schemas.GitPullRequest,
    principal: ToolboxUser,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
) -> Envelope[schemas.GitOperationResponse]:
    result = await _toolbox(driver, recorder).pull(
        uow,
        _actor(principal),
        sandbox_id,
        body.path,
        remote=body.remote,
        branch=body.branch,
        credential=body.credential,
        remote_url=body.remote_url,
    )
    return ok(_operation(result))
