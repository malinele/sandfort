"""The ``snapshot.create`` job handler: runs the snapshot commit path off the request.

Idempotent on retry because ``SnapshotService.complete_create`` only acts on a ``pending``
row: a retry after a finished attempt returns the stored outcome, and a retry after a crash
mid-commit commits again to the same per-snapshot tag. Importing this module registers the
handler in the default registry (``api.wiring`` does so for the server).
"""

from collections.abc import Mapping
from typing import Any

from sandfort.services.snapshots import SNAPSHOT_CREATE, SnapshotCreateJob, SnapshotService
from sandfort.workers.handlers import JobContext, register


@register(SNAPSHOT_CREATE)
async def handle_snapshot_create(payload: Mapping[str, Any], context: JobContext) -> None:
    job = SnapshotCreateJob.from_payload(payload)
    service = SnapshotService(context.uow_factory, context.driver, context.clock)
    await service.complete_create(job.org_id, job.snapshot_id)
