"""SDK: the ``inherit_resources`` create option and the snapshot ``resources`` record."""

# ruff: noqa: F811  (pytest fixtures imported from test_sdk are shadowed by test parameters)

import json
import sys
from pathlib import Path

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import pytest  # noqa: E402
from sandfort_sdk import AsyncClient, Resources, SnapshotInfo  # noqa: E402

from test_sdk import api, call, client, envelope, kind, sandbox_json  # noqa: E402, F401

SNAPSHOT_PAYLOAD = {
    "id": "snp_01HZZZZZZZZZZZZZZZZZZZZZZZ",
    "name": "base",
    "state": "ready",
    "image_ref": "sandfort/base:1",
    "layer_count": 3,
    "created_at": "2026-11-24T06:00:00+00:00",
}
SNAPSHOT_RESOURCES = {"cpu_millicores": 500, "memory_mib": 256, "disk_gib": 1}


async def test_create_with_inherit_resources_sends_the_flag(api, client):
    route = api.post("/v1/sandboxes").respond(201, json=envelope(sandbox_json("started")))

    await call(client.create_sandbox, inherit_resources=True)

    assert json.loads(route.calls.last.request.content) == {"inherit_resources": True}


async def test_create_without_inherit_resources_leaves_the_field_out(api, client):
    route = api.post("/v1/sandboxes").respond(201, json=envelope(sandbox_json("started")))

    await call(client.create_sandbox, name="demo")

    assert "inherit_resources" not in json.loads(route.calls.last.request.content)


async def test_async_client_create_with_inherit_resources_sends_the_flag(api):
    route = api.post("/v1/sandboxes").respond(201, json=envelope(sandbox_json("started")))
    async_client = AsyncClient("http://sandfort.test", "sf_test_key", max_retries=0)

    try:
        await async_client.create_sandbox(inherit_resources=True)
    finally:
        await async_client.aclose()

    assert json.loads(route.calls.last.request.content) == {"inherit_resources": True}


def test_snapshot_info_parses_the_recorded_resources():
    info = SnapshotInfo.from_payload({**SNAPSHOT_PAYLOAD, "resources": SNAPSHOT_RESOURCES})

    assert info.resources == Resources(500, 256, 1)


@pytest.mark.parametrize("extra", [{}, {"resources": None}], ids=["missing", "null"])
def test_snapshot_info_without_recorded_resources_reports_none(extra):
    info = SnapshotInfo.from_payload({**SNAPSHOT_PAYLOAD, **extra})

    assert info.resources is None
