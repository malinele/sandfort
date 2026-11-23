"""r66a: a resize keeps the root filesystem, against a real local daemon (S1).

Through the api on ``alpine:3.20``: files are written into the root filesystem, the sandbox is
stopped, resized and started again, and the files must still be there. The ``sf-resize-<id>``
image stays while the sandbox lives (the new container is based on it; the next resize commits to
the same tag, so a second resize must work on overlay2 too) and is gone after the delete. A reset
after the resize still wipes.
"""

import uuid
from dataclasses import replace
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

import test_docker_snapshots as snapshots
from sandfort.config import FAULT_RESIZE_CREATE_FAIL
from sandfort.drivers.base import resize_image_reference
from test_docker_snapshots import IMAGE, Cleanup, call

pytestmark = pytest.mark.docker

# the daemon-backed fixtures of the snapshot tests (an assignment, so the test parameters of the
# same name are not redefinitions of an import)
app = snapshots.app
client = snapshots.client
http = snapshots.http
image = snapshots.image
key = snapshots.key
cleanup = snapshots.cleanup

docker = pytest.importorskip("docker")

PATHS = ("/tmp/sf-r66-marker", "/root/sf-r66-marker")


async def started_sandbox(http: httpx.AsyncClient, key: str, cleanup: Cleanup) -> str:
    created = await call(http, "POST", "/v1/sandboxes", key, status=201, json={"snapshot": IMAGE})
    cleanup.sandbox_ids.append(created["id"])
    assert created["state"] == "started", created
    sandbox_id: str = created["id"]
    return sandbox_id


async def write(http: httpx.AsyncClient, key: str, sandbox_id: str, path: str, text: str) -> None:
    await call(
        http,
        "PUT",
        f"/v1/sandboxes/{sandbox_id}/toolbox/fs/upload",
        key,
        status=200,
        params={"path": path},
        content=text.encode(),
    )


async def read(http: httpx.AsyncClient, key: str, sandbox_id: str, path: str) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {key}"}
    response = await http.get(
        f"/v1/sandboxes/{sandbox_id}/toolbox/fs/download",
        headers=headers,
        params={"path": path, "inline": "true"},
    )
    body: dict[str, Any] = response.json()
    return {"status": response.status_code, "body": body}


async def stop_resize_start(
    http: httpx.AsyncClient, key: str, sandbox_id: str, **resources: int
) -> dict[str, Any]:
    base = f"/v1/sandboxes/{sandbox_id}"
    stopped = await call(http, "POST", f"{base}/stop", key, status=200)
    assert stopped["state"] == "stopped", stopped
    await call(http, "POST", f"{base}/resize", key, status=200, json=resources)
    started = await call(http, "POST", f"{base}/start", key, status=200)
    assert started["state"] == "started", started
    return started


def resize_tags(client: Any, sandbox_id: str) -> list[str]:
    wanted = resize_image_reference(sandbox_id)
    return [
        tag for item in client.images.list() for tag in item.tags if tag.split(":")[0] == wanted
    ]


async def test_cpu_resize_keeps_files_and_the_resize_tag_lives_and_dies_with_the_sandbox(
    client: Any, http: httpx.AsyncClient, key: str, cleanup: Cleanup
) -> None:
    sandbox_id = await started_sandbox(http, key, cleanup)
    markers = {path: f"keep-{uuid.uuid4().hex}" for path in PATHS}
    for path, text in markers.items():
        await write(http, key, sandbox_id, path, text)

    started = await stop_resize_start(http, key, sandbox_id, cpu_millicores=300)

    assert started["resources"]["cpu_millicores"] == 300
    for path, text in markers.items():
        got = await read(http, key, sandbox_id, path)
        assert got["status"] == 200, got
        assert got["body"]["data"]["content"] == text
    wanted = resize_image_reference(sandbox_id)
    assert [tag.split(":")[0] for tag in resize_tags(client, sandbox_id)] == [wanted]

    base_image = client.api.inspect_container(f"sf-{sandbox_id}")["Image"]
    await call(http, "DELETE", f"/v1/sandboxes/{sandbox_id}", key, status=200)
    assert resize_tags(client, sandbox_id) == []
    with pytest.raises(docker.errors.ImageNotFound):  # the resize image goes with its sandbox
        client.images.get(base_image)


async def test_a_second_resize_keeps_files_of_both_rounds(
    client: Any, http: httpx.AsyncClient, key: str, cleanup: Cleanup
) -> None:
    sandbox_id = await started_sandbox(http, key, cleanup)
    await write(http, key, sandbox_id, PATHS[0], "first")
    await stop_resize_start(http, key, sandbox_id, cpu_millicores=300)
    await write(http, key, sandbox_id, PATHS[1], "second")
    first_image = client.images.get(resize_image_reference(sandbox_id)).id

    await stop_resize_start(http, key, sandbox_id, memory_mib=768)  # the regression: 404 on start

    for path, text in zip(PATHS, ("first", "second"), strict=True):
        got = await read(http, key, sandbox_id, path)
        assert got["body"]["data"]["content"] == text
    assert len(resize_tags(client, sandbox_id)) == 1
    with pytest.raises(docker.errors.ImageNotFound):  # the image the tag moved off is removed
        client.images.get(first_image)
    await call(http, "DELETE", f"/v1/sandboxes/{sandbox_id}", key, status=200)
    assert resize_tags(client, sandbox_id) == []


async def test_a_disk_resize_keeps_files(
    client: Any, http: httpx.AsyncClient, key: str, cleanup: Cleanup
) -> None:
    sandbox_id = await started_sandbox(http, key, cleanup)
    await write(http, key, sandbox_id, PATHS[1], "on-disk")

    started = await stop_resize_start(http, key, sandbox_id, disk_gib=4)

    assert started["resources"]["disk_gib"] == 4
    got = await read(http, key, sandbox_id, PATHS[1])
    assert got["body"]["data"]["content"] == "on-disk"
    await call(http, "DELETE", f"/v1/sandboxes/{sandbox_id}", key, status=200)
    assert resize_tags(client, sandbox_id) == []


async def test_reset_after_a_resize_still_wipes(
    http: httpx.AsyncClient, key: str, cleanup: Cleanup
) -> None:
    sandbox_id = await started_sandbox(http, key, cleanup)
    await write(http, key, sandbox_id, PATHS[1], "doomed")
    await stop_resize_start(http, key, sandbox_id, cpu_millicores=300)

    await call(http, "POST", f"/v1/sandboxes/{sandbox_id}/reset", key, status=200)

    got = await read(http, key, sandbox_id, PATHS[1])
    assert got["status"] == 404, got
    await call(http, "DELETE", f"/v1/sandboxes/{sandbox_id}", key, status=200)


async def test_a_create_that_fails_after_the_destroy_is_recovered_from_the_resize_image(
    app: FastAPI, client: Any, http: httpx.AsyncClient, key: str, cleanup: Cleanup
) -> None:
    sandbox_id = await started_sandbox(http, key, cleanup)
    await write(http, key, sandbox_id, PATHS[1], "survives-the-crash")
    base = f"/v1/sandboxes/{sandbox_id}"
    await call(http, "POST", f"{base}/stop", key, status=200)
    await call(http, "POST", f"{base}/resize", key, status=200, json={"cpu_millicores": 300})
    faulty = replace(app.state.settings, fault_injection=(FAULT_RESIZE_CREATE_FAIL,))
    healthy = app.state.settings
    app.state.sandbox_service._settings = faulty

    failed = await http.post(f"{base}/start", headers={"Authorization": f"Bearer {key}"})

    assert failed.status_code == 500, failed.text
    assert failed.json()["error"]["code"] == "INTERNAL"
    with pytest.raises(docker.errors.NotFound):  # the old container is gone
        client.containers.get(f"sf-{sandbox_id}")
    assert len(resize_tags(client, sandbox_id)) == 1  # its files live in the image

    app.state.sandbox_service._settings = healthy
    started = await call(http, "POST", f"{base}/start", key, status=200)

    assert started["state"] == "started", started
    assert started["resources"]["cpu_millicores"] == 300
    got = await read(http, key, sandbox_id, PATHS[1])
    assert got["body"]["data"]["content"] == "survives-the-crash"
    await call(http, "DELETE", base, key, status=200)
    assert resize_tags(client, sandbox_id) == []
