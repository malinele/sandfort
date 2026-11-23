"""r66a: the docker driver's side of the resize image (labels, forced removal, cleanup)."""

from types import SimpleNamespace
from typing import Any

from sandfort.drivers.base import RESIZE_IMAGE_LABEL
from sandfort.drivers.docker import images
from sandfort.drivers.docker.containers import remove_container
from sandfort.drivers.docker.labels import LABEL_SANDBOX_ID

BASE_ID = "sha256:base"
COMMITTED_ID = "sha256:committed"


class Api:
    def __init__(self, container: dict[str, Any], image: dict[str, Any] | None = None) -> None:
        self.container = container
        self.image = image or {}
        self.commits: list[dict[str, Any]] = []
        self.removed_images: list[tuple[str, dict[str, Any]]] = []
        self.removed_containers: list[str] = []

    def inspect_container(self, ref: str) -> dict[str, Any]:
        return self.container

    def inspect_image(self, ref: str) -> dict[str, Any]:
        if ref == BASE_ID:
            return {"Id": BASE_ID, "Config": {"Env": []}}
        return self.image or {"Id": COMMITTED_ID, "RootFS": {"Layers": ["a"]}}

    def commit(self, container: str, **kwargs: Any) -> dict[str, Any]:
        self.commits.append(kwargs)
        return {"Id": COMMITTED_ID}

    def remove_image(self, ref: str, **kwargs: Any) -> None:
        self.removed_images.append((ref, kwargs))

    def remove_container(self, ref: str, **kwargs: Any) -> None:
        self.removed_containers.append(ref)


async def test_commit_writes_the_given_labels_into_the_image_config() -> None:
    api = Api({"Image": BASE_ID, "Config": {"Env": []}})

    await images.commit_container(
        SimpleNamespace(api=api), "ctr", "sf-resize-sbx_1", {RESIZE_IMAGE_LABEL: "1"}
    )

    assert api.commits[0]["conf"]["Labels"] == {RESIZE_IMAGE_LABEL: "1"}


async def test_commit_without_labels_sends_no_label_config() -> None:
    api = Api({"Image": BASE_ID, "Config": {"Env": []}})

    await images.commit_container(SimpleNamespace(api=api), "ctr", "sandfort-snapshot:s1")

    assert "Labels" not in api.commits[0]["conf"]


async def test_remove_image_forces_only_when_asked() -> None:
    api = Api({})
    client = SimpleNamespace(api=api)

    await images.remove_image(client, "plain")
    await images.remove_image(client, "forced", force=True)

    assert api.removed_images == [("plain", {}), ("forced", {"force": True})]


async def test_destroying_a_container_of_a_resize_image_removes_that_image() -> None:
    api = Api(
        {"Image": "sha256:resized", "Config": {"Labels": {RESIZE_IMAGE_LABEL: "1"}}},
        image={"Id": "sha256:resized", "RepoTags": [], "RepoDigests": []},
    )

    await remove_container(SimpleNamespace(api=api), "ctr", remove_volumes=False)

    assert api.removed_containers == ["ctr"]
    assert api.removed_images == [("sha256:resized", {})]


async def test_a_tagged_image_with_the_inherited_marker_is_never_removed() -> None:
    """A snapshot committed from a resized container inherits the label but keeps its tag."""
    api = Api(
        {"Image": "sha256:snap", "Config": {"Labels": {RESIZE_IMAGE_LABEL: "1"}}},
        image={"Id": "sha256:snap", "RepoTags": ["sandfort-snapshot:snap_1"]},
    )

    await remove_container(SimpleNamespace(api=api), "ctr", remove_volumes=False)

    assert api.removed_images == []


async def test_a_container_without_the_marker_removes_no_image() -> None:
    api = Api({"Image": "sha256:alpine", "Config": {"Labels": {}}})

    await remove_container(SimpleNamespace(api=api), "ctr", remove_volumes=False)

    assert api.removed_images == []


async def test_removing_a_sandbox_container_also_removes_its_tagged_resize_image() -> None:
    labels = {RESIZE_IMAGE_LABEL: "1", LABEL_SANDBOX_ID: "sbx_ABC"}
    api = Api(
        {"Image": "sha256:resized", "Config": {"Labels": labels}},
        image={"Id": "sha256:resized", "RepoTags": ["sf-resize-sbx_abc:latest"]},
    )

    await remove_container(SimpleNamespace(api=api), "ctr", remove_volumes=True)

    assert api.removed_containers == ["ctr"]
    assert api.removed_images[0] == ("sf-resize-sbx_abc", {"force": True})


async def test_the_tag_goes_even_when_the_container_has_no_marker() -> None:
    """A reset swaps in a container of the original image; the tag still has to go on delete."""
    api = Api({"Image": "sha256:alpine", "Config": {"Labels": {LABEL_SANDBOX_ID: "sbx_1"}}})

    await remove_container(SimpleNamespace(api=api), "ctr", remove_volumes=True)

    assert api.removed_images == [("sf-resize-sbx_1", {"force": True})]


async def test_replacing_a_container_keeps_the_tag_the_new_one_is_based_on() -> None:
    labels = {RESIZE_IMAGE_LABEL: "1", LABEL_SANDBOX_ID: "sbx_1"}
    api = Api(
        {"Image": "sha256:resized", "Config": {"Labels": labels}},
        image={"Id": "sha256:resized", "RepoTags": ["sf-resize-sbx_1:latest"]},
    )

    await remove_container(SimpleNamespace(api=api), "ctr", remove_volumes=False)

    assert api.removed_images == []


async def test_a_missing_tag_does_not_fail_the_removal() -> None:
    api = Api({"Image": "sha256:alpine", "Config": {"Labels": {LABEL_SANDBOX_ID: "sbx_1"}}})

    def refuse(ref: str, **kwargs: Any) -> None:
        raise RuntimeError("No such image")

    api.remove_image = refuse  # type: ignore[method-assign]

    await remove_container(SimpleNamespace(api=api), "ctr", remove_volumes=True)

    assert api.removed_containers == ["ctr"]
