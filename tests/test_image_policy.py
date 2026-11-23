"""The user image-reference policy: image IDs and the reserved repository are refused.

Docker resolves a raw reference against the local image store first and also resolves image IDs,
so an ID would run another org's committed snapshot image. The same check guards the build
``base_image`` (the classic build resolves ``FROM`` locally too).
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sandfort.clock import FrozenClock
from sandfort.domain.image_spec import ImageSpec
from sandfort.errors import Unprocessable
from sandfort.images.dockerfile import (
    InvalidImageSpec,
    compile_dockerfile,
    is_reserved_image_reference,
    reserved_repository,
)
from sandfort.services import snapshots
from sandfort.services.image_policy import check_user_image_reference

DIGEST = "sha256:" + "ab" * 32
ID_MESSAGE = "image IDs are not accepted; pass an image name such as python:3.12-slim"
RESERVED = "images in the sandfort-snapshot repository are reserved; pass the snapshot id instead"
ID_LIKE = (
    DIGEST,
    "ab" * 32,
    "4f2a9c",
    "4F2A9C",
    DIGEST.upper(),
    "  " + "ab" * 32 + "  ",
    "\t4f2a9c\n",
    "sha256:4f2a9c",
    "sha256:",
    "SHA256:whatever",
    "@" + DIGEST,
    " @" + DIGEST,
)
DANGLING = (
    "untagged images (moby-dangling) are not accepted; pass an image name such as python:3.12-slim"
)
SNAPSHOT_FORMS = (
    "sandfort-snapshot",
    "sandfort-snapshot:snap_abc",
    "SANDFORT-SNAPSHOT:SNAP_ABC",
    "Sandfort-Snapshot:snap_abc",
    "registry.example.com/sandfort-snapshot:snap_abc",
    "localhost:5000/team/sandfort-snapshot:snap_abc",
    "docker.io/library/SandFort-Snapshot@" + DIGEST,
    "  sandfort-snapshot:snap_abc  ",
)
DANGLING_FORMS = (
    "moby-dangling@" + DIGEST,
    "moby-dangling",
    "Moby-Dangling:latest",
    "MOBY-DANGLING@" + DIGEST.upper(),
    "docker.io/library/moby-dangling@" + DIGEST,
    "registry.example.com/team/moby-dangling:x",
    "  moby-dangling@" + DIGEST + "  ",
)
RESERVED_FORMS = (*SNAPSHOT_FORMS, *DANGLING_FORMS)
ALLOWED = (
    "python:3.12-slim",
    "alpine",
    "ghcr.io/o/r:t",
    "localhost:5000/team/app:1",
    "alpine@" + DIGEST,
    "python:3.12-slim@" + DIGEST,
    "ghcr.io/o/r@" + DIGEST,
    "registry.example.com/sandfort-snapshots:1",
    "my/sandfort-snapshot-tools:2",
    "registry.example.com/moby-dangling-tools:1",
    "my/moby-dangler@" + DIGEST,
)


@pytest.mark.parametrize("reference", ID_LIKE)
def test_id_like_reference_is_refused(reference: str) -> None:
    with pytest.raises(Unprocessable) as raised:
        check_user_image_reference(reference)

    assert raised.value.message == ID_MESSAGE


@pytest.mark.parametrize("reference", SNAPSHOT_FORMS)
def test_snapshot_repository_is_refused_in_every_spelling(reference: str) -> None:
    with pytest.raises(Unprocessable) as raised:
        check_user_image_reference(reference)

    assert raised.value.message == RESERVED


@pytest.mark.parametrize("reference", DANGLING_FORMS)
def test_dangling_repository_gets_its_own_message_in_every_spelling(reference: str) -> None:
    with pytest.raises(Unprocessable) as raised:
        check_user_image_reference(reference)

    assert raised.value.message == DANGLING
    assert "sandfort-snapshot" not in raised.value.message


@pytest.mark.parametrize(
    ("reference", "expected"),
    [
        *((form, "sandfort-snapshot") for form in SNAPSHOT_FORMS),
        *((form, "moby-dangling") for form in DANGLING_FORMS),
        *((form, None) for form in ALLOWED),
    ],
)
def test_reserved_repository_names_the_matching_repository(
    reference: str, expected: str | None
) -> None:
    assert reserved_repository(reference) == expected
    assert is_reserved_image_reference(reference) is (expected is not None)


@pytest.mark.parametrize("reference", ["", "   ", "\n\t"])
def test_empty_reference_is_refused(reference: str) -> None:
    with pytest.raises(Unprocessable):
        check_user_image_reference(reference)


@pytest.mark.parametrize("reference", ALLOWED)
def test_normal_names_and_named_digests_pass(reference: str) -> None:
    check_user_image_reference(reference)


def test_the_old_reserved_check_is_still_importable_from_snapshots() -> None:
    assert snapshots.is_reserved_image_reference("sandfort-snapshot:snap_x")
    assert not snapshots.is_reserved_image_reference("alpine:3.20")
    assert snapshots.SNAPSHOT_REPOSITORY == "sandfort-snapshot"


@pytest.mark.parametrize("reference", [*ID_LIKE, *RESERVED_FORMS])
def test_build_base_image_refuses_ids_and_the_reserved_repository(reference: str) -> None:
    with pytest.raises(InvalidImageSpec):
        compile_dockerfile(ImageSpec(base_image=reference))


class SpyDriver:
    """A driver that records every image call, so a refused register can prove it made none."""

    name = "spy"

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def pull_image_digest(self, image: str) -> str:
        self.calls.append(f"pull {image}")
        return DIGEST

    async def inspect_image(self, image: str) -> Any:
        self.calls.append(f"inspect {image}")
        return SimpleNamespace(layer_count=1)


@pytest.mark.parametrize("reference", [*ID_LIKE, *RESERVED_FORMS, ""])
async def test_register_refuses_a_bad_reference_before_pulling_or_inspecting(
    reference: str,
) -> None:
    driver = SpyDriver()
    service = snapshots.SnapshotService(
        cast(Any, lambda: pytest.fail("no unit of work may open")),
        cast(Any, driver),
        FrozenClock(datetime(2026, 11, 5, tzinfo=UTC)),
    )

    with pytest.raises(Unprocessable):
        await service.register("org_1", None, reference)

    assert driver.calls == []


@pytest.mark.parametrize("reference", ["4f2a9c", "sha256:4f2a9c", "sandfort-snapshot:snap_x"])
def test_build_base_image_refusal_names_the_field(reference: str) -> None:
    with pytest.raises(InvalidImageSpec) as raised:
        compile_dockerfile(ImageSpec(base_image=reference))

    assert raised.value.details == {"field": "base_image"}
    assert raised.value.message in {ID_MESSAGE, RESERVED, DANGLING}


@pytest.mark.parametrize("reference", ALLOWED)
def test_build_base_image_accepts_normal_names_and_named_digests(reference: str) -> None:
    assert compile_dockerfile(ImageSpec(base_image=reference)) == f"FROM {reference}\n"
