"""Image-build answers withhold registry and source details from label-scoped callers.

Same rule as ``snapshot_response``: ``source_sandbox_id`` can name a sandbox outside the caller's
scope (round 35), and ``image_ref`` and ``digest`` expose the operator's registry host and path
(round 36). That covers the build answer and the final ``state`` event of the build-log stream.
"""

import json
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from typing import Any, cast

import pytest

from sandfort.api.routes.image_builds import _frames
from sandfort.api.schemas.image_builds import BuildImageResponse, build_response
from sandfort.auth.label_scope import set_label_scope
from sandfort.domain.snapshot import Snapshot, SnapshotState
from sandfort.services.image_builds import ImageBuildService

SOURCE_SANDBOX_ID = "sbx_source"
IMAGE_REF = "sandfort/built:abc"
DIGEST = "sha256:abc"
CREATED_AT = datetime(2026, 11, 8, 7, 0, tzinfo=UTC)


def make_snapshot(state: SnapshotState = SnapshotState.READY) -> Snapshot:
    return Snapshot(
        id="snp_built",
        org_id="org_1",
        name="built-image",
        image_ref=IMAGE_REF,
        digest=DIGEST,
        layer_count=3,
        state=state,
        source_sandbox_id=SOURCE_SANDBOX_ID,
        spec_hash="hash_1",
        created_at=CREATED_AT,
    )


@pytest.fixture
def label_scope() -> Iterator[None]:
    """Activate a ``team=red`` label scope for the test, then restore the unscoped default."""
    set_label_scope({"team": "red"})
    try:
        yield
    finally:
        set_label_scope(None)


def test_label_scoped_caller_sees_null_source_sandbox_id(label_scope: None) -> None:
    response = build_response(make_snapshot())

    assert response.source_sandbox_id is None


def test_org_wide_caller_sees_source_sandbox_id() -> None:
    response = build_response(make_snapshot())

    assert response.source_sandbox_id == SOURCE_SANDBOX_ID


def test_rest_of_response_is_identical_with_and_without_scope(label_scope: None) -> None:
    scoped = build_response(make_snapshot()).model_dump()
    set_label_scope(None)
    unscoped = build_response(make_snapshot()).model_dump()

    for hidden, value in (
        ("source_sandbox_id", SOURCE_SANDBOX_ID),
        ("image_ref", IMAGE_REF),
        ("digest", DIGEST),
    ):
        assert scoped.pop(hidden) is None
        assert unscoped.pop(hidden) == value
    assert scoped == unscoped


def test_build_fields_are_unchanged() -> None:
    ready = build_response(make_snapshot(SnapshotState.READY))
    pending = build_response(make_snapshot(SnapshotState.PENDING))

    assert ready == BuildImageResponse(
        id="snp_built",
        name="built-image",
        state="ready",
        image_ref=IMAGE_REF,
        digest=DIGEST,
        layer_count=3,
        source_sandbox_id=SOURCE_SANDBOX_ID,
        created_at=CREATED_AT,
        spec_hash="hash_1",
        reused=True,
        labels={},
    )
    assert pending.reused is False
    assert pending.state == "pending"


def test_label_scoped_caller_sees_null_image_ref_and_digest(label_scope: None) -> None:
    response = build_response(make_snapshot())

    assert response.image_ref is None
    assert response.digest is None


def test_org_wide_caller_sees_image_ref_and_digest() -> None:
    response = build_response(make_snapshot())

    assert response.image_ref == IMAGE_REF
    assert response.digest == DIGEST


class _StubService:
    """Just the two calls the final ``state`` event makes."""

    def __init__(self, reason: str | None = None) -> None:
        self.reason = reason

    async def get(self, org_id: str, snapshot_id: str) -> Snapshot:
        return make_snapshot()

    def failure_reason(self, snapshot_id: str) -> str | None:
        return self.reason


async def _no_lines() -> AsyncIterator[str]:
    return
    yield ""


BUILD_LOG = (
    "Step 1/2 : FROM alpine:3.20",
    "Successfully built 0123456789ab",
    "Successfully tagged sandfort-snapshot:snap_0123456789abcdef",
    "sha256:" + "ab" * 32,
)


async def _log_lines(log: tuple[str, ...]) -> AsyncIterator[str]:
    for line in log:
        yield line


async def _logged_lines(log: tuple[str, ...] = BUILD_LOG) -> list[str]:
    service = cast(ImageBuildService, _StubService())
    frames = [f async for f in _frames(service, "org_1", "snp_built", _log_lines(log))]
    lines = []
    for frame in frames:
        if "event: log" in frame:
            data = next(x for x in frame.splitlines() if x.startswith("data:"))
            lines.append(json.loads(data.removeprefix("data:").strip())["line"])
    return lines


async def _final_event(reason: str | None = None) -> dict[str, Any]:
    service = cast(ImageBuildService, _StubService(reason))
    frames = [frame async for frame in _frames(service, "org_1", "snp_built", _no_lines())]
    state_frame = next(frame for frame in frames if "event: state" in frame)
    data_line = next(line for line in state_frame.splitlines() if line.startswith("data:"))
    return cast(dict[str, Any], json.loads(data_line.removeprefix("data:").strip()))


async def test_label_scoped_final_log_event_sends_null_digest(label_scope: None) -> None:
    final = await _final_event()

    assert final["state"] == "ready"
    assert final["digest"] is None


async def test_org_wide_final_log_event_sends_digest() -> None:
    final = await _final_event()

    assert final["digest"] == DIGEST


async def test_label_scoped_build_log_has_no_tag_or_hex_id(label_scope: None) -> None:
    lines = await _logged_lines()
    text = "\n".join(lines)

    assert "sandfort-snapshot" not in text
    assert "0123456789ab" not in text
    assert "abab" not in text
    assert lines[1] == "Successfully built the built image"
    assert lines[2] == "Successfully tagged the built image"
    assert lines[0] == BUILD_LOG[0]


async def test_org_wide_build_log_is_unchanged() -> None:
    assert await _logged_lines() == list(BUILD_LOG)


GIT_SHA = "9fceb02d0ae598e95dc970b74767f19372d61af8"
PIP_HASH = "    --hash=sha256:" + "0f" * 32
SHA256SUM_LINE = "ab" * 32 + "  requirements.txt"
SHORT_ID_LINE = "HEAD is now at 0123456789abcdef fix the thing"
TENANT_LINES = (
    f"commit {GIT_SHA}",
    PIP_HASH,
    SHA256SUM_LINE,
    SHORT_ID_LINE,
    "Collecting requests==2.32.3",
)


async def test_label_scoped_build_log_keeps_tenant_hex_and_hashes(label_scope: None) -> None:
    log = (*TENANT_LINES[:2], "Successfully built 0123456789ab", *TENANT_LINES[2:])

    lines = await _logged_lines(log)

    assert lines == [
        *TENANT_LINES[:2],
        "Successfully built the built image",
        *TENANT_LINES[2:],
    ]


async def test_label_scoped_build_log_redacts_only_the_builders_shapes(label_scope: None) -> None:
    digest = "sha256:" + "AB" * 32
    log = (
        f"#8 writing image {digest} done",
        "#9 naming to docker.io/library/sandfort-snapshot:snap_0123456789abcdef done",
        digest,
        f"exporting config {digest.lower()}",
        "Successfully built 0123456789AB",
        f"RUN git checkout {GIT_SHA} && pip install --hash=sha256:{'0f' * 32} x",
    )

    lines = await _logged_lines(log)

    assert lines == [
        "#8 writing image the built image done",
        "#9 naming to docker.io/library/the built image done",
        "the built image",
        "exporting config the built image",
        "Successfully built the built image",
        log[-1],
    ]


async def test_org_wide_build_log_keeps_tenant_lines_and_builder_lines() -> None:
    log = (*TENANT_LINES, *BUILD_LOG)

    assert await _logged_lines(log) == list(log)


BARE_12_HEX = "deadbeefcafe"  # test-only hex, the length of a classic builder's short id
STEP_ECHO_12_HEX = f"Step 2/4 : RUN echo {BARE_12_HEX}"
# A classic (non-BuildKit) builder log: (line as printed, line a label-scoped caller sees).
CLASSIC_LOG = (
    ("Step 1/4 : FROM alpine:3.20", "Step 1/4 : FROM alpine:3.20"),
    (" ---> 0123456789ab", " ---> the built image"),
    ("Step 2/4 : RUN echo deadbeefcafe0123", "Step 2/4 : RUN echo deadbeefcafe0123"),
    (" ---> Running in 1a2b3c4d5e6f", " ---> Running in the built image"),
    ("deadbeefcafe0123", "deadbeefcafe0123"),  # the tenant's RUN output
    # 12-hex words outside the three anchors stay, so the anchors (not the word boundary) decide
    (BARE_12_HEX, BARE_12_HEX),
    (STEP_ECHO_12_HEX, STEP_ECHO_12_HEX),
    (
        "Removing intermediate container 1a2b3c4d5e6f",
        "Removing intermediate container the built image",
    ),
    # the live classic builder prints the past tense after the step's arrow
    (
        " ---> Removed intermediate container 1a2b3c4d5e6f",
        " ---> Removed intermediate container the built image",
    ),
    (" ---> 9f8e7d6c5b4a", " ---> the built image"),
    ("Step 3/4 : RUN git rev-parse HEAD", "Step 3/4 : RUN git rev-parse HEAD"),
    (" ---> Using cache", " ---> Using cache"),
    (GIT_SHA, GIT_SHA),
    (PIP_HASH, PIP_HASH),
    ("sha256=" + "cd" * 32, "sha256=" + "cd" * 32),
    ("Step 4/4 : CMD sh", "Step 4/4 : CMD sh"),
    (" ---> Running in 0a1b2c3d4e5f", " ---> Running in the built image"),
    (
        "Removing intermediate container 0a1b2c3d4e5f",
        "Removing intermediate container the built image",
    ),
    (
        " ---> Removed intermediate container 0a1b2c3d4e5f",
        " ---> Removed intermediate container the built image",
    ),
    (
        "removed intermediate container A600AA33656A",
        "removed intermediate container the built image",
    ),
    (" ---> 00aa11bb22cc", " ---> the built image"),
    ("Successfully built 00aa11bb22cc", "Successfully built the built image"),
    (
        "Successfully tagged sandfort-snapshot:snap_0123456789abcdef",
        "Successfully tagged the built image",
    ),
)


async def test_label_scoped_classic_build_log_redacts_the_step_ids_line_by_line(
    label_scope: None,
) -> None:
    printed = tuple(line for line, _ in CLASSIC_LOG)

    lines = await _logged_lines(printed)

    assert len(lines) == len(CLASSIC_LOG)
    for shown, (line, expected) in zip(lines, CLASSIC_LOG, strict=True):
        assert shown == expected, line


async def test_label_scoped_classic_build_log_keeps_unanchored_12_hex_words(
    label_scope: None,
) -> None:
    log = (
        f" ---> {BARE_12_HEX}",
        BARE_12_HEX,
        f" ---> Running in {BARE_12_HEX}",
        STEP_ECHO_12_HEX,
        f"Removing intermediate container {BARE_12_HEX}",
        f" ---> Removed intermediate container {BARE_12_HEX}",
    )

    lines = await _logged_lines(log)

    assert lines == [
        " ---> the built image",
        BARE_12_HEX,
        " ---> Running in the built image",
        STEP_ECHO_12_HEX,
        "Removing intermediate container the built image",
        " ---> Removed intermediate container the built image",
    ]


async def test_org_wide_classic_build_log_is_unchanged_line_by_line() -> None:
    printed = tuple(line for line, _ in CLASSIC_LOG)

    lines = await _logged_lines(printed)

    for shown, line in zip(lines, printed, strict=True):
        assert shown == line
    assert " ---> Removed intermediate container 0a1b2c3d4e5f" in lines


async def test_label_scoped_final_event_reason_is_redacted(label_scope: None) -> None:
    tag = "sandfort-snapshot:snap_0123456789abcdef"
    reason = f"build failed: sha256:{'ab' * 32} ({tag}) at {GIT_SHA}"

    final = await _final_event(reason)

    assert final["reason"] == f"build failed: the built image (the built image) at {GIT_SHA}"


async def test_org_wide_final_event_reason_is_unchanged() -> None:
    reason = f"build failed: sha256:{'ab' * 32}"

    assert (await _final_event(reason))["reason"] == reason


async def test_label_scoped_final_event_without_a_reason_stays_null(label_scope: None) -> None:
    assert (await _final_event())["reason"] is None
