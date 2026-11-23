"""create/start/stop/remove/inspect/list_managed over docker-py."""

import io
import logging
import math
import posixpath
import re
import tarfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from sandfort.config import Settings, is_reserved_env_name
from sandfort.domain.resources import (
    DEFAULT_DISK_GIB,
    MIN_CPU_MILLICORES,
    MIN_DISK_GIB,
    MIN_MEMORY_MIB,
    ResourceSpec,
)
from sandfort.domain.sandbox import egress_restricted
from sandfort.drivers.base import (
    IMAGE_MOUNTS_LABEL,
    RESIZE_IMAGE_LABEL,
    ExecRequest,
    InstanceInfo,
    InstanceState,
    SandboxSpec,
    decode_image_mounts,
    resize_image_reference,
)
from sandfort.drivers.docker.client import (
    HTTP_CONFLICT,
    clean_message,
    docker_errors,
    load_docker_module,
    run_blocking,
    translate_errors,
)
from sandfort.drivers.docker.disk_reserve import fill_reserve, release_reserve
from sandfort.drivers.docker.exec import exec_run, has_own_network_stack
from sandfort.drivers.docker.hardening import (
    BYTES_PER_MIB,
    GVISOR_RUNTIME,
    GVISOR_TMP_PATH,
    NANO_CPUS_PER_MILLICORE,
    NETWORK_NONE,
    HardeningOptions,
    build_host_config,
)
from sandfort.drivers.docker.image_volumes import (
    remove_scratch_volumes,
    scratch_cleanup_on_failure,
    scratch_owner,
    with_scratch_volumes,
)
from sandfort.drivers.docker.images import _pull as pull_reference
from sandfort.drivers.docker.images import invalid_reference, is_invalid_reference
from sandfort.drivers.docker.labels import (
    LABEL_DISK_GIB,
    LABEL_MANAGED,
    LABEL_ORG_ID,
    LABEL_SANDBOX_ID,
    build_labels,
    managed_filters,
)
from sandfort.drivers.docker.networks import (
    EGRESS_NETWORK_NAME,
    NETWORK_NAME,
    ensure_network,
)
from sandfort.drivers.errors import (
    DriverConflict,
    DriverError,
    DriverNotFound,
)

# Sandboxes idle until the toolbox execs into them; the image ENTRYPOINT is overridden
# so images with their own entrypoint behave identically.
KEEPALIVE_ENTRYPOINT = ("tail", "-f", "/dev/null")

logger = logging.getLogger(__name__)

# gVisor and Kata guests never see docker's embedded resolver (127.0.0.11), so containers on
# those runtimes get real nameservers written into resolv.conf after every start (docker
# rewrites it on each start).
RESOLV_CONF_PATH = "/etc/resolv.conf"
RESOLV_NAMESERVER_PREFIX = "nameserver "
RESOLV_OPTIONS_LINE = "options ndots:0"
# The egress-allowlist network drops direct DNS to public resolvers, so a lookup would hang
# until the client times out. A dead local nameserver makes it fail at once and clients use the
# egress proxy, which resolves names itself. Network mode none gets the same text on every
# runtime: docker would otherwise leave a copy of the host's resolv.conf (internal DNS details).
FAIL_FAST_NAMESERVER = "127.0.0.1"
FAIL_FAST_OPTIONS_LINE = "options timeout:1 attempts:1"
RESOLV_WRITE_SCRIPT = 'cat > "$1"'  # $1 = target path; the text arrives on stdin
RESOLV_WRITE_USER = "0"  # root: resolv.conf is root-owned
RESOLV_WRITE_TIMEOUT_S = 10.0
RESOLV_WRITE_MAX_OUTPUT_BYTES = 4096

# gVisor mounts a private tmpfs over /tmp when /tmp in the root filesystem is empty at start,
# and that tmpfs escapes the disk quota and snapshots. A file in /tmp keeps it in the root
# filesystem, so every runsc start puts this empty marker there first.
TMP_MARKER_NAME = ".sandfort-keep"
TMP_DIR_MODE = 0o1777
TMP_MARKER_MODE = 0o644
ROOT_PATH = "/"

_EXTRA_FRACTION_DIGITS = re.compile(r"(\.\d{6})\d+")


def build_create_kwargs(
    spec: SandboxSpec, settings: Settings, options: HardeningOptions | None = None
) -> dict[str, Any]:
    """Everything ``containers.create`` needs besides the image (pure; no daemon)."""
    reserved = sorted(name for name in spec.env if is_reserved_env_name(name))
    if reserved:
        raise DriverError(f"reserved environment names rejected: {', '.join(reserved)}")
    relative = sorted(
        bind.mount_path for bind in spec.volumes if not bind.mount_path.startswith("/")
    )
    if relative:
        raise DriverError(f"volume mount paths must be absolute: {', '.join(relative)}")
    kwargs = build_host_config(spec, settings, options)  # maps spec.volumes onto named mounts
    kwargs.update(
        name=spec.name,
        labels={
            **build_labels(spec.sandbox_id, spec.org_id, spec.labels),
            LABEL_DISK_GIB: str(spec.resources.disk_gib),
        },
        environment=dict(spec.env),
        entrypoint=list(KEEPALIVE_ENTRYPOINT),
    )
    return kwargs


def _to_docker_kwargs(kwargs: Mapping[str, Any]) -> dict[str, Any]:
    """Convert plain-dict pieces to the docker-py types ``containers.create`` requires."""
    converted = dict(kwargs)
    log_config = converted.get("log_config")
    if isinstance(log_config, Mapping):
        types = load_docker_module().types
        converted["log_config"] = types.LogConfig(
            type=log_config["Type"], config=dict(log_config["Config"])
        )
    return converted


def _parse_created(raw: str) -> datetime:
    trimmed = _EXTRA_FRACTION_DIGITS.sub(r"\1", raw).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(trimmed)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _instance_state(state: Mapping[str, Any]) -> InstanceState:
    status = state.get("Status", "")
    if state.get("Paused") or status == "paused":
        return InstanceState.PAUSED
    if status in ("running", "restarting"):
        return InstanceState.RUNNING
    if status == "created":
        return InstanceState.CREATED
    return InstanceState.EXITED


def _resources_from(host_config: Mapping[str, Any], labels: Mapping[str, str]) -> ResourceSpec:
    cpu = int(host_config.get("NanoCpus") or 0) // NANO_CPUS_PER_MILLICORE
    memory = int(host_config.get("Memory") or 0) // BYTES_PER_MIB
    try:
        disk = int(labels.get(LABEL_DISK_GIB, DEFAULT_DISK_GIB))
    except ValueError:
        disk = DEFAULT_DISK_GIB
    return ResourceSpec(
        cpu_millicores=max(cpu, MIN_CPU_MILLICORES),
        memory_mib=max(memory, MIN_MEMORY_MIB),
        disk_gib=max(disk, MIN_DISK_GIB),
    )


def info_from_attrs(attrs: Mapping[str, Any]) -> InstanceInfo:
    """Build an ``InstanceInfo`` from a ``docker inspect`` payload."""
    config = attrs.get("Config") or {}
    labels: dict[str, str] = dict(config.get("Labels") or {})
    return InstanceInfo(
        ref=attrs["Id"],
        name=str(attrs["Name"]).lstrip("/"),
        sandbox_id=labels.get(LABEL_SANDBOX_ID, ""),
        org_id=labels.get(LABEL_ORG_ID, ""),
        state=_instance_state(attrs.get("State") or {}),
        image=config.get("Image", ""),
        resources=_resources_from(attrs.get("HostConfig") or {}, labels),
        labels=labels,
        created_at=_parse_created(attrs["Created"]),
        image_mounts=decode_image_mounts(labels.get(IMAGE_MOUNTS_LABEL)),
    )


async def _create_pulling_missing(client: Any, image: str, kwargs: Mapping[str, Any]) -> Any:
    errors = docker_errors()
    docker_kwargs = _to_docker_kwargs(kwargs)
    try:
        return await run_blocking(client.containers.create, image, **docker_kwargs)
    except errors.ImageNotFound:
        # A registry pull is a bulk call; the shared helper turns an unknown or inaccessible
        # reference into a customer-safe "no such image or snapshot" not-found.
        await pull_reference(client, image)
        return await run_blocking(client.containers.create, image, **docker_kwargs)
    except errors.APIError as exc:
        # A reference the daemon cannot parse never reaches the pull; same message as the pull's.
        message = clean_message(exc)
        if exc.status_code != HTTP_CONFLICT and is_invalid_reference(message):
            raise invalid_reference(image, message) from exc
        raise


async def _adopt(client: Any, spec: SandboxSpec) -> InstanceInfo:
    """Return the existing container for ``spec.name`` if it is this sandbox's."""
    with translate_errors(spec.name, "container.adopt"):
        container = await run_blocking(client.containers.get, spec.name)
    info = info_from_attrs(container.attrs)
    managed = info.labels.get(LABEL_MANAGED) == "true"
    if not managed or (info.sandbox_id, info.org_id) != (spec.sandbox_id, spec.org_id):
        raise DriverConflict(
            f"container name {spec.name!r} is taken by a different object", ref=spec.name
        )
    return info


async def _require_volumes(client: Any, spec: SandboxSpec) -> None:
    """Every mounted volume must already exist: docker would silently create a blank one."""
    for bind in spec.volumes:
        try:
            with translate_errors(bind.volume_ref, "volume.inspect"):
                await run_blocking(client.api.inspect_volume, bind.volume_ref)
        except DriverNotFound:
            raise DriverNotFound(
                f"volume {bind.volume_ref!r} does not exist", ref=bind.volume_ref
            ) from None


async def create_container(
    client: Any, spec: SandboxSpec, settings: Settings, options: HardeningOptions | None = None
) -> InstanceInfo:
    """Create a hardened container; adopt the existing one on a name conflict."""
    kwargs = build_create_kwargs(spec, settings, options)
    errors = docker_errors()
    await _require_volumes(client, spec)
    with translate_errors(spec.name, "container.create"):
        if not spec.network.block_all:
            await ensure_network(client)
            if egress_restricted(spec.labels):  # same predicate as the host config builder
                await ensure_network(client, EGRESS_NETWORK_NAME)
        # Declared image volumes get named scratch volumes, never anonymous ones; any failure
        # or cancellation from here on removes the ones already made (an adopt keeps them).
        async with scratch_cleanup_on_failure(client, spec.sandbox_id):
            kwargs = await with_scratch_volumes(client, spec, kwargs)
            try:
                container = await _create_pulling_missing(client, spec.image, kwargs)
            except errors.APIError as exc:
                if exc.status_code == HTTP_CONFLICT:
                    return await _adopt(client, spec)
                raise
    return info_from_attrs(container.attrs)


def resolv_conf_text(nameservers: Sequence[str]) -> str:
    """The resolv.conf body: one ``nameserver`` line per address in order, then ndots:0."""
    lines = [f"{RESOLV_NAMESERVER_PREFIX}{address}" for address in nameservers]
    return "\n".join([*lines, RESOLV_OPTIONS_LINE]) + "\n"


def fail_fast_resolv_conf_text() -> str:
    """The resolv.conf body that makes every lookup fail at once (egress and none networks)."""
    return f"{RESOLV_NAMESERVER_PREFIX}{FAIL_FAST_NAMESERVER}\n{FAIL_FAST_OPTIONS_LINE}\n"


def _resolv_conf_for(attrs: Mapping[str, Any], nameservers: Sequence[str]) -> str | None:
    """The resolv.conf text to write into this container, or ``None`` to leave it alone.

    Network mode none and the egress-allowlist network get the fail-fast text (none on every
    runtime). Other networks get ``nameservers`` only on a runtime with its own network stack.
    """
    host_config = attrs.get("HostConfig") or {}
    network_mode = host_config.get("NetworkMode")
    if network_mode == NETWORK_NONE:
        return fail_fast_resolv_conf_text()
    if not has_own_network_stack(host_config.get("Runtime") or ""):
        return None
    if network_mode == EGRESS_NETWORK_NAME:
        return fail_fast_resolv_conf_text()
    return resolv_conf_text(nameservers)


async def _write_gvisor_dns(client: Any, ref: str, nameservers: Sequence[str]) -> None:
    """Write resolv.conf into a started container that needs one; never raises on failure."""
    try:
        with translate_errors(ref, "container.inspect"):
            attrs = await run_blocking(client.api.inspect_container, ref)
        text = _resolv_conf_for(attrs, nameservers)
        if text is None:
            return
        request = ExecRequest(
            argv=["sh", "-c", RESOLV_WRITE_SCRIPT, "sh", RESOLV_CONF_PATH],
            stdin=text.encode(),
            timeout_s=RESOLV_WRITE_TIMEOUT_S,
            max_output_bytes=RESOLV_WRITE_MAX_OUTPUT_BYTES,
            user=RESOLV_WRITE_USER,
        )
        result = await exec_run(client, ref, request)
    except Exception:
        logger.warning("could not write gVisor nameservers for %s", ref, exc_info=True)
        return
    if result.exit_code != 0 or result.timed_out:
        logger.warning(
            "writing gVisor nameservers for %s failed (exit %s, timed out: %s): %s",
            ref,
            result.exit_code,
            result.timed_out,
            result.stderr.decode(errors="replace").strip(),
        )


def _tmp_marker_archive(with_tmp_dir: bool) -> bytes:
    """A tar holding the empty marker; with ``with_tmp_dir`` it also creates ``/tmp``.

    Without the directory entry the tar is meant for extraction into an existing ``/tmp``,
    so an image's own ``/tmp`` mode and owner are never rewritten.
    """
    buffer = io.BytesIO()
    prefix = ""
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        if with_tmp_dir:
            directory = tarfile.TarInfo(posixpath.basename(GVISOR_TMP_PATH))
            directory.type = tarfile.DIRTYPE
            directory.mode = TMP_DIR_MODE
            tar.addfile(directory)
            prefix = f"{directory.name}/"
        marker = tarfile.TarInfo(f"{prefix}{TMP_MARKER_NAME}")
        marker.mode = TMP_MARKER_MODE
        tar.addfile(marker)  # size 0: an empty file
    return buffer.getvalue()


def _tmp_is_mounted(attrs: Mapping[str, Any]) -> bool:
    """True when a volume is mounted at /tmp (a user volume or a legacy gVisor volume)."""
    mounts = attrs.get("Mounts") or []
    return any(
        posixpath.normpath(str(mount.get("Destination") or "")) == GVISOR_TMP_PATH
        for mount in mounts
    )


async def _put_tmp_marker(client: Any, ref: str) -> None:
    """Put the marker into /tmp; if /tmp is missing, create it in the same archive."""
    errors = docker_errors()
    try:
        accepted = await run_blocking(
            client.api.put_archive, ref, GVISOR_TMP_PATH, _tmp_marker_archive(False)
        )
    except errors.NotFound:
        accepted = await run_blocking(
            client.api.put_archive, ref, ROOT_PATH, _tmp_marker_archive(True)
        )
    if not accepted:
        raise DriverError(f"docker refused the {GVISOR_TMP_PATH} marker archive", ref=ref)


async def _keep_gvisor_tmp_populated(client: Any, ref: str) -> None:
    """Before a runsc start, make sure /tmp is not empty; never raises on failure.

    The runtime comes from the container's own HostConfig, so restarts and per-sandbox gVisor
    tiers are covered. runc and kata containers are left alone, and so are containers with a
    volume at /tmp (nothing to protect there, and the marker must not land in a user volume).
    """
    try:
        attrs = await run_blocking(client.api.inspect_container, ref)
        if (attrs.get("HostConfig") or {}).get("Runtime") != GVISOR_RUNTIME:
            return
        if _tmp_is_mounted(attrs):
            return
        await _put_tmp_marker(client, ref)
    except Exception:
        logger.warning("could not put the %s marker for %s", TMP_MARKER_NAME, ref, exc_info=True)


async def start_container(client: Any, ref: str, nameservers: Sequence[str] = ()) -> None:
    """Start ``ref``; then, for runsc and kata containers, write ``nameservers`` into resolv.conf.

    Before the start, a runsc container gets an empty ``/tmp/.sandfort-keep`` so gVisor keeps
    ``/tmp`` in the root filesystem (disk quota, snapshots). A failed put only logs a warning.

    A container on the egress-allowlist network gets the fail-fast text instead, and so does a
    container in network mode none on any runtime (including runc). Empty ``nameservers``
    leaves resolv.conf alone. A failed write only logs a warning.
    """
    await _keep_gvisor_tmp_populated(client, ref)
    with translate_errors(ref, "container.start"):
        await run_blocking(client.api.start, ref)
    if nameservers:
        await _write_gvisor_dns(client, ref, nameservers)
    await fill_reserve(client, ref)  # no-op without a disk quota


async def stop_container(client: Any, ref: str, timeout_s: float) -> None:
    grace = max(0, math.ceil(timeout_s))
    await release_reserve(client, ref)  # frees the space docker needs to mount the layer later
    with translate_errors(ref, "container.stop"):
        await run_blocking(client.api.stop, ref, timeout=grace)


async def pause_container(client: Any, ref: str) -> None:
    with translate_errors(ref, "container.pause"):
        await run_blocking(client.api.pause, ref)


async def unpause_container(client: Any, ref: str) -> None:
    with translate_errors(ref, "container.unpause"):
        await run_blocking(client.api.unpause, ref)


async def remove_container(client: Any, ref: str, remove_volumes: bool) -> None:
    """Force-remove ``ref``; a missing container is already the desired outcome.

    With ``remove_volumes`` its image-volume scratch volumes go too, after the container and by
    sandbox label; that step never fails the removal (the GC collects what it leaves).
    """
    sandbox_id = await scratch_owner(client, ref) if remove_volumes else None
    resize_image = await _resize_image_id(client, ref)
    try:
        with translate_errors(ref, "container.remove"):
            await run_blocking(client.api.remove_container, ref, v=remove_volumes, force=True)
    except DriverNotFound:
        pass
    if sandbox_id is not None:
        await remove_scratch_volumes(client, sandbox_id)
        await _drop_resize_tag(client, sandbox_id)  # the sandbox ends: so does its resize image
    if resize_image is not None:
        await _drop_resize_image(client, resize_image)


async def _drop_resize_tag(client: Any, sandbox_id: str) -> None:
    """Force-remove the sandbox's ``sf-resize-<id>`` tag; best effort, a missing tag is fine.

    A resize keeps the tag while the sandbox lives (its container is based on that image, and on
    overlay2 removing it earlier deletes the image under the container), so it goes here, once
    the container is removed. ``resize_image_reference`` names it deterministically.
    """
    try:
        await run_blocking(client.api.remove_image, resize_image_reference(sandbox_id), force=True)
    except Exception:
        logger.debug("no resize image to remove for %s", sandbox_id, exc_info=True)


async def _resize_image_id(client: Any, ref: str) -> str | None:
    """The id of the resize image ``ref`` was created from (it carries the marker), else ``None``.

    The image id is read before the container goes. Best effort: any failure means no cleanup.
    """
    try:
        attrs = await run_blocking(client.api.inspect_container, ref)
        labels = (attrs.get("Config") or {}).get("Labels") or {}
        image = attrs.get("Image")
        return str(image) if labels.get(RESIZE_IMAGE_LABEL) and image else None
    except Exception:
        logger.debug("could not read the resize image of %s", ref, exc_info=True)
        return None


async def _drop_resize_image(client: Any, image_id: str) -> None:
    """Remove the image id a destroyed resize container was based on, once nothing names it.

    The marker label is inherited by anything committed from such a container (a snapshot), so
    only an image without any name is removed: a tagged or digest-pinned image is never ours.
    """
    try:
        attrs = await run_blocking(client.api.inspect_image, image_id)
        if attrs.get("RepoTags") or attrs.get("RepoDigests"):
            return
        await run_blocking(client.api.remove_image, image_id)
    except Exception:
        logger.debug("could not remove the resize image %s", image_id, exc_info=True)


async def inspect_container(client: Any, ref: str) -> InstanceInfo:
    with translate_errors(ref, "container.inspect"):
        attrs = await run_blocking(client.api.inspect_container, ref)
    return info_from_attrs(attrs)


def bridge_address(attrs: Mapping[str, Any]) -> str | None:
    """The container's IP on the sandbox bridge network, else on any attached network."""
    network_settings = attrs.get("NetworkSettings") or {}
    networks: Mapping[str, Any] = network_settings.get("Networks") or {}
    preferred = networks.get(NETWORK_NAME)
    for network in (preferred, *networks.values()):
        address = (network or {}).get("IPAddress")
        if address:
            return str(address)
    return None


async def container_endpoint(client: Any, ref: str, port: int) -> tuple[str, int]:
    """``(bridge ip, port)``: the host reaches unpublished container ports over the bridge."""
    with translate_errors(ref, "container.endpoint"):
        attrs = await run_blocking(client.api.inspect_container, ref)
    address = bridge_address(attrs)
    if address is None:
        raise DriverError(f"container {ref} has no network address", ref=ref)
    return address, port


async def list_managed_containers(client: Any, org_id: str | None) -> list[InstanceInfo]:
    with translate_errors(None, "container.list"):
        containers = await run_blocking(
            client.containers.list, all=True, filters=managed_filters(org_id)
        )
    return [info_from_attrs(container.attrs) for container in containers]


async def container_size_rw(client: Any, provider_id: str) -> int | None:
    """Bytes in the container's writable layer (``SizeRw``), else ``None``; never raises."""
    try:
        entries = await run_blocking(
            client.api.containers, all=True, size=True, filters={"id": provider_id}
        )
    except Exception:
        logger.debug("cannot read the size of container %s", provider_id, exc_info=True)
        return None
    size = entries[0].get("SizeRw") if entries and isinstance(entries[0], Mapping) else None
    return size if isinstance(size, int) and not isinstance(size, bool) else None
