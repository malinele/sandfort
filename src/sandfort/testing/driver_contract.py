"""Packaged driver conformance suite (WP 5.6): capability-aware checks for any driver object.

Each check is an async function ``(driver, context)`` that raises ``ConformanceFailure``
naming itself and removes every object it created, pass or fail. ``run_suite`` runs the
checks whose capabilities the driver declares (without a declaration: the protocols it
structurally implements, see ``drivers.registry``) and reports passed, failed and
skipped-by-capability checks. ``DriverContract`` keeps the seed entry point.
"""

import asyncio
import contextlib
import io
import logging
import tarfile
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from sandfort.domain.resources import ResourceSpec
from sandfort.drivers.base import (
    ArchiveStreamDriver,
    ExecRequest,
    ExitEvent,
    ImageRegistryDriver,
    InstanceState,
    LogsDriver,
    NamedVolumeDriver,
    OutputChunk,
    SandboxSpec,
)
from sandfort.drivers.errors import DriverError, DriverNotFound
from sandfort.drivers.registry import (
    CAPABILITY_PROTOCOLS,
    Capability,
    RuntimeArchive,
    RuntimeCompute,
    RuntimeExec,
    RuntimeImages,
    RuntimeVolumes,
    detect_capabilities,
)

logger = logging.getLogger(__name__)

OWNER = "WP 5.6 (driver plug-in certification)"
PROTOCOLS = CAPABILITY_PROTOCOLS  # the seed's name for the capability -> protocols table
DEFAULT_IMAGE = "alpine:3.20"
DEFAULT_KEEPALIVE = ("tail", "-f", "/dev/null")
SUITE_LABEL = "sandfort-conformance"
PROTOCOLS_CHECK = "protocols"
ECHO_ARGV = ("echo", "sandfort", "conformance")
ECHO_OUTPUT = b"sandfort conformance\n"
EXIT_CODE = 3
ENV_KEY = "CONFORMANCE_TOKEN"
OUTPUT_CAP = 64
CAP_PAYLOAD_BYTES = 4096
ARCHIVE_DIR = "/tmp"
LOG_LINES = 3
POLL_S = 0.1
# Prints its arguments, one per line, on the stdout of the instance's main process.
EMIT_SCRIPT = 'printf "%s\\n" "$@" > /proc/1/fd/1'

type LogEmitter = Callable[[object, str, Sequence[str]], Awaitable[None]]


def _default_resources() -> ResourceSpec:
    return ResourceSpec(cpu_millicores=500, memory_mib=256, disk_gib=1)


@dataclass(frozen=True, slots=True)
class DriverContext:
    """Per-driver inputs: the image instances boot and the idle command they run.

    ``emit_logs`` writes lines into an instance's log (default: ``exec_log_emitter``, which
    writes through the main process, i.e. ``keepalive_argv``; docker forces it as entrypoint).
    """

    image: str = DEFAULT_IMAGE
    keepalive_argv: Sequence[str] = DEFAULT_KEEPALIVE
    emit_logs: LogEmitter | None = None
    stop_timeout_s: float = 2.0
    log_deadline_s: float = 10.0
    resources: ResourceSpec = field(default_factory=_default_resources)

    def new_spec(self) -> SandboxSpec:
        """A fresh spec with a deterministic ``sf-<id>`` name, labelled as suite-owned."""
        sandbox_id = f"sbx_conf{uuid.uuid4().hex[:12]}"
        return SandboxSpec(
            sandbox_id=sandbox_id,
            org_id=f"org_conf{uuid.uuid4().hex[:12]}",
            name=f"sf-{sandbox_id}",
            image=self.image,
            resources=self.resources,
            labels={"suite": SUITE_LABEL},
        )


class DriverContractError(AssertionError):
    """The driver does not satisfy one or more protocols."""


class ConformanceFailure(DriverContractError):
    """One named check failed."""

    def __init__(self, check: str, message: str) -> None:
        super().__init__(f"[{check}] {message}")
        self.check = check
        self.message = message


def _expect(condition: bool, check: str, message: str) -> None:
    if not condition:
        raise ConformanceFailure(check, message)


async def _expect_missing(probe: Awaitable[object], check: str, message: str) -> None:
    try:
        await probe
    except DriverNotFound:
        return
    raise ConformanceFailure(check, message)


async def _cleanup(action: Awaitable[None], check: str, ref: str) -> None:
    """Best-effort removal after a check; a failure is logged, never raised over the result."""
    try:
        await action
    except DriverError as exc:
        logger.warning("conformance check %s could not clean up %s: %s", check, ref, exc)


def _compute(driver: object, check: str) -> RuntimeCompute:
    if not isinstance(driver, RuntimeCompute):
        raise ConformanceFailure(check, "driver does not implement the compute protocol")
    return driver


def _exec(driver: object, check: str) -> RuntimeExec:
    if not isinstance(driver, RuntimeExec):
        raise ConformanceFailure(check, "driver does not implement the exec protocol")
    return driver


@contextlib.asynccontextmanager
async def _running(driver: object, context: DriverContext, check: str) -> AsyncIterator[str]:
    """A started instance for the check body; destroyed afterwards whatever happens."""
    compute = _compute(driver, check)
    info = await compute.create(context.new_spec())
    try:
        await compute.start(info.ref)
        yield info.ref
    finally:
        await _cleanup(compute.destroy(info.ref), check, info.ref)


async def _expect_state(
    compute: RuntimeCompute, ref: str, wanted: InstanceState, check: str, when: str
) -> None:
    state = (await compute.inspect(ref)).state
    _expect(state == wanted, check, f"state {when} is {state}, expected {wanted}")


async def check_compute(driver: object, context: DriverContext) -> None:
    """Create, inspect, list, stop, start, adopt on re-create, delete."""
    name = "compute"
    compute = _compute(driver, name)
    spec = context.new_spec()
    created = await compute.create(spec)
    ref, destroyed = created.ref, False
    try:
        identity = (created.name, created.sandbox_id, created.org_id)
        wanted = (spec.name, spec.sandbox_id, spec.org_id)
        _expect(identity == wanted, name, f"create gave {identity}, not {wanted}")
        await _expect_state(compute, ref, InstanceState.CREATED, name, "after create")
        await compute.start(ref)
        await _expect_state(compute, ref, InstanceState.RUNNING, name, "after start")
        listed = {item.ref for item in await compute.list_managed(org_id=spec.org_id)}
        _expect(ref in listed, name, f"list_managed does not report {ref}")
        await compute.stop(ref, timeout_s=context.stop_timeout_s)
        await _expect_state(compute, ref, InstanceState.EXITED, name, "after stop")
        await compute.start(ref)
        await _expect_state(compute, ref, InstanceState.RUNNING, name, "after restart")
        adopted = await compute.create(spec)
        _expect(adopted.ref == ref, name, f"re-create made {adopted.ref}, not adopting {ref}")
        await compute.destroy(ref)
        destroyed = True
        await _expect_missing(compute.inspect(ref), name, f"instance {ref} survived destroy")
    finally:
        if not destroyed:
            await _cleanup(compute.destroy(ref), name, ref)


async def _check_echo(runner: RuntimeExec, ref: str, name: str) -> None:
    result = await runner.exec(ref, ExecRequest(argv=ECHO_ARGV))
    _expect(result.exit_code == 0, name, f"echo exited {result.exit_code}")
    _expect(result.stdout == ECHO_OUTPUT, name, f"echo printed {result.stdout!r}")
    _expect(not result.truncated and not result.timed_out, name, "echo truncated or timed out")
    events = [event async for event in runner.exec_stream(ref, ExecRequest(argv=ECHO_ARGV))]
    chunks = [e for e in events if isinstance(e, OutputChunk) and e.stream == "stdout"]
    exits = [e for e in events if isinstance(e, ExitEvent)]
    streamed = b"".join(chunk.data for chunk in chunks)
    _expect(streamed == ECHO_OUTPUT, name, f"exec_stream printed {streamed!r}")
    single_exit = len(exits) == 1 and events[-1] is exits[0] and exits[0].exit_code == 0
    _expect(single_exit, name, "exec_stream must end with exactly one zero ExitEvent")


async def check_exec(driver: object, context: DriverContext) -> None:
    """Argv echo round-trip (plain and streamed), exit codes, env injection, output caps."""
    name = "exec"
    runner = _exec(driver, name)
    async with _running(driver, context, name) as ref:
        await _check_echo(runner, ref, name)
        failed = await runner.exec(ref, ExecRequest(argv=("sh", "-c", f"exit {EXIT_CODE}")))
        code = failed.exit_code
        _expect(code == EXIT_CODE, name, f"exit {EXIT_CODE} gave {code}")
        token = uuid.uuid4().hex
        env = await runner.exec(ref, ExecRequest(argv=("env",), env={ENV_KEY: token}))
        lines = env.stdout.decode(errors="replace").splitlines()
        _expect(f"{ENV_KEY}={token}" in lines, name, "request env did not reach the command")
        payload = "x" * CAP_PAYLOAD_BYTES
        capped = await runner.exec(
            ref, ExecRequest(argv=("echo", payload), max_output_bytes=OUTPUT_CAP)
        )
        _expect(capped.truncated, name, "over-cap output not marked truncated")
        size = len(capped.stdout)
        _expect(size <= OUTPUT_CAP, name, f"capped output is {size} bytes > {OUTPUT_CAP}")


def _tar(filename: str, payload: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        member = tarfile.TarInfo(filename)
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    return buffer.getvalue()


def _untar(data: bytes, filename: str) -> bytes | None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive.getmembers():
            handle = archive.extractfile(member) if member.isfile() else None
            if handle is not None and member.name.rsplit("/", 1)[-1] == filename:
                return handle.read()
    return None


async def _one_chunk(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def check_archive(driver: object, context: DriverContext) -> None:
    """A tar put into the instance comes back byte-identical, plain and with its stat."""
    name = "archive"
    if not isinstance(driver, RuntimeArchive) or not isinstance(driver, ArchiveStreamDriver):
        raise ConformanceFailure(name, "driver does not implement the archive protocols")
    async with _running(driver, context, name) as ref:
        filename = f"conformance-{uuid.uuid4().hex[:12]}.txt"
        payload = f"sandfort conformance {filename}\n".encode()
        await driver.put_archive(ref, ARCHIVE_DIR, _one_chunk(_tar(filename, payload)))
        path = f"{ARCHIVE_DIR}/{filename}"
        data = b"".join([chunk async for chunk in driver.get_archive(ref, path)])
        _expect(_untar(data, filename) == payload, name, "get_archive changed the file")
        stat, stream = await driver.get_archive_with_stat(ref, path)
        streamed = b"".join([chunk async for chunk in stream])
        _expect(stat.get("name") == filename, name, f"stat names {stat.get('name')!r}")
        _expect(_untar(streamed, filename) == payload, name, "get_archive_with_stat changed it")


async def exec_log_emitter(driver: object, ref: str, lines: Sequence[str]) -> None:
    """Default emitter: print ``lines`` on the main process's stdout, which logs capture."""
    result = await _exec(driver, "logs").exec(
        ref, ExecRequest(argv=("sh", "-c", EMIT_SCRIPT, "sh", *lines))
    )
    if result.exit_code != 0:
        detail = result.stderr.decode(errors="replace").strip()
        message = f"emitting log lines exited {result.exit_code}: {detail}"
        raise ConformanceFailure("logs", message)


async def _tail(logs: LogsDriver, ref: str, count: int) -> list[str]:
    return [entry.line.rstrip("\r\n") async for entry in logs.stream_logs(ref, tail=count)]


async def check_logs(driver: object, context: DriverContext) -> None:
    """Lines emitted into an instance come back from ``stream_logs`` with ``tail``."""
    name = "logs"
    if not isinstance(driver, LogsDriver):
        raise ConformanceFailure(name, "driver does not implement the logs protocol")
    emit = context.emit_logs or exec_log_emitter
    async with _running(driver, context, name) as ref:
        token = uuid.uuid4().hex[:12]
        lines = [f"conformance-{token}-{index}" for index in range(1, LOG_LINES + 1)]
        await emit(driver, ref, lines)
        deadline = time.monotonic() + context.log_deadline_s
        got = await _tail(driver, ref, LOG_LINES)
        while got != lines and time.monotonic() < deadline:  # log shipping may lag
            await asyncio.sleep(POLL_S)
            got = await _tail(driver, ref, LOG_LINES)
        _expect(got == lines, name, f"tail={LOG_LINES} returned {got}, expected {lines}")
        last = await _tail(driver, ref, 1)
        _expect(last == lines[-1:], name, f"tail=1 returned {last}")


async def check_volumes(driver: object, context: DriverContext) -> None:
    """Create, inspect, list and remove a named volume."""
    name = "volumes"
    if not isinstance(driver, RuntimeVolumes) or not isinstance(driver, NamedVolumeDriver):
        raise ConformanceFailure(name, "driver does not implement the volume protocols")
    volume_name = f"sf-conformance-{uuid.uuid4().hex[:12]}"
    info = await driver.create_volume(volume_name, labels={"suite": SUITE_LABEL})
    removed = False
    try:
        _expect(info.name == volume_name, name, f"create_volume named it {info.name!r}")
        inspected = await driver.inspect_volume(info.ref)
        _expect(inspected.get("name") == volume_name, name, f"inspect gave {inspected}")
        listed = {item.ref for item in await driver.list_volumes()}
        _expect(info.ref in listed, name, f"list_volumes does not report {info.ref}")
        await driver.remove_volume(info.ref)
        removed = True
        gone = driver.inspect_volume(info.ref)
        await _expect_missing(gone, name, f"volume {info.ref} survived remove_volume")
    finally:
        if not removed:
            await _cleanup(driver.remove_volume(info.ref), name, info.ref)


async def check_images(driver: object, context: DriverContext) -> None:
    """The context image is present (pulled only when missing); an absent one reads absent."""
    name = "images"
    if not isinstance(driver, RuntimeImages) or not isinstance(driver, ImageRegistryDriver):
        raise ConformanceFailure(name, "driver does not implement the image protocols")
    pulled = not await driver.image_exists(context.image)
    if pulled:
        await driver.pull_image_digest(context.image)
    try:
        exists = await driver.image_exists(context.image)
        _expect(exists, name, f"{context.image} is absent after a pull")
        info = await driver.inspect_image(context.image)
        _expect(bool(info.digest), name, f"inspect_image gave no digest for {context.image}")
        absent = f"sandfort-conformance/absent:{uuid.uuid4().hex[:12]}"
        _expect(not await driver.image_exists(absent), name, f"{absent} reads as present")
    finally:
        if pulled:
            await _cleanup(driver.remove_image(context.image), name, context.image)


type Check = Callable[[object, DriverContext], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class ConformanceCheck:
    name: str
    requires: frozenset[Capability]
    run: Check


def _instance_check(name: str, capability: Capability, run: Check) -> ConformanceCheck:
    """A check that boots an instance, so it needs compute besides its own capability."""
    return ConformanceCheck(name, frozenset({Capability.COMPUTE, capability}), run)


SUITE: tuple[ConformanceCheck, ...] = (
    _instance_check("compute", Capability.COMPUTE, check_compute),
    _instance_check("exec", Capability.EXEC, check_exec),
    _instance_check("archive", Capability.ARCHIVE, check_archive),
    _instance_check("logs", Capability.LOGS, check_logs),
    ConformanceCheck("volumes", frozenset({Capability.VOLUMES}), check_volumes),
    ConformanceCheck("images", frozenset({Capability.IMAGES}), check_images),
)
CHECKS: Mapping[str, ConformanceCheck] = {check.name: check for check in SUITE}


@dataclass(frozen=True, slots=True)
class SuiteReport:
    driver: str
    capabilities: frozenset[Capability]
    passed: tuple[str, ...]
    failed: Mapping[str, str]
    skipped: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.failed

    def summary(self) -> str:
        failures = "; ".join(f"{check}: {reason}" for check, reason in self.failed.items())
        skipped = list(self.skipped)
        return f"{self.driver}: passed={list(self.passed)} skipped={skipped} failed={failures}"


async def _outcome(
    check: ConformanceCheck, driver: object, context: DriverContext
) -> str | None:
    """``None`` when the check passes, else the failure reason."""
    try:
        await check.run(driver, context)
    except ConformanceFailure as exc:
        return exc.message
    except Exception as exc:
        logger.warning("conformance check %s raised", check.name, exc_info=True)
        return f"{type(exc).__name__}: {exc}"
    return None


async def run_suite(
    driver: object,
    context: DriverContext | None = None,
    *,
    capabilities: Iterable[Capability] | None = None,
    checks: Sequence[ConformanceCheck] = SUITE,
) -> SuiteReport:
    """Run ``checks`` the declared capabilities allow; the rest are skipped-by-capability.

    A capability declared but not structurally implemented fails the ``protocols`` entry.
    """
    resolved = context or DriverContext()
    implemented = detect_capabilities(driver)
    declared = implemented if capabilities is None else frozenset(capabilities)
    failed: dict[str, str] = {}
    unimplemented = sorted(declared - implemented)
    if unimplemented:
        failed[PROTOCOLS_CHECK] = f"declared but not implemented: {', '.join(unimplemented)}"
    passed: list[str] = []
    skipped: list[str] = []
    for check in checks:
        if not check.requires <= declared:
            skipped.append(check.name)
            continue
        reason = await _outcome(check, driver, resolved)
        if reason is None:
            passed.append(check.name)
        else:
            failed[check.name] = reason
    driver_name = str(getattr(driver, "name", type(driver).__name__))
    return SuiteReport(driver_name, declared, tuple(passed), failed, tuple(skipped))


class DriverContract:
    """One driver under test; the behavioural checks need a ``DriverContext``."""

    def __init__(
        self,
        driver: object,
        context: DriverContext | None = None,
        *,
        capabilities: Iterable[Capability] | None = None,
    ) -> None:
        self.driver = driver
        self.context = context
        self.capabilities = None if capabilities is None else frozenset(capabilities)

    def check_protocols(self) -> list[str]:
        """Verify structural conformance to every protocol; return the names checked."""
        implemented = detect_capabilities(self.driver)
        missing = [name for name in PROTOCOLS if name not in implemented]
        if missing:
            raise DriverContractError(f"driver does not satisfy protocols: {', '.join(missing)}")
        return [str(name) for name in PROTOCOLS]

    def _context(self, operation: str) -> DriverContext:
        if self.context is None:
            message = f"{operation} needs a DriverContext (image, keepalive argv); see {OWNER}"
            raise NotImplementedError(message)
        return self.context

    async def run(self) -> SuiteReport:
        return await run_suite(self.driver, self._context("run"), capabilities=self.capabilities)

    async def check(self, name: str) -> None:
        """Run the check ``name`` (``compute``, ``exec``, ``archive``, ``logs``, ...)."""
        await CHECKS[name].run(self.driver, self._context(f"check_{name}"))

    async def check_compute(self) -> None:
        await self.check("compute")

    async def check_exec(self) -> None:
        await self.check("exec")
