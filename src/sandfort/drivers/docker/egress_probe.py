"""Egress probe: start a canary container on each managed network and try to get out.

The startup gate used to trust a flag the operator set after running ``deploy/host-setup.sh``.
The probe checks the result instead: from inside one short-lived container per managed
network it attempts TCP connects (2 s timeout) to the link-local metadata address, the bridge
gateway's SSH port, one RFC 1918 address and, on the allowlist network only, one public
address. Every attempt must be refused or time out; a target that accepts is a finding.

The canary first checks that ``nc`` and ``timeout`` exist and prints ``READY``, then connects
to a listener it started on loopback and prints ``LOOPBACK OK`` (positive controls): a missing
marker or a non-zero exit means the probe could not run, never a pass.
Any failure of the probe, whatever its type, is a "could not run" finding (fail closed).

The canary uses the configured probe image and the daemon's default runtime, carries no
sandbox labels (only ``CANARY_LABEL``) and is removed afterwards; canaries an interrupted
start left behind are pruned at the start of the next probe. ``CanaryRunner`` is the seam
the tests fake.
"""

import asyncio
import ipaddress
import logging
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from sandfort.drivers.docker.client import clean_message, docker_errors, run_blocking
from sandfort.drivers.docker.networks import EGRESS_NETWORK_NAME, NETWORK_NAME, ensure_network

logger = logging.getLogger(__name__)

DEFAULT_PROBE_IMAGE = "alpine:3.20"
METADATA_TARGET = "169.254.169.254:80"
GATEWAY_PORT = 22
PRIVATE_TARGET = "10.255.255.254:80"  # RFC 1918; nothing should answer or route there
PUBLIC_TARGET = "1.1.1.1:443"  # probed on the allowlist network only
CONNECT_TIMEOUT_S = 2
CANARY_DEADLINE_S = 30.0  # the whole canary run, image pull excluded
REMOVE_DEADLINE_S = 10.0  # one canary removal; a stuck daemon must not hold the probe
STALE_CANARY_S = 300  # a canary older than this belongs to no running probe
REACHABLE_MARK = "REACHABLE "
READY_MARK = "READY"
LOOPBACK_MARK = "LOOPBACK OK"  # printed only after a connect to the canary's own listener
LOOPBACK_PORT = 18080
LOOPBACK_TRIES = 10  # the listener starts in the background: retry the connect briefly
MISSING_TOOL_STATUS = 3  # the canary's exit status when nc or timeout is missing
PROBE_FINDING_PREFIX = "egress probe"
PROBED_NETWORKS = (NETWORK_NAME, EGRESS_NETWORK_NAME)
CANARY_MEMORY = "32m"
CANARY_PIDS_LIMIT = 64
CANARY_LABEL = "sandfort.egress_probe"
CANARY_LABEL_VALUE = "canary"
CANARY_STARTED_LABEL = "sandfort.egress_probe.started"  # epoch seconds of the create
CANARY_FILTERS = {"label": [f"{CANARY_LABEL}={CANARY_LABEL_VALUE}"]}
MIN_SUBNET_ADDRESSES = 4  # network, gateway, one sandbox and broadcast at the least
# Positive controls first: both tools exist (READY), then a listener on loopback that the
# canary itself connects to (LOOPBACK OK), so a broken ``nc`` cannot make every target look
# refused. One backgrounded connect per target (``$@``); busybox ``nc`` exits 0 only when
# connected.
CANARY_SCRIPT = (
    "command -v nc >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1"
    f" || exit {MISSING_TOOL_STATUS}; echo {READY_MARK};"
    f" timeout {LOOPBACK_TRIES} nc -l -s 127.0.0.1 -p {LOOPBACK_PORT}"
    " </dev/null >/dev/null 2>&1 & l=$!;"
    f" for i in $(seq {LOOPBACK_TRIES}); do"
    f" timeout {CONNECT_TIMEOUT_S} nc -w 1 127.0.0.1 {LOOPBACK_PORT} </dev/null"
    f" >/dev/null 2>&1 && {{ echo '{LOOPBACK_MARK}'; break; }}; sleep 0.2; done;"
    " kill $l >/dev/null 2>&1;"
    ' for t in "$@"; do ('
    'h="${t%:*}"; p="${t#*:}";'
    f' timeout {CONNECT_TIMEOUT_S + 2} nc -w {CONNECT_TIMEOUT_S} "$h" "$p" </dev/null'
    f' >/dev/null 2>&1 && echo "{REACHABLE_MARK}$t") & done; wait'
)


class EgressProbeError(RuntimeError):
    """The probe could not run (no image, no daemon, no gateway); never read as a pass."""


class CanaryRunner(Protocol):
    async def prune(self) -> None:
        """Remove canaries an earlier, interrupted probe left behind."""
        ...

    async def gateway(self, network: str) -> str:
        """The bridge gateway address of ``network``."""
        ...

    async def reachable(self, network: str, image: str, targets: Sequence[str]) -> frozenset[str]:
        """Run one canary on ``network``; the ``host:port`` targets that accepted a connect."""
        ...


@dataclass(frozen=True, slots=True)
class NetworkFinding:
    network: str
    reachable: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EgressProbeReport:
    networks: tuple[NetworkFinding, ...]

    def findings(self) -> list[str]:
        """One line per network that had a reachable target; empty when all were refused."""
        return [
            f"{PROBE_FINDING_PREFIX}: network {found.network} reached"
            f" {', '.join(found.reachable)} (expected refused or unreachable)"
            for found in self.networks
            if found.reachable
        ]


def describe(exc: BaseException) -> str:
    """``Type: message`` with daemon urls and container ids cleaned out."""
    return f"{type(exc).__name__}: {clean_message(exc)}"


def targets_for(network: str, gateway: str) -> list[str]:
    """The ``host:port`` targets probed on ``network``."""
    targets = [METADATA_TARGET, f"{gateway}:{GATEWAY_PORT}", PRIVATE_TARGET]
    if network == EGRESS_NETWORK_NAME:
        targets.append(PUBLIC_TARGET)
    return targets


async def _probe_one(runner: CanaryRunner, network: str, image: str) -> NetworkFinding:
    try:
        targets = targets_for(network, await runner.gateway(network))
        hits = await runner.reachable(network, image, targets)
    except EgressProbeError:
        raise
    except Exception as exc:  # a fake client or a docker-py surprise: still fail closed
        raise EgressProbeError(f"network {network}: {describe(exc)}") from exc
    return NetworkFinding(network, tuple(t for t in targets if t in hits))


async def probe_networks(runner: CanaryRunner, image: str) -> EgressProbeReport:
    """Probe every managed network; raises ``EgressProbeError`` when a canary cannot run."""
    try:
        await runner.prune()
    except EgressProbeError:
        raise
    except Exception as exc:
        raise EgressProbeError(f"stale canaries: {describe(exc)}") from exc
    results = [await _probe_one(runner, network, image) for network in PROBED_NETWORKS]
    return EgressProbeReport(tuple(results))


async def probe_findings(runner: CanaryRunner, image: str) -> list[str]:
    """The probe's findings; a probe that cannot run, for any reason, is itself one finding."""
    try:
        return (await probe_networks(runner, image)).findings()
    except Exception as exc:  # never a traceback at startup, never a pass
        detail = str(exc) if isinstance(exc, EgressProbeError) else describe(exc)
        return [f"{PROBE_FINDING_PREFIX} could not run: {detail}"]


def parse_reachable(output: str, known: Sequence[str]) -> frozenset[str]:
    """The targets a canary reported as reachable; names outside ``known`` are ignored."""
    reported = {
        line[len(REACHABLE_MARK) :].strip()
        for line in output.splitlines()
        if line.startswith(REACHABLE_MARK)
    }
    return frozenset(reported & set(known))


def parse_canary(output: str, status: int, known: Sequence[str]) -> frozenset[str]:
    """The reachable targets of a canary that ran; ``EgressProbeError`` when it did not."""
    if status == MISSING_TOOL_STATUS:
        raise EgressProbeError(f"canary exited with status {status}: nc or timeout is missing")
    if status != 0:
        raise EgressProbeError(f"canary exited with status {status}")
    if READY_MARK not in (line.strip() for line in output.splitlines()):
        raise EgressProbeError(f"canary did not print {READY_MARK}")
    if LOOPBACK_MARK not in (line.strip() for line in output.splitlines()):
        raise EgressProbeError(f"canary did not print {LOOPBACK_MARK}: nc cannot connect")
    return parse_reachable(output, known)


def _address(value: object) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def _subnet_gateway(value: object) -> str | None:
    """The first host of a subnet with room for a gateway and a sandbox; else ``None``."""
    if not value:
        return None
    try:
        subnet = ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        return None
    if subnet.num_addresses < MIN_SUBNET_ADDRESSES:
        return None  # /31, /32 (or /127, /128): no bridge gateway to speak of
    return str(next(iter(subnet.hosts()), subnet.network_address))


def gateway_of(attrs: Mapping[str, Any]) -> str | None:
    """The bridge gateway from a network's IPAM config; ``None`` for odd or unparsable ones."""
    ipam = attrs.get("IPAM")
    configs = ipam.get("Config") if isinstance(ipam, Mapping) else None
    for config in configs if isinstance(configs, list) else []:
        if not isinstance(config, Mapping):
            continue
        address = _address(config.get("Gateway")) or _subnet_gateway(config.get("Subnet"))
        if address is not None:
            return address
    return None


def _exit_status(result: object) -> int:
    code = result.get("StatusCode") if isinstance(result, Mapping) else None
    return code if isinstance(code, int) else -1


def _is_stale(container: Any, now: float) -> bool:
    labels = getattr(container, "labels", None) or {}
    try:
        started = float(labels.get(CANARY_STARTED_LABEL, ""))
    except (AttributeError, TypeError, ValueError):
        return True  # no usable timestamp: no running probe can own it
    return now - started > STALE_CANARY_S


class DockerCanaryRunner:
    """Runs the canary through a docker-py client."""

    def __init__(self, client: Any) -> None:
        self._client = client

    async def prune(self) -> None:
        try:
            listing = self._client.containers.list
            found = await run_blocking(listing, all=True, filters=CANARY_FILTERS)
        except Exception as exc:
            raise EgressProbeError(f"listing stale canaries: {describe(exc)}") from exc
        now = time.time()  # a fresh canary may belong to a concurrent start: leave it
        stale = [container for container in found if _is_stale(container, now)]
        for container in stale:
            await self._remove(container)
        if stale:
            logger.info("removed %d stale egress probe canary container(s)", len(stale))

    async def gateway(self, network: str) -> str:
        try:
            await ensure_network(self._client, network)
            found = await run_blocking(self._client.networks.get, network)
            attrs = getattr(found, "attrs", None)
            address = gateway_of(attrs if isinstance(attrs, Mapping) else {})
        except Exception as exc:
            raise EgressProbeError(f"network {network}: {describe(exc)}") from exc
        if address is None:
            raise EgressProbeError(f"network {network} reports no usable gateway address")
        return address

    async def _ensure_image(self, image: str) -> None:
        errors = docker_errors()
        try:
            await run_blocking(self._client.images.get, image)
        except errors.ImageNotFound:
            logger.info("pulling the egress probe image %s", image)
            await run_blocking(self._client.images.pull, image)

    async def _run(self, network: str, image: str, targets: Sequence[str]) -> frozenset[str]:
        container: Any = None
        try:
            await self._ensure_image(image)
            container = await run_blocking(
                self._client.containers.create,
                image,
                ["sh", "-c", CANARY_SCRIPT, "canary", *targets],
                network=network,
                labels={
                    CANARY_LABEL: CANARY_LABEL_VALUE,
                    CANARY_STARTED_LABEL: str(int(time.time())),
                },
                cap_drop=["ALL"],
                security_opt=["no-new-privileges"],
                mem_limit=CANARY_MEMORY,
                pids_limit=CANARY_PIDS_LIMIT,
            )
            await run_blocking(container.start)
            status = _exit_status(await run_blocking(container.wait, timeout=CANARY_DEADLINE_S))
            logs = await run_blocking(container.logs, stdout=True, stderr=False)
            output = bytes(logs).decode("utf-8", errors="replace")
        finally:
            if container is not None:
                await self._remove(container)
        return parse_canary(output, status, targets)

    async def reachable(self, network: str, image: str, targets: Sequence[str]) -> frozenset[str]:
        try:
            return await self._run(network, image, targets)
        except EgressProbeError as exc:
            raise EgressProbeError(f"canary on {network}: {exc}") from exc
        except Exception as exc:
            raise EgressProbeError(f"canary on {network}: {describe(exc)}") from exc

    @staticmethod
    async def _remove(container: Any) -> None:
        try:
            await asyncio.wait_for(run_blocking(container.remove, force=True), REMOVE_DEADLINE_S)
        except Exception:
            logger.warning("egress probe canary container was not removed", exc_info=True)


def canary_runner_for(driver: object) -> CanaryRunner | None:
    """A runner over the docker driver's client; ``None`` for a driver without one."""
    client = getattr(driver, "_client", None)
    return None if client is None else DockerCanaryRunner(client)
