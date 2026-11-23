"""Server settings read from ``SANDFORT_*`` environment variables.

SECURITY: the ``SANDFORT_`` prefix is reserved for the server. These variables
must never reach a sandbox environment; ``is_reserved_env_name`` is used to
reject them on input, and a Gate 1 test asserts ``env`` inside a sandbox is clean.
No secret has a usable default (the key pepper defaults to empty and must be
supplied by the operator).
"""

import ipaddress
import logging
import math
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from cryptography.fernet import Fernet

from sandfort.audit_signing import AUDIT_SIGNING_KEY_ENV, HeadSigner, signer_from_text
from sandfort.domain.isolation import (
    DEFAULT_TIER,
    GVISOR,
    MICROVM,
    TIERS,
    TierRuntimes,
    available_runtimes,
    check_default_tier,
    parse_tier_runtimes,
)
from sandfort.domain.node import DEFAULT_NODE_ID
from sandfort.domain.quota import OrgQuota
from sandfort.domain.user import OrgRole

ENV_PREFIX = "SANDFORT_"
MIN_SESSION_SECRET_CHARS = 32
MIN_SESSION_TTL_S = 60
MAX_SESSION_TTL_S = 86400
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")
# The preview host parser expects ``<port>-<sandbox-id>.preview.<domain>``.
PREVIEW_DOMAIN_PATTERN = re.compile(r"preview(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+")
PREVIEW_URL_SCHEMES = ("http", "https")
# Where browsers reach the API: scheme, authority and an optional path prefix, no query.
PUBLIC_API_URL_PATTERN = re.compile(r"(?:https?|wss?)://[^\s/?#]+(?:/[^\s?#]*)?", re.IGNORECASE)
# Where peer nodes forward toolbox calls: ``http://host:port`` only; no path, query or userinfo.
NODE_INTERNAL_URL_PATTERN = re.compile(
    r"http://(?:[A-Za-z0-9][A-Za-z0-9_.-]*|\[[0-9A-Fa-f:.]+\]):(?P<port>[0-9]{1,5})"
)
MAX_PORT = 65535
VALID_ROLES = ("all", "api", "worker")
VALID_DRIVERS = ("docker", "fake")
VALID_TRACE_EXPORTERS = ("none", "console")  # "none": spans stay in process (no export)
# A systemd slice name: components of letters, digits, "_", "@", ":" and "." (never starting with
# a dot) joined by single hyphens, ending in exactly one ".slice". No "/" (path), no ".." (parent
# reference), no whitespace or control chars; the root slice "-.slice" and a leading, trailing or
# doubled hyphen are rejected.
CGROUP_PARENT_PATTERN = re.compile(
    r"(?!.*\.\.)(?!.*\.slice\.slice)"
    r"[A-Za-z0-9_@:][A-Za-z0-9_@:.]*(?:-[A-Za-z0-9_@:][A-Za-z0-9_@:.]*)*\.slice"
)
BUILD_NETWORK_ENV = ENV_PREFIX + "BUILD_NETWORK"  # also read by the docker build module
BUILD_NETWORK_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]*")
ALLOWED_REGISTRIES_ENV = ENV_PREFIX + "ALLOWED_REGISTRIES"
REGISTRY_LIST_SEPARATOR = ","
REGISTRY_HOST_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?(?::[0-9]{1,5})?")


def parse_allowed_registries(raw: str) -> tuple[str, ...]:
    """The registry hosts of a comma separated allowlist, lowercased, blanks dropped.

    An entry must be a bare ``host[:port]``: a scheme (``https://``), a path or whitespace is a
    ``ValueError`` naming the entry, so a typo fails at startup instead of matching nothing.
    """
    hosts: list[str] = []
    for item in raw.split(REGISTRY_LIST_SEPARATOR):
        entry = item.strip()
        if not entry:
            continue
        if "://" in entry:
            raise ValueError(
                f"{ALLOWED_REGISTRIES_ENV} entries are registry hosts such as ghcr.io or"
                f" registry.example.com:5000; remove the scheme from {entry!r}"
            )
        host = entry.lower()
        if REGISTRY_HOST_PATTERN.fullmatch(host) is None:
            raise ValueError(
                f"{ALLOWED_REGISTRIES_ENV} entries must be a registry host with an optional"
                f" port (no path or whitespace), got {entry!r}"
            )
        hosts.append(host)
    return tuple(hosts)


# The env default of REQUIRE_BUILD_RUNTIME. The dataclass field stays False so a Settings built
# directly (tests, tools) does not pick up a prod refusal it never asked for.
DEFAULT_REQUIRE_BUILD_RUNTIME = True
# The env default of ALLOW_ROOT_SHARED_KERNEL; the dataclass field is True for the same reason.
DEFAULT_ALLOW_ROOT_SHARED_KERNEL = False
RUNC_VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?")  # MIN_RUNC_VERSION, e.g. 1.1.12
GVISOR_RUNTIME_PREFIX = "runsc"  # a gvisor tier's runtime name starts with this
KATA_RUNTIME_MARKER = "kata"  # a microvm tier's runtime name contains this
PROD_ENVIRONMENT = "prod"
VALID_ENVIRONMENTS = ("dev", PROD_ENVIRONMENT)  # prod refuses to start on a weakly isolated host
TRUE_WORDS = ("1", "true", "yes", "on")
FALSE_WORDS = ("0", "false", "no", "off")
AUDIT_CHAIN_KEY_ENV = ENV_PREFIX + "AUDIT_CHAIN_KEY"
AUDIT_CHAIN_ACCEPT_UNKEYED_ENV = ENV_PREFIX + "AUDIT_CHAIN_ACCEPT_UNKEYED"
MIN_AUDIT_CHAIN_KEY_BYTES = 32
SIGNING_WITHOUT_CHAIN_KEY = (
    f"{AUDIT_SIGNING_KEY_ENV} is set without {AUDIT_CHAIN_KEY_ENV}: signing needs the chain"
    f" key, so audit heads would not be signed; set {AUDIT_CHAIN_KEY_ENV} as well"
)
_LOG = logging.getLogger(__name__)
VALID_SCIM_ROLES = tuple(role.value for role in OrgRole)
DEFAULT_GVISOR_DNS = "1.1.1.1,8.8.8.8"  # public resolvers written into gVisor sandboxes
GVISOR_DNS_SEPARATOR = ","
# Tiers whose runtime cannot run under daemon-wide user-namespace remapping (Kata): their
# containers opt out per container with the host user namespace mode.
DEFAULT_USERNS_HOST_TIERS: tuple[str, ...] = (MICROVM,)
TIER_LIST_SEPARATOR = ","
# Test hooks of ``SANDFORT_FAULT_INJECTION`` (never for production; see docs/operations.md).
FAULT_RESIZE_COMMIT_FAIL = "resize_commit_fail"  # a DriverError instead of the resize commit
FAULT_RESIZE_CREATE_FAIL = "resize_create_fail"  # a DriverError instead of the create after it
# The docker restore upload stalls after its first piece went to the daemon (extraction began).
FAULT_RESTORE_EXTRACT_HOLD = "restore_extract_hold"
# The start-up restore recovery fails to empty every marked volume, without calling the driver.
FAULT_VOLUME_RECOVERY_CLEAR_FAIL = "volume_recovery_clear_fail"
VALID_FAULTS = (
    FAULT_RESIZE_COMMIT_FAIL,
    FAULT_RESIZE_CREATE_FAIL,
    FAULT_RESTORE_EXTRACT_HOLD,
    FAULT_VOLUME_RECOVERY_CLEAR_FAIL,
)
# Egress proxy limits (read by the proxy process and by Settings; see sandfort.egress.proxy).
DEFAULT_EGRESS_DENIED_CIDRS: tuple[str, ...] = (
    "127.0.0.0/8",
    "::1/128",
    "169.254.0.0/16",
    "fe80::/10",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
)
DEFAULT_EGRESS_ALLOWED_PORTS: tuple[int, ...] = (443, 80)
DEFAULT_EGRESS_MAX_CONNECTIONS = 64
DEFAULT_EGRESS_IDLE_TIMEOUT_S = 300
DEFAULT_EGRESS_TOKEN_TTL_S = 7 * 24 * 3600
MIN_EGRESS_TOKEN_TTL_S = 60
MAX_EGRESS_TOKEN_TTL_S = 400 * 24 * 3600
LIST_SEPARATOR = ","


def parse_fault_injection(raw: str) -> tuple[str, ...]:
    """The fault names of a comma separated list, blanks dropped; an unknown name is refused.

    A typo must fail at startup: a hook that silently matches nothing would look like a passing
    fault-injection test.
    """
    faults: list[str] = []
    for item in raw.split(TIER_LIST_SEPARATOR):
        name = item.strip().lower()
        if not name:
            continue
        if name not in VALID_FAULTS:
            raise ValueError(
                f"{ENV_PREFIX}FAULT_INJECTION: unknown fault {name!r}; known: {VALID_FAULTS}"
            )
        if name not in faults:
            faults.append(name)
    return tuple(faults)


def parse_cidrs(raw: str) -> tuple[str, ...]:
    """Parse a comma-separated CIDR list (blank = none) into canonical text forms."""
    entries = [part.strip() for part in raw.split(LIST_SEPARATOR) if part.strip()]
    try:
        return tuple(str(ipaddress.ip_network(entry, strict=False)) for entry in entries)
    except ValueError as exc:
        raise ValueError(f"not a CIDR list: {raw!r}") from exc


def parse_ports(raw: str) -> tuple[int, ...]:
    """Parse a comma-separated port list; every entry must be 1..65535."""
    ports: list[int] = []
    for part in (piece.strip() for piece in raw.split(LIST_SEPARATOR)):
        if not (part.isascii() and part.isdigit() and 1 <= int(part) <= MAX_PORT):
            raise ValueError(f"not a port list: {raw!r}")
        ports.append(int(part))
    return tuple(ports)


def parse_nameservers(raw: str) -> tuple[str, ...]:
    """Parse a comma-separated IPv4/IPv6 list; blank means no entries.

    Each entry is returned in its canonical text form. A bad entry (empty, not an address, or
    an IPv6 zone id) raises ``ValueError`` naming it, so nothing odd reaches ``resolv.conf``.
    """
    if not raw.strip():
        return ()
    nameservers: list[str] = []
    for part in raw.split(GVISOR_DNS_SEPARATOR):
        entry = part.strip()
        try:
            if "%" in entry:
                raise ValueError(entry)
            nameservers.append(str(ipaddress.ip_address(entry)))
        except ValueError:
            raise ValueError(
                f"{ENV_PREFIX}GVISOR_DNS entry {entry!r} is not an IPv4 or IPv6 address"
            ) from None
    return tuple(nameservers)


def parse_tier_list(raw: str, variable: str) -> tuple[str, ...]:
    """Parse a comma-separated list of isolation tier names; blank means none.

    Duplicates collapse (first position wins). An unknown tier raises ``ValueError`` naming
    the variable, so a typo cannot silently leave a tier remapped or opted out.
    """
    tiers: list[str] = []
    for part in raw.split(TIER_LIST_SEPARATOR):
        tier = part.strip().lower()
        if not tier:
            continue
        if tier not in TIERS:
            raise ValueError(
                f"{ENV_PREFIX}{variable} entry {tier!r} is not a tier;"
                f" valid tiers: {', '.join(TIERS)}"
            )
        if tier not in tiers:
            tiers.append(tier)
    return tuple(tiers)


def is_reserved_env_name(name: str) -> bool:
    """True for names in the server-only ``SANDFORT_`` namespace."""
    return name.upper().startswith(ENV_PREFIX)


@dataclass(frozen=True, slots=True)
class Settings:
    env: str = "dev"
    role: str = "all"
    host: str = "127.0.0.1"
    port: int = 8000
    database_url: str = "sqlite+aiosqlite:///./sandfort.db"
    database_pool_size: int = 5  # Postgres connections kept open; SQLite ignores both pool knobs
    database_max_overflow: int = 10  # extra Postgres connections allowed beyond the pool
    driver: str = "docker"
    docker_thread_limit: int = 64  # total worker threads of the docker driver
    docker_bulk_threads: int = 48  # bulk-lane ceiling inside the total (clamped to total - 1)
    api_key_pepper: str = ""
    log_level: str = "INFO"
    max_sandbox_cpu_millicores: int = 4000
    max_sandbox_memory_mib: int = 8192
    max_sandbox_disk_gib: int = 20
    default_exec_timeout_s: int = 60
    max_exec_timeout_s: int = 3600
    max_output_bytes: int = 1024 * 1024
    max_ptys_per_org: int = 8  # live terminals per org in this process; 0 = unlimited
    max_async_commands_per_org: int = 16  # running async session commands per org; 0 = unlimited
    max_volume_transfers_per_org: int = 2  # running volume exports and restores per org; 0 = no cap
    max_volume_transfers: int = 8  # the same in this process, all orgs; 0 = no cap
    reconcile_interval_s: int = 30
    orphan_grace_s: int = 300
    job_execution_enabled: bool = True
    autostop_enabled: bool = True
    autostop_interval_s: int = 30
    reconcile_enabled: bool = True
    gc_enabled: bool = True
    gc_interval_s: int = 300
    webhook_dispatcher_enabled: bool = True
    webhook_dispatch_interval_s: int = 5
    webhook_timeout_s: int = 10
    webhook_allow_private_networks: bool = False  # opt-in: admit private receivers (not metadata)
    webhook_secret_key: str = ""  # fernet key sealing webhook secrets at rest; prod requires it
    # Reject non-https webhook URLs at registration and delivery; from_env forces it in prod.
    webhook_require_https: bool = False
    metering_enabled: bool = True
    metering_rollup_interval_s: int = 3600  # hourly rollup pass
    metering_rollup_lookback_hours: int = 3  # completed hours each pass recomputes (idempotent)
    metering_sample_interval_s: int = 300  # disk sampler pass and the window each sample covers
    host_capacity_cpu_millicores: int = 0  # total the host admits across all orgs; 0 = unguarded
    host_capacity_memory_mib: int = 0  # likewise for memory
    host_overcommit_factor: float = 1.0  # effective host capacity = configured capacity * this
    rate_limit_enabled: bool = True
    rate_limit_refill_per_s: int = 100  # tokens returned to each key's bucket per second
    rate_limit_burst: int = 1000  # bucket capacity: back-to-back requests one key may make
    max_request_body_bytes: int = 16 * 1024 * 1024  # JSON body cap; the fs upload route is exempt
    tracing_enabled: bool = True
    tracing_exporter: str = "none"  # one of VALID_TRACE_EXPORTERS
    sandbox_jobs_enabled: bool = False  # lifecycle commands enqueue jobs instead of running inline
    warm_pool_size: int = 0  # standby sandboxes kept per org, snapshot and shape; 0 = pool off
    volume_max_bytes: int = 0  # soft size limit per volume, checked at mount; 0 = no limit
    preview_domain: str = "preview.localtest.me"  # previews: <port>-<sandbox-id>.<this domain>
    proxy_enabled: bool = False  # sandfort-server also serves the preview proxy on proxy_port
    proxy_port: int = 8001
    public_api_url: str = ""  # API base the web terminal dials; "" = the request's host + port
    public_preview_url: str = ""  # origin previews are served on; "" = http + proxy_port
    environment: str = "dev"  # one of VALID_ENVIRONMENTS; prod gates startup on isolation
    container_runtime: str = ""  # docker runtime for sandboxes (e.g. "runsc"); "" = daemon default
    isolation_runtimes: TierRuntimes = ()  # (tier, runtime) pairs; () = default tier only
    default_isolation: str = DEFAULT_TIER  # tier of a create that names none
    gvisor_dns: str = DEFAULT_GVISOR_DNS  # nameservers for gVisor sandboxes; "" = leave as is
    # Explicit override: downgrades an egress probe refusal to a warning. With the probe off,
    # it is the old honour-system confirmation that deploy/host-setup.sh ran.
    egress_acknowledged: bool = False
    egress_probe: bool | None = None  # canary probe of the managed networks; None = on in prod
    egress_probe_image: str = "alpine:3.20"  # canary image; needs sh, nc and timeout (busybox)
    enforce_disk_quota: bool = False  # per-sandbox disk size outside prod (prod always enforces)
    default_block_network: bool = False  # a create naming no network policy gets block_all
    # Operator policy: a create asking for block_all false or an allowlist is refused (403).
    enforce_block_network: bool = False
    # Quota a new org starts with (admin bootstrap/create-org); None = that dimension unlimited.
    default_org_max_sandboxes: int | None = None
    default_org_max_vcpus: float | None = None
    default_org_max_memory_mib: int | None = None
    default_org_max_disk_gib: int | None = None
    allow_unbounded_host: bool = False  # prod may start with no host capacity configured
    egress_allowlist_max_entries: int = 16  # hosts one sandbox's egress allowlist may name
    egress_proxy_address: str = ""  # host:port sandboxes reach the egress proxy on; "" = off
    egress_secret: str = ""  # signs egress tokens; "" = allowlisted creates are refused
    # Proxy targets refused after DNS resolution (the node's own addresses are always added).
    egress_denied_cidrs: tuple[str, ...] = DEFAULT_EGRESS_DENIED_CIDRS
    egress_allowed_ports: tuple[int, ...] = DEFAULT_EGRESS_ALLOWED_PORTS  # CONNECT target ports
    egress_max_connections: int = DEFAULT_EGRESS_MAX_CONNECTIONS  # concurrent, per sandbox
    egress_idle_timeout_s: int = DEFAULT_EGRESS_IDLE_TIMEOUT_S  # idle tunnel is closed after this
    # Lifetime of a minted egress token; it is minted when the sandbox is created.
    egress_token_ttl_s: int = DEFAULT_EGRESS_TOKEN_TTL_S
    # HMAC key of the audit hash chain (>= 32 bytes); "" = the unkeyed SHA-256 chain.
    audit_chain_key: str = ""
    # Ed25519 private key (raw urlsafe base64 or PEM) signing the audit head; "" = HMAC head only.
    audit_signing_key: str = field(default="", repr=False)
    # With a key set, verify still accepts unkeyed rows written before the key existed.
    audit_chain_accept_unkeyed: bool = True
    audit_retention_days: int = 0  # prune audit rows older than this many days; 0 = disabled
    audit_retention_interval_s: int = 3600  # pause between retention passes
    seccomp_profile_path: str = ""  # JSON profile for sandboxes; "" = docker's default profile
    # cgroup parent of every sandbox container (documented value: sandfort.slice); "" = unset.
    cgroup_parent: str = ""
    # Tiers that opt out of daemon-wide userns remapping per container (host user namespace).
    userns_host_tiers: tuple[str, ...] = DEFAULT_USERNS_HOST_TIERS
    # Prod refuses to start when the daemon has no userns remapping; off = reported only.
    require_userns_remap: bool = False
    # Prod refuses to start when the daemon default runtime (tenant image builds run on it) is
    # not a runsc or kata runtime while a sandbox tier offers one. The env default is true.
    require_build_runtime: bool = False
    # Prod refuses to start when a tier runs on a runc-class runtime (not runsc or kata) whose
    # container root is host root (no userns remapping for it), unless this is set. The env
    # default is false; the field stays True like require_build_runtime's stays False.
    allow_root_shared_kernel: bool = True
    min_runc_version: str = ""  # oldest runc the daemon may report, e.g. "1.1.12"; "" = no check
    # Docker network mode for image builds ("" = the daemon default network).
    build_network: str = ""
    # Registries a user image reference or build base may name; () = any registry.
    allowed_registries: tuple[str, ...] = ()
    session_secret: str = ""  # signs user session tokens; "" = user sessions are disabled
    session_ttl_s: int = 3600  # lifetime of a minted user session token
    oidc_issuer: str = ""  # expected ``iss`` of identity tokens; "" = the SSO exchange is off
    oidc_audience: str = ""  # expected ``aud`` (the client id registered with the provider)
    oidc_jwks_url: str = ""  # where the provider publishes its JSON web key set
    oidc_org_id: str = ""  # the org single sign-on signs into
    oidc_jwks_cache_s: int = 300  # how long a fetched key set is reused
    node_id: str = DEFAULT_NODE_ID  # this worker's identity in the node registry
    node_max_sandboxes: int = 0  # sandboxes this node admits; 0 = unlimited
    node_heartbeat_enabled: bool = True
    node_heartbeat_interval_s: int = 15  # pause between registry heartbeats
    node_internal_url: str = ""  # http://host:port peers forward toolbox calls to; "" = none
    routing_secret: str = ""  # signs route tokens between nodes; "" = routing is off
    routing_timeout_s: float = 5.0  # connect, write and pool timeout of one forwarding hop
    scim_enabled: bool = False  # mounts the /scim/v2 and SCIM token routes; off = nothing mounted
    scim_default_role: str = "viewer"  # one of VALID_SCIM_ROLES; role of a SCIM-created user
    # Comma-separated proxy addresses (or "*") whose X-Forwarded-Proto/For uvicorn trusts; behind a
    # TLS-terminating ingress set it so websocket and other absolute urls get the public scheme.
    forwarded_allow_ips: str = "127.0.0.1"
    build_sha: str = ""  # commit of the running build, shown on /v1/status; "" = not reported
    status_notice_file: str = ""  # operator notice read per request by /v1/status; "" = no notice
    # Test hook (SANDFORT_FAULT_INJECTION): faults raised inside the resize replace path. Never in
    # production: /v1/status names them in its notice, startup warns and doctor FAILs.
    fault_injection: tuple[str, ...] = ()
    build_sha_file: str = "/app/BUILD_SHA"  # commit baked into the image; "" or missing = none

    def __post_init__(self) -> None:
        # Validated once at load (``from_env``, a direct constructor or ``replace``), so the
        # signer and ``/v1/status`` never meet a malformed key later.
        audit_signer_of(self.audit_signing_key)

    def audit_signer(self) -> HeadSigner | None:
        """The audit head signer of ``audit_signing_key`` (``None`` when unset).

        The only source of the signing key: exports sign with it and ``/v1/status`` publishes
        its public key, so both always agree. Parsed once per value (cached).
        """
        return audit_signer_of(self.audit_signing_key)

    def egress_probe_enabled(self) -> bool:
        """Whether startup runs the egress probe: the setting, else on in prod only."""
        if self.egress_probe is not None:
            return self.egress_probe
        return self.environment == PROD_ENVIRONMENT

    def default_org_quota(self) -> OrgQuota:
        """The limits a new org starts with; every unset dimension is unlimited."""
        return OrgQuota(
            max_sandboxes=self.default_org_max_sandboxes,
            max_vcpus=self.default_org_max_vcpus,
            max_memory_mib=self.default_org_max_memory_mib,
            max_disk_gib=self.default_org_max_disk_gib,
        )

    def isolation_tiers(self) -> dict[str, str]:
        """Tier -> docker runtime this deployment offers ("" = the daemon default runtime)."""
        return available_runtimes(
            self.isolation_runtimes, self.default_isolation, self.container_runtime
        )

    def gvisor_nameservers(self) -> tuple[str, ...]:
        """The validated ``gvisor_dns`` addresses in order; empty = do not touch resolv.conf."""
        return parse_nameservers(self.gvisor_dns)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        source = os.environ if environ is None else environ
        defaults = cls()

        def text(name: str, default: str) -> str:
            return source.get(ENV_PREFIX + name, default)

        def integer(name: str, default: int) -> int:
            raw = source.get(ENV_PREFIX + name)
            if raw is None:
                return default
            try:
                return int(raw)
            except ValueError as exc:
                raise ValueError(f"{ENV_PREFIX}{name} must be an integer, got {raw!r}") from exc

        def non_negative(name: str, default: int) -> int:
            value = integer(name, default)
            if value < 0:
                raise ValueError(f"{ENV_PREFIX}{name} must be 0 or more, got {value}")
            return value

        def at_least_one(name: str, default: int) -> int:
            value = integer(name, default)
            if value < 1:
                raise ValueError(f"{ENV_PREFIX}{name} must be at least 1, got {value}")
            return value

        def positive_real(name: str, default: float) -> float:
            raw = source.get(ENV_PREFIX + name)
            if raw is None:
                return default
            try:
                value = float(raw)
            except ValueError as exc:
                raise ValueError(f"{ENV_PREFIX}{name} must be a number, got {raw!r}") from exc
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{ENV_PREFIX}{name} must be a positive number, got {raw!r}")
            return value

        def optional_limit[T: (int, float)](name: str, kind: type[T]) -> T | None:
            """An unset or blank variable is no limit; a set one is a finite number >= 0."""
            raw = source.get(ENV_PREFIX + name, "").strip()
            if not raw:
                return None
            try:
                value = kind(raw)
            except ValueError as exc:
                raise ValueError(f"{ENV_PREFIX}{name} must be a number, got {raw!r}") from exc
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{ENV_PREFIX}{name} must be 0 or more, got {raw!r}")
            return value

        def boolean(name: str, default: bool) -> bool:
            raw = source.get(ENV_PREFIX + name)
            if raw is None:
                return default
            lowered = raw.strip().lower()
            if lowered in TRUE_WORDS:
                return True
            if lowered in FALSE_WORDS:
                return False
            raise ValueError(f"{ENV_PREFIX}{name} must be a boolean, got {raw!r}")

        role = text("ROLE", defaults.role)
        if role not in VALID_ROLES:
            raise ValueError(f"{ENV_PREFIX}ROLE must be one of {VALID_ROLES}, got {role!r}")
        driver = text("DRIVER", defaults.driver)
        if driver not in VALID_DRIVERS:
            raise ValueError(f"{ENV_PREFIX}DRIVER must be one of {VALID_DRIVERS}, got {driver!r}")
        exporter = text("TRACING_EXPORTER", defaults.tracing_exporter)
        if exporter not in VALID_TRACE_EXPORTERS:
            raise ValueError(
                f"{ENV_PREFIX}TRACING_EXPORTER must be one of {VALID_TRACE_EXPORTERS},"
                f" got {exporter!r}"
            )
        preview_domain = text("PREVIEW_DOMAIN", defaults.preview_domain).strip().lower()
        if PREVIEW_DOMAIN_PATTERN.fullmatch(preview_domain) is None:
            raise ValueError(
                f"{ENV_PREFIX}PREVIEW_DOMAIN must be a domain whose first label is 'preview',"
                f" got {preview_domain!r}"
            )
        public_api_url = text("PUBLIC_API_URL", defaults.public_api_url).strip().rstrip("/")
        if public_api_url and PUBLIC_API_URL_PATTERN.fullmatch(public_api_url) is None:
            raise ValueError(
                f"{ENV_PREFIX}PUBLIC_API_URL must be empty or an http(s)/ws(s) URL without a"
                f" query, got {public_api_url!r}"
            )
        public_preview_url = _check_public_preview_url(
            text("PUBLIC_PREVIEW_URL", defaults.public_preview_url), preview_domain
        )
        environment = text("ENVIRONMENT", defaults.environment).strip().lower()
        if environment not in VALID_ENVIRONMENTS:
            raise ValueError(
                f"{ENV_PREFIX}ENVIRONMENT must be one of {VALID_ENVIRONMENTS}, got {environment!r}"
            )

        audit_chain_key = audit_chain_key_from(source)
        audit_signing_key = audit_signing_key_from(source)
        if audit_signing_key and not audit_chain_key:
            if environment == PROD_ENVIRONMENT:
                raise ValueError(SIGNING_WITHOUT_CHAIN_KEY)
            _LOG.warning(SIGNING_WITHOUT_CHAIN_KEY)
        if environment == PROD_ENVIRONMENT and not audit_chain_key:
            _LOG.warning(
                "%s is unset: the audit chain is an unkeyed hash, so anyone who can write the"
                " database can rewrite history consistently",
                AUDIT_CHAIN_KEY_ENV,
            )

        build_network = text("BUILD_NETWORK", defaults.build_network).strip()
        if build_network and BUILD_NETWORK_PATTERN.fullmatch(build_network) is None:
            raise ValueError(
                f"{BUILD_NETWORK_ENV} must be a docker network name or mode (letters, digits,"
                f" '_', '.', ':', '-'), got {build_network!r}"
            )
        raw_registries = source.get(ALLOWED_REGISTRIES_ENV)
        allowed_registries = (
            defaults.allowed_registries
            if raw_registries is None
            else parse_allowed_registries(raw_registries)
        )
        cgroup_parent = text("CGROUP_PARENT", defaults.cgroup_parent).strip()
        if cgroup_parent and CGROUP_PARENT_PATTERN.fullmatch(cgroup_parent) is None:
            raise ValueError(
                f"{ENV_PREFIX}CGROUP_PARENT must be a systemd slice name (letters, digits,"
                f" '_', '.', '@', ':' joined by single '-', ending in one '.slice'; not the root"
                f" slice; no path separators, parent references, whitespace or control"
                f" characters), got {cgroup_parent!r}"
            )
        raw_userns_tiers = source.get(ENV_PREFIX + "USERNS_HOST_TIERS")
        userns_host_tiers = (
            defaults.userns_host_tiers
            if raw_userns_tiers is None
            else parse_tier_list(raw_userns_tiers, "USERNS_HOST_TIERS")
        )
        isolation_runtimes, default_isolation = _isolation_settings(
            text("ISOLATION_RUNTIMES", ""), text("DEFAULT_ISOLATION", defaults.default_isolation)
        )

        gvisor_dns = text("GVISOR_DNS", defaults.gvisor_dns).strip()
        parse_nameservers(gvisor_dns)  # fail at load time on a bad entry

        session_secret = text("SESSION_SECRET", defaults.session_secret)
        session_ttl_s = integer("SESSION_TTL_S", defaults.session_ttl_s)
        oidc_issuer = text("OIDC_ISSUER", defaults.oidc_issuer).strip()
        oidc_jwks_url = text("OIDC_JWKS_URL", defaults.oidc_jwks_url).strip()
        oidc_jwks_cache_s = integer("OIDC_JWKS_CACHE_S", defaults.oidc_jwks_cache_s)
        _check_session_settings(
            session_secret, session_ttl_s, oidc_issuer, oidc_jwks_url, oidc_jwks_cache_s
        )
        egress_secret = text("EGRESS_SECRET", defaults.egress_secret)
        if egress_secret and len(egress_secret) < MIN_SESSION_SECRET_CHARS:
            raise ValueError(
                f"{ENV_PREFIX}EGRESS_SECRET must be at least {MIN_SESSION_SECRET_CHARS} characters"
            )
        egress_limits = egress_limits_from(source)
        # Unset keeps None (on in prod only); a set variable is an explicit choice either way.
        egress_probe = (
            boolean("EGRESS_PROBE", True) if ENV_PREFIX + "EGRESS_PROBE" in source else None
        )
        egress_probe_image = text("EGRESS_PROBE_IMAGE", "").strip() or defaults.egress_probe_image
        node_internal_url = text("NODE_INTERNAL_URL", defaults.node_internal_url).strip()
        routing_secret = text("ROUTING_SECRET", defaults.routing_secret)
        _check_routing_settings(node_internal_url, routing_secret)

        scim_default_role = text("SCIM_DEFAULT_ROLE", defaults.scim_default_role).strip()
        if scim_default_role not in VALID_SCIM_ROLES:
            raise ValueError(
                f"{ENV_PREFIX}SCIM_DEFAULT_ROLE must be one of {VALID_SCIM_ROLES},"
                f" got {scim_default_role!r}"
            )

        webhook_secret_key = text("WEBHOOK_SECRET_KEY", defaults.webhook_secret_key).strip()
        if webhook_secret_key:
            try:
                Fernet(webhook_secret_key.encode())
            except ValueError:
                raise ValueError(
                    f"{ENV_PREFIX}WEBHOOK_SECRET_KEY must be a urlsafe base64 fernet key (32 bytes)"
                ) from None
        require_https = boolean("WEBHOOK_REQUIRE_HTTPS", defaults.webhook_require_https)
        webhook_require_https = require_https or environment == PROD_ENVIRONMENT
        min_runc_version = text("MIN_RUNC_VERSION", defaults.min_runc_version).strip()
        if min_runc_version and RUNC_VERSION_PATTERN.fullmatch(min_runc_version) is None:
            raise ValueError(
                f"{ENV_PREFIX}MIN_RUNC_VERSION must be a version like 1.1.12 (digits and dots,"
                f" no 'v' prefix or suffix), got {min_runc_version!r}"
            )

        settings = cls(
            env=text("ENV", defaults.env),
            role=role,
            host=text("HOST", defaults.host),
            port=integer("PORT", defaults.port),
            database_url=text("DATABASE_URL", defaults.database_url),
            database_pool_size=integer("DATABASE_POOL_SIZE", defaults.database_pool_size),
            database_max_overflow=integer("DATABASE_MAX_OVERFLOW", defaults.database_max_overflow),
            driver=driver,
            docker_thread_limit=integer("DOCKER_THREAD_LIMIT", defaults.docker_thread_limit),
            docker_bulk_threads=at_least_one("DOCKER_BULK_THREADS", defaults.docker_bulk_threads),
            api_key_pepper=text("API_KEY_PEPPER", defaults.api_key_pepper),
            log_level=text("LOG_LEVEL", defaults.log_level),
            max_sandbox_cpu_millicores=integer(
                "MAX_SANDBOX_CPU_MILLICORES", defaults.max_sandbox_cpu_millicores
            ),
            max_sandbox_memory_mib=integer(
                "MAX_SANDBOX_MEMORY_MIB", defaults.max_sandbox_memory_mib
            ),
            max_sandbox_disk_gib=integer("MAX_SANDBOX_DISK_GIB", defaults.max_sandbox_disk_gib),
            default_exec_timeout_s=integer(
                "DEFAULT_EXEC_TIMEOUT_S", defaults.default_exec_timeout_s
            ),
            max_exec_timeout_s=integer("MAX_EXEC_TIMEOUT_S", defaults.max_exec_timeout_s),
            max_output_bytes=integer("MAX_OUTPUT_BYTES", defaults.max_output_bytes),
            max_ptys_per_org=non_negative("MAX_PTYS_PER_ORG", defaults.max_ptys_per_org),
            max_async_commands_per_org=non_negative(
                "MAX_ASYNC_COMMANDS_PER_ORG", defaults.max_async_commands_per_org
            ),
            max_volume_transfers_per_org=non_negative(
                "MAX_VOLUME_TRANSFERS_PER_ORG", defaults.max_volume_transfers_per_org
            ),
            max_volume_transfers=non_negative(
                "MAX_VOLUME_TRANSFERS", defaults.max_volume_transfers
            ),
            reconcile_interval_s=integer("RECONCILE_INTERVAL_S", defaults.reconcile_interval_s),
            orphan_grace_s=integer("ORPHAN_GRACE_S", defaults.orphan_grace_s),
            job_execution_enabled=boolean("JOB_EXECUTION_ENABLED", defaults.job_execution_enabled),
            autostop_enabled=boolean("AUTOSTOP_ENABLED", defaults.autostop_enabled),
            autostop_interval_s=integer("AUTOSTOP_INTERVAL_S", defaults.autostop_interval_s),
            reconcile_enabled=boolean("RECONCILE_ENABLED", defaults.reconcile_enabled),
            gc_enabled=boolean("GC_ENABLED", defaults.gc_enabled),
            gc_interval_s=integer("GC_INTERVAL_S", defaults.gc_interval_s),
            webhook_dispatcher_enabled=boolean(
                "WEBHOOK_DISPATCHER_ENABLED", defaults.webhook_dispatcher_enabled
            ),
            webhook_dispatch_interval_s=integer(
                "WEBHOOK_DISPATCH_INTERVAL_S", defaults.webhook_dispatch_interval_s
            ),
            webhook_timeout_s=integer("WEBHOOK_TIMEOUT_S", defaults.webhook_timeout_s),
            webhook_allow_private_networks=boolean(
                "WEBHOOK_ALLOW_PRIVATE_NETWORKS", defaults.webhook_allow_private_networks
            ),
            webhook_secret_key=webhook_secret_key,
            webhook_require_https=webhook_require_https,
            metering_enabled=boolean("METERING_ENABLED", defaults.metering_enabled),
            metering_rollup_interval_s=integer(
                "METERING_ROLLUP_INTERVAL_S", defaults.metering_rollup_interval_s
            ),
            metering_rollup_lookback_hours=integer(
                "METERING_ROLLUP_LOOKBACK_HOURS", defaults.metering_rollup_lookback_hours
            ),
            metering_sample_interval_s=integer(
                "METERING_SAMPLE_INTERVAL_S", defaults.metering_sample_interval_s
            ),
            host_capacity_cpu_millicores=integer(
                "HOST_CAPACITY_CPU_MILLICORES", defaults.host_capacity_cpu_millicores
            ),
            host_capacity_memory_mib=integer(
                "HOST_CAPACITY_MEMORY_MIB", defaults.host_capacity_memory_mib
            ),
            host_overcommit_factor=positive_real(
                "HOST_OVERCOMMIT_FACTOR", defaults.host_overcommit_factor
            ),
            rate_limit_enabled=boolean("RATE_LIMIT_ENABLED", defaults.rate_limit_enabled),
            rate_limit_refill_per_s=integer(
                "RATE_LIMIT_REFILL_PER_S", defaults.rate_limit_refill_per_s
            ),
            rate_limit_burst=integer("RATE_LIMIT_BURST", defaults.rate_limit_burst),
            max_request_body_bytes=integer(
                "MAX_REQUEST_BODY_BYTES", defaults.max_request_body_bytes
            ),
            tracing_enabled=boolean("TRACING_ENABLED", defaults.tracing_enabled),
            tracing_exporter=exporter,
            sandbox_jobs_enabled=boolean("SANDBOX_JOBS_ENABLED", defaults.sandbox_jobs_enabled),
            warm_pool_size=integer("WARM_POOL_SIZE", defaults.warm_pool_size),
            volume_max_bytes=non_negative("VOLUME_MAX_BYTES", defaults.volume_max_bytes),
            preview_domain=preview_domain,
            proxy_enabled=boolean("PROXY_ENABLED", defaults.proxy_enabled),
            proxy_port=integer("PROXY_PORT", defaults.proxy_port),
            public_api_url=public_api_url,
            public_preview_url=public_preview_url,
            environment=environment,
            container_runtime=text("CONTAINER_RUNTIME", defaults.container_runtime).strip(),
            isolation_runtimes=isolation_runtimes,
            default_isolation=default_isolation,
            gvisor_dns=gvisor_dns,
            egress_acknowledged=boolean("EGRESS_ACKNOWLEDGED", defaults.egress_acknowledged),
            egress_probe=egress_probe,
            egress_probe_image=egress_probe_image,
            enforce_disk_quota=boolean("ENFORCE_DISK_QUOTA", defaults.enforce_disk_quota),
            default_block_network=boolean("DEFAULT_BLOCK_NETWORK", defaults.default_block_network),
            enforce_block_network=boolean("ENFORCE_BLOCK_NETWORK", defaults.enforce_block_network),
            default_org_max_sandboxes=optional_limit("DEFAULT_ORG_MAX_SANDBOXES", int),
            default_org_max_vcpus=optional_limit("DEFAULT_ORG_MAX_VCPUS", float),
            default_org_max_memory_mib=optional_limit("DEFAULT_ORG_MAX_MEMORY_MIB", int),
            default_org_max_disk_gib=optional_limit("DEFAULT_ORG_MAX_DISK_GIB", int),
            allow_unbounded_host=boolean("ALLOW_UNBOUNDED_HOST", defaults.allow_unbounded_host),
            egress_allowlist_max_entries=integer(
                "EGRESS_ALLOWLIST_MAX_ENTRIES", defaults.egress_allowlist_max_entries
            ),
            egress_proxy_address=text(
                "EGRESS_PROXY_ADDRESS", defaults.egress_proxy_address
            ).strip(),
            egress_secret=egress_secret,
            egress_denied_cidrs=egress_limits.denied_cidrs,
            egress_allowed_ports=egress_limits.allowed_ports,
            egress_max_connections=egress_limits.max_connections,
            egress_idle_timeout_s=egress_limits.idle_timeout_s,
            egress_token_ttl_s=egress_limits.token_ttl_s,
            audit_chain_key=audit_chain_key,
            audit_signing_key=audit_signing_key,
            audit_chain_accept_unkeyed=audit_chain_accept_unkeyed_from(source),
            audit_retention_days=integer("AUDIT_RETENTION_DAYS", defaults.audit_retention_days),
            audit_retention_interval_s=integer(
                "AUDIT_RETENTION_INTERVAL_S", defaults.audit_retention_interval_s
            ),
            seccomp_profile_path=text(
                "SECCOMP_PROFILE_PATH", defaults.seccomp_profile_path
            ).strip(),
            cgroup_parent=cgroup_parent,
            userns_host_tiers=userns_host_tiers,
            require_userns_remap=boolean("REQUIRE_USERNS_REMAP", defaults.require_userns_remap),
            require_build_runtime=boolean("REQUIRE_BUILD_RUNTIME", DEFAULT_REQUIRE_BUILD_RUNTIME),
            allow_root_shared_kernel=boolean(
                "ALLOW_ROOT_SHARED_KERNEL", DEFAULT_ALLOW_ROOT_SHARED_KERNEL
            ),
            min_runc_version=min_runc_version,
            build_network=build_network,
            allowed_registries=allowed_registries,
            session_secret=session_secret,
            session_ttl_s=session_ttl_s,
            oidc_issuer=oidc_issuer,
            oidc_audience=text("OIDC_AUDIENCE", defaults.oidc_audience).strip(),
            oidc_jwks_url=oidc_jwks_url,
            oidc_org_id=text("OIDC_ORG_ID", defaults.oidc_org_id).strip(),
            oidc_jwks_cache_s=oidc_jwks_cache_s,
            node_id=text("NODE_ID", defaults.node_id).strip(),
            node_max_sandboxes=integer("NODE_MAX_SANDBOXES", defaults.node_max_sandboxes),
            node_heartbeat_enabled=boolean(
                "NODE_HEARTBEAT_ENABLED", defaults.node_heartbeat_enabled
            ),
            node_heartbeat_interval_s=integer(
                "NODE_HEARTBEAT_INTERVAL_S", defaults.node_heartbeat_interval_s
            ),
            node_internal_url=node_internal_url,
            routing_secret=routing_secret,
            routing_timeout_s=positive_real("ROUTING_TIMEOUT_S", defaults.routing_timeout_s),
            scim_enabled=boolean("SCIM_ENABLED", defaults.scim_enabled),
            scim_default_role=scim_default_role,
            forwarded_allow_ips=text("FORWARDED_ALLOW_IPS", defaults.forwarded_allow_ips),
            build_sha=text("BUILD_SHA", defaults.build_sha).strip(),
            status_notice_file=text("STATUS_NOTICE_FILE", defaults.status_notice_file).strip(),
            fault_injection=parse_fault_injection(text("FAULT_INJECTION", "")),
            build_sha_file=text("BUILD_SHA_FILE", defaults.build_sha_file).strip(),
        )
        check_tier_families(settings.isolation_tiers())
        return settings


def audit_chain_key_from(source: Mapping[str, str]) -> str:
    """The audit chain HMAC key in ``source`` ("" = unset); at least 32 bytes when set."""
    key = source.get(AUDIT_CHAIN_KEY_ENV, "").strip()
    if key and len(key.encode()) < MIN_AUDIT_CHAIN_KEY_BYTES:
        raise ValueError(
            f"{AUDIT_CHAIN_KEY_ENV} must be at least {MIN_AUDIT_CHAIN_KEY_BYTES} bytes when set"
        )
    return key


def audit_signing_key_from(source: Mapping[str, str]) -> str:
    """The audit head signing key in ``source`` ("" = unset); an Ed25519 key when set.

    Only strips the value: ``Settings.__post_init__`` validates it (``audit_signer_of``).
    """
    return source.get(AUDIT_SIGNING_KEY_ENV, "").strip()


def audit_signer_of(text: str) -> HeadSigner | None:
    """The head signer of a signing key value (``None`` when blank).

    Raises ``ValueError`` naming the variable (never the value) when it is malformed.
    """
    try:
        return signer_from_text(text)
    except ValueError as exc:
        raise ValueError(f"{AUDIT_SIGNING_KEY_ENV} {exc}") from None


def audit_chain_accept_unkeyed_from(source: Mapping[str, str]) -> bool:
    """Whether verify accepts unkeyed rows next to keyed ones (default true)."""
    raw = source.get(AUDIT_CHAIN_ACCEPT_UNKEYED_ENV)
    if raw is None:
        return True
    lowered = raw.strip().lower()
    if lowered in TRUE_WORDS:
        return True
    if lowered in FALSE_WORDS:
        return False
    raise ValueError(f"{AUDIT_CHAIN_ACCEPT_UNKEYED_ENV} must be a boolean, got {raw!r}")


def check_tier_families(tiers: Mapping[str, str]) -> None:
    """Refuse a gvisor tier off a runsc runtime and a microvm tier off a kata runtime."""
    for tier, runtime in tiers.items():
        name = runtime.strip().lower()
        if tier == GVISOR and not name.startswith(GVISOR_RUNTIME_PREFIX):
            wanted = f"a runtime whose name starts with {GVISOR_RUNTIME_PREFIX!r}"
        elif tier == MICROVM and KATA_RUNTIME_MARKER not in name:
            wanted = f"a runtime whose name contains {KATA_RUNTIME_MARKER!r}"
        else:
            continue
        raise ValueError(
            f"isolation tier {tier!r} needs {wanted}, got runtime {runtime!r}"
            f" ('' = the daemon default); fix {ENV_PREFIX}ISOLATION_RUNTIMES"
            f" (or {ENV_PREFIX}CONTAINER_RUNTIME when no tier map is set)"
        )


def _isolation_settings(raw_runtimes: str, raw_default: str) -> tuple[TierRuntimes, str]:
    """Parse the tier map and the default tier; reject a bad pair or an unavailable default."""
    try:
        pairs = parse_tier_runtimes(raw_runtimes)
    except ValueError as exc:
        raise ValueError(f"{ENV_PREFIX}ISOLATION_RUNTIMES: {exc}") from None
    default = raw_default.strip()
    try:
        check_default_tier(pairs, default)
    except ValueError as exc:
        raise ValueError(f"{ENV_PREFIX}DEFAULT_ISOLATION: {exc}") from None
    return pairs, default


def _check_public_preview_url(raw: str, preview_domain: str) -> str:
    """Return the normalized public preview origin, or raise ``ValueError`` when it is not one.

    An origin is ``http(s)://<preview domain>[:<port>]``: the host must be exactly the preview
    domain and nothing may follow the authority. One trailing slash is dropped; scheme and host
    are lower-cased. Empty means "not set".
    """
    name = f"{ENV_PREFIX}PUBLIC_PREVIEW_URL"
    value = raw.strip()
    if not value:
        return ""
    value = value.removesuffix("/")
    scheme, sep, rest = value.partition("://")
    scheme = scheme.lower()
    if not sep or scheme not in PREVIEW_URL_SCHEMES:
        raise ValueError(f"{name} must start with http:// or https://, got {raw!r}")
    if any(char in rest for char in "/?#"):
        raise ValueError(f"{name} must be an origin without a path, query or fragment, got {raw!r}")
    host, has_port, port = rest.partition(":")
    if host.lower() != preview_domain:
        raise ValueError(f"{name} host must be the preview domain {preview_domain!r}, got {raw!r}")
    if not has_port:
        return f"{scheme}://{preview_domain}"
    if not (port.isascii() and port.isdigit() and 1 <= int(port) <= MAX_PORT):
        raise ValueError(f"{name} port must be a number from 1 to {MAX_PORT}, got {raw!r}")
    return f"{scheme}://{preview_domain}:{int(port)}"


def _check_session_settings(
    secret: str, ttl_s: int, issuer: str, jwks_url: str, jwks_cache_s: int
) -> None:
    """Reject weak session and sign-on settings at load time."""
    if secret and len(secret) < MIN_SESSION_SECRET_CHARS:
        raise ValueError(
            f"{ENV_PREFIX}SESSION_SECRET must be at least {MIN_SESSION_SECRET_CHARS} characters"
        )
    if not issuer:
        return
    parts = urlsplit(jwks_url)
    local_http = parts.scheme == "http" and parts.hostname in LOCAL_HOSTS
    if parts.scheme != "https" and not local_http:
        raise ValueError(
            f"{ENV_PREFIX}OIDC_JWKS_URL must start with https (http only for localhost),"
            f" got {jwks_url!r}"
        )
    if jwks_cache_s < 1:
        raise ValueError(f"{ENV_PREFIX}OIDC_JWKS_CACHE_S must be at least 1, got {jwks_cache_s}")
    if not MIN_SESSION_TTL_S <= ttl_s <= MAX_SESSION_TTL_S:
        raise ValueError(
            f"{ENV_PREFIX}SESSION_TTL_S must be between {MIN_SESSION_TTL_S} and"
            f" {MAX_SESSION_TTL_S} seconds, got {ttl_s}"
        )


def _check_routing_settings(internal_url: str, secret: str) -> None:
    """Reject a weak routing secret, a malformed node address and an address with no secret.

    The address is never echoed back: a mistyped value can carry userinfo credentials.
    """
    if secret and len(secret) < MIN_SESSION_SECRET_CHARS:
        raise ValueError(
            f"{ENV_PREFIX}ROUTING_SECRET must be at least {MIN_SESSION_SECRET_CHARS} characters"
        )
    if not internal_url:
        return
    match = NODE_INTERNAL_URL_PATTERN.fullmatch(internal_url)
    if match is None or not 1 <= int(match.group("port")) <= MAX_PORT:
        raise ValueError(
            f"{ENV_PREFIX}NODE_INTERNAL_URL must be http://host:port with no path, query or"
            " userinfo"
        )
    if not secret:
        raise ValueError(f"{ENV_PREFIX}NODE_INTERNAL_URL needs {ENV_PREFIX}ROUTING_SECRET")


@dataclass(frozen=True, slots=True)
class EgressLimits:
    """The egress proxy limits, as read from ``SANDFORT_EGRESS_*`` variables."""

    denied_cidrs: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    max_connections: int
    idle_timeout_s: int
    token_ttl_s: int


def egress_limits_from(source: Mapping[str, str]) -> EgressLimits:
    """Read and validate the egress proxy limits; unset variables take the safe defaults."""

    def number(name: str, default: int, low: int, high: int) -> int:
        raw = source.get(ENV_PREFIX + name)
        if raw is None:
            return default
        text = raw.strip()
        if not (text.isascii() and text.isdigit()) or not low <= int(text) <= high:
            raise ValueError(f"{ENV_PREFIX}{name} must be an integer {low}..{high}, got {raw!r}")
        return int(text)

    def listed[T](name: str, default: T, parse: Callable[[str], T]) -> T:
        raw = source.get(ENV_PREFIX + name)
        if raw is None:
            return default
        try:
            return parse(raw)
        except ValueError as exc:
            raise ValueError(f"{ENV_PREFIX}{name} is invalid: {exc}") from exc

    return EgressLimits(
        denied_cidrs=listed("EGRESS_DENIED_CIDRS", DEFAULT_EGRESS_DENIED_CIDRS, parse_cidrs),
        allowed_ports=listed("EGRESS_ALLOWED_PORTS", DEFAULT_EGRESS_ALLOWED_PORTS, parse_ports),
        max_connections=number(
            "EGRESS_MAX_CONNECTIONS_PER_SANDBOX", DEFAULT_EGRESS_MAX_CONNECTIONS, 1, 100_000
        ),
        idle_timeout_s=number("EGRESS_IDLE_TIMEOUT_S", DEFAULT_EGRESS_IDLE_TIMEOUT_S, 1, 86_400),
        token_ttl_s=number(
            "EGRESS_TOKEN_TTL_S",
            DEFAULT_EGRESS_TOKEN_TTL_S,
            MIN_EGRESS_TOKEN_TTL_S,
            MAX_EGRESS_TOKEN_TTL_S,
        ),
    )
