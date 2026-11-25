"""Request/response models for ``/v1/sandboxes`` (architecture.md section 3)."""

from collections.abc import Mapping
from typing import Annotated, Self, TypeVar

from pydantic import (
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictBool,
    StringConstraints,
    WithJsonSchema,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

from sandfort.api.schemas.common import RequestModel
from sandfort.api.schemas.mount_paths import check_mount_path
from sandfort.api.schemas.text_checks import (
    MAX_LABEL_KEY_LENGTH,
    MAX_LABEL_VALUE_LENGTH,
    MAX_LABELS,
    check_egress_hosts,
    check_env,
    check_label_content,
    check_reserved_labels,
    plain_error,
)
from sandfort.auth.label_scope import current_label_scope
from sandfort.domain.isolation import DEFAULT_TIER, IsolationTier, tier_of
from sandfort.domain.resources import (
    DEFAULT_CPU_MILLICORES,
    DEFAULT_DISK_GIB,
    DEFAULT_MEMORY_MIB,
    MIN_CPU_MILLICORES,
    MIN_DISK_GIB,
    MIN_MEMORY_MIB,
    ResourceSpec,
)
from sandfort.domain.sandbox import (
    NetworkPolicy,
    Sandbox,
    SandboxState,
    encode_egress_allowlist,
    visible_stop_cause,
    visible_stopped_at,
)
from sandfort.drivers.base import IMAGE_MOUNTS_LABEL, decode_image_mounts
from sandfort.egress.env import NO_PROXY_VARIABLES, PROXY_VARIABLES
from sandfort.services.volumes import (
    MAX_MOUNT_PATH_LENGTH,
    MAX_MOUNTS,
    MountRequest,
    decode_mounts,
    encode_mount_requests,
    user_labels,
)

NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]*$"
MAX_NAME_LENGTH = 63
MIN_AUTO_MINUTES = -1  # -1 disables the timer
MAX_AUTO_MINUTES = 525_600  # one year of minutes; far below the 32-bit column limit
# Schema-level sanity ceilings, well above the configurable per-sandbox maxima (defaults
# 4000 millicores, 8192 MiB, 20 GiB: `SANDFORT_MAX_SANDBOX_*`). The service still enforces
# the deployment's real maximum; these only keep a value out of the database integer range.
MAX_CPU_MILLICORES = 1_000_000  # 1000 cores
MAX_MEMORY_MIB = 16_777_216  # 16 TiB
MAX_DISK_GIB = 1_048_576  # 1 PiB
MAX_VOLUME_ID_LENGTH = 64
ENV_VALUE_MASK = "***"  # what a response shows in place of every environment value
BOOL_NOT_NUMBER_TYPE = "number_not_bool"  # validation error type for a JSON boolean
BOOL_NOT_NUMBER_MESSAGE = "Input should be a number, not a boolean"


def _reject_bool(value: object) -> object:
    """Refuse a JSON boolean before lax number coercion reads ``true`` as 1 (round 53)."""
    if isinstance(value, bool):
        raise PydanticCustomError(BOOL_NOT_NUMBER_TYPE, BOOL_NOT_NUMBER_MESSAGE)
    return value


_Number = TypeVar("_Number")
# A request number (``NoBool[int]``): every numeric form accepted before, except ``true`` and
# ``false``. It wraps the whole type, so ``ge``/``le`` still render as ``minimum``/``maximum``.
NoBool = Annotated[_Number, BeforeValidator(_reject_bool)]

# Request labels (round 58): at most ``MAX_LABELS`` entries, bounded keys and values. The
# bounds sit on the types, so the spec publishes ``maxProperties``, ``propertyNames.maxLength``
# and ``additionalProperties.maxLength``; a breach is a 422 naming the limit.
LabelKey = Annotated[str, StringConstraints(max_length=MAX_LABEL_KEY_LENGTH)]
LabelValue = Annotated[str, StringConstraints(max_length=MAX_LABEL_VALUE_LENGTH)]
RequestLabels = Annotated[dict[LabelKey, LabelValue], Field(max_length=MAX_LABELS)]
UPDATE_LABELS_DESCRIPTION = (
    f"Replaces every user label (at most {MAX_LABELS}). null removes all labels; omit the "
    "field to keep them."
)


class VolumeMountSpec(RequestModel):
    """Mount the org's volume ``volume_id`` at the absolute ``mount_path``."""

    volume_id: str = Field(min_length=1, max_length=MAX_VOLUME_ID_LENGTH)
    mount_path: str = Field(min_length=1, max_length=MAX_MOUNT_PATH_LENGTH)
    read_only: StrictBool = Field(
        default=False,
        description=(
            "Mount the volume read-only. A read-only mount needs `volumes:read`, a read-write "
            "mount needs `volumes:write`."
        ),
    )

    @field_validator("mount_path")
    @classmethod
    def valid_mount_path(cls, value: str) -> str:
        """Visible text, absolute and normalised, and not a system directory or guarded tree."""
        return check_mount_path(value)


class VolumeMountView(BaseModel):
    """A mount as a sandbox response reports it."""

    volume_id: str
    mount_path: str
    read_only: bool = Field(default=False, description="True when the volume is mounted read-only.")


class ResourceSpecRequest(ResourceSpec):
    """``ResourceSpec`` as a request accepts it: the same lower bounds plus an upper bound."""

    # Like every request model: an unknown field is a 422 naming it, never silently dropped.
    model_config = ConfigDict(frozen=True, extra="forbid")

    cpu_millicores: NoBool[int] = Field(
        default=DEFAULT_CPU_MILLICORES, ge=MIN_CPU_MILLICORES, le=MAX_CPU_MILLICORES
    )
    memory_mib: NoBool[int] = Field(
        default=DEFAULT_MEMORY_MIB, ge=MIN_MEMORY_MIB, le=MAX_MEMORY_MIB
    )
    disk_gib: NoBool[int] = Field(default=DEFAULT_DISK_GIB, ge=MIN_DISK_GIB, le=MAX_DISK_GIB)


class CreateSandboxRequest(BaseModel):
    # An unknown field is a 422 naming it, not a silently ignored request.
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(
        default=None, min_length=1, max_length=MAX_NAME_LENGTH, pattern=NAME_PATTERN
    )
    snapshot: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description=(
            "Snapshot id, snapshot name, or image reference. A snapshot name of the "
            "organization wins over an image of the same name."
        ),
    )
    resources: ResourceSpecRequest = Field(default_factory=ResourceSpecRequest)
    inherit_resources: StrictBool = Field(
        default=False,
        description=(
            "When true and `snapshot` is a snapshot (id or name) that recorded the resources "
            "of its source sandbox, every field of `resources` you leave out is taken from "
            "that record instead of the default; a field you set always wins. The merged "
            "values must fit the per-sandbox maximum (422 otherwise, never clamped). Has no "
            "effect for an image reference, for a snapshot without recorded resources, or "
            "when no snapshot is given."
        ),
    )
    env: dict[str, str] = Field(default_factory=dict)
    labels: RequestLabels = Field(default_factory=dict)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    auto_stop_minutes: NoBool[int] = Field(default=15, ge=MIN_AUTO_MINUTES, le=MAX_AUTO_MINUTES)
    auto_delete_minutes: NoBool[int] = Field(default=-1, ge=MIN_AUTO_MINUTES, le=MAX_AUTO_MINUTES)
    public: bool = False
    volumes: list[VolumeMountSpec] = Field(default_factory=list, max_length=MAX_MOUNTS)
    # The service validates the entries (domain ``check_egress_allowlist``).
    egress_allowlist: list[str] | None = Field(
        default=None,
        description=(
            "Host names, leading-dot domains or CIDR ranges the sandbox may reach through the "
            "egress proxy. An empty list means no network at all (block-all). Omitting the "
            "field keeps the operator default."
        ),
    )

    isolation: IsolationTier | None = Field(
        default=None,
        description=(
            "Isolation tier to run the sandbox on (`GET /v1/isolation` lists the tiers this "
            "deployment offers); absent means the deployment default."
        ),
    )

    @field_validator("network", mode="before")
    @classmethod
    def unset_block_all(cls, value: object) -> object:
        """Read a null ``network`` or ``network.block_all`` as "not set" (deployment default).

        An explicit ``true`` or ``false`` is always kept.
        """
        if value is None:
            return {}
        if isinstance(value, dict) and value.get("block_all", False) is None:
            return {key: item for key, item in value.items() if key != "block_all"}
        return value

    @field_validator("env")
    @classmethod
    def valid_env(cls, value: dict[str, str]) -> dict[str, str]:
        """Env keys and values without control, invisible or private-use characters."""
        check_env(value)
        return value

    @field_validator("egress_allowlist")
    @classmethod
    def valid_egress_hosts(cls, value: list[str] | None) -> list[str] | None:
        """Allowlist hosts without whitespace, controls or invisible characters."""
        return check_egress_hosts(value)

    @field_validator("labels")
    @classmethod
    def visible_label_keys(cls, value: dict[str, str]) -> dict[str, str]:
        """Visible label names, none of them reserved (the one ``RESERVED_LABEL`` refusal)."""
        check_label_content(value)
        check_reserved_labels(value)
        return value

    @model_validator(mode="after")
    def carry_volumes(self) -> Self:
        """Carry ``volumes`` and the allowlist in ``labels``, the one field the create route
        copies onto the service command; the service takes the carriers out again."""
        requests = [
            MountRequest(item.volume_id, item.mount_path, item.read_only) for item in self.volumes
        ]
        self.labels = {
            **self.labels,
            **encode_mount_requests(requests),
            **encode_egress_allowlist(self.egress_allowlist),
        }
        return self


class UpdateSandboxRequest(RequestModel):
    labels: RequestLabels | None = Field(default=None, description=UPDATE_LABELS_DESCRIPTION)
    auto_stop_minutes: NoBool[int | None] = Field(
        default=None, ge=MIN_AUTO_MINUTES, le=MAX_AUTO_MINUTES
    )
    auto_delete_minutes: NoBool[int | None] = Field(
        default=None, ge=MIN_AUTO_MINUTES, le=MAX_AUTO_MINUTES
    )
    public: bool | None = None
    egress_allowlist: list[str] | None = Field(
        default=None,
        description=(
            "Replaces the egress allowlist of a sandbox created with a non-empty one, and "
            "raises its egress_policy_generation by 1. Omitting the field keeps egress as "
            "it is, a list replaces the stored one, `[]` refuses every connection, and null "
            "is refused with 422: an allowlist cannot be removed. Only the database changes, "
            "so the proxy applies the new list within its cache window."
        ),
    )

    @field_validator("egress_allowlist")
    @classmethod
    def valid_egress_hosts(cls, value: list[str] | None) -> list[str] | None:
        """Allowlist hosts without whitespace, controls or invisible characters."""
        return check_egress_hosts(value)

    @field_validator("labels", mode="before")
    @classmethod
    def null_clears_labels(cls, value: object) -> object:
        """An explicit ``"labels": null`` is an empty label set: every user label is removed.

        Runs only for a sent field, so an omitted ``labels`` stays ``None`` (labels kept).
        """
        return {} if value is None else value

    @field_validator("labels")
    @classmethod
    def visible_label_keys(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        """Visible label names, none of them reserved (the one ``RESERVED_LABEL`` refusal)."""
        check_label_content(value)
        check_reserved_labels(value)
        return value


class ResizeSandboxRequest(RequestModel):
    """Resource fields to change on a stopped sandbox; omitted fields keep their value."""

    cpu_millicores: NoBool[int | None] = Field(
        default=None, ge=MIN_CPU_MILLICORES, le=MAX_CPU_MILLICORES
    )
    memory_mib: NoBool[int | None] = Field(default=None, ge=MIN_MEMORY_MIB, le=MAX_MEMORY_MIB)
    disk_gib: NoBool[int | None] = Field(default=None, ge=MIN_DISK_GIB, le=MAX_DISK_GIB)

    @model_validator(mode="after")
    def require_a_change(self) -> Self:
        if self.cpu_millicores is None and self.memory_mib is None and self.disk_gib is None:
            raise plain_error("at least one of cpu_millicores, memory_mib, disk_gib is required")
        return self


class SandboxResponse(BaseModel):
    id: str
    name: str
    state: SandboxState
    resources: ResourceSpec
    env: dict[str, str]
    labels: dict[str, str]
    network: NetworkPolicy
    public: bool
    auto_stop_minutes: int
    auto_delete_minutes: int
    volumes: list[VolumeMountView] = Field(default_factory=list)
    image_mounts: list[str] = Field(
        default_factory=list,
        description=(
            "Paths the image declares as volumes (a snapshot of a sandbox that had a volume "
            "mounted declares its mount path too) that none of `volumes` covers. Each is "
            "backed by a per-sandbox scratch volume, mounted read-write, that lives outside "
            "`disk_gib` and is deleted with the sandbox. The volume soft limit does not cover "
            "them. Sorted; empty when the image declares none."
        ),
    )
    isolation: str  # the sandbox's isolation tier
    error_reason: str | None = None
    error_code: str | None = Field(
        default=None,
        description=(
            "Machine-readable code set with error_reason, null when there is none: "
            "image_not_found, registry_unreachable (retryable: the registry did not answer, "
            "throttled the pull or failed on its side), registry_tls_error (not retryable: "
            "the registry's TLS certificate failed validation), "
            "image_access_denied (not retryable: the registry refused the pull), "
            "invalid_image_reference (not retryable: the reference cannot be parsed), "
            "start_failed, timeout, reset_failed, container_missing, "
            "container_exited, node_lost, egress_unavailable (the node that ran the create job "
            "has no egress proxy settings, so no container was created) or internal. "
            "Branch on this, not on the reason text."
        ),
    )
    job_id: str | None = Field(
        default=None,
        description=(
            "Reserved. Currently always null for every caller, org-wide and label-scoped "
            "keys alike; do not rely on it."
        ),
    )
    # Documented as a string that may be null (an OpenAPI 3.1 type union), so the published
    # schema keeps its plain string type instead of an ``anyOf``.
    node_id: Annotated[str | None, WithJsonSchema({"type": ["string", "null"]})] = Field(
        default=None,
        description=(
            "Id of the node that runs the sandbox. Null when the caller is a label-scoped "
            "key: node placement is internal. Org-wide keys see it."
        ),
    )
    egress_allowlist: list[str] | None = Field(
        default=None,
        description=(
            "Host names, leading-dot domains or CIDR ranges the sandbox may reach through the "
            "egress proxy; null means the network policy default."
        ),
    )
    egress_policy_generation: int | None = Field(
        default=None,
        description=(
            "Version of the egress allowlist: 1 at create, plus 1 per PATCH that changes it. "
            "Null when egress_allowlist is null; 0 for a sandbox that predates egress v2 "
            "(reset it to upgrade its egress credential)."
        ),
    )
    snapshot: str | None = Field(
        default=None,
        description=(
            "The snapshot id or image reference the sandbox was created from; null for "
            "sandboxes created before this field existed or with no snapshot. Also null "
            "when the caller is a label-scoped key: the source may be a snapshot outside "
            "its scope, and such a caller learns nothing about those. Org-wide keys see it."
        ),
    )
    created_at: AwareDatetime | None = Field(
        default=None,
        description=(
            "When the sandbox was created (UTC, ISO 8601 with offset). Never changes. "
            "The server sets it on every sandbox object."
        ),
    )
    updated_at: AwareDatetime | None = Field(
        default=None,
        description=(
            "When the sandbox record last changed (UTC, ISO 8601 with offset); "
            "a state change moves it forward. The server sets it on every sandbox object."
        ),
    )
    stop_cause: str | None = Field(
        default=None,
        description=(
            "Why the sandbox stopped; null unless the state is stopping or stopped. "
            "requested: stopped on purpose by a stop request; auto_stop: stopped on purpose "
            "by the idle timer (auto_stop_minutes); container_exited: the process tree "
            "exited, start it again; oom_killed: the container was killed for exceeding its "
            "memory limit (container isolation tier only; the other tiers report "
            "container_exited); unknown: stopped before this field existed."
        ),
    )
    stopped_at: AwareDatetime | None = Field(
        default=None,
        description="When the sandbox stopped (UTC, ISO 8601 with offset); null unless the "
        "state is stopped.",
    )


def public_env(env: Mapping[str, str]) -> dict[str, str]:
    """``env`` without the proxy variables the platform injects.

    The proxy urls carry the minted egress token as userinfo, so they must not reach a
    response body (and from there CI logs). The ``no_proxy`` names are platform-injected too
    and the user never set them. The user's own entries pass unchanged.
    """
    hidden = (*PROXY_VARIABLES, *NO_PROXY_VARIABLES)
    return {name: value for name, value in env.items() if name not in hidden}


class IsolationResponse(BaseModel):
    """The isolation tiers this deployment offers and the one a create gets by default."""

    default: str
    available: list[str]


def sandbox_response(sandbox: Sandbox, default_isolation: str = DEFAULT_TIER) -> SandboxResponse:
    """The API view of ``sandbox``; ``default_isolation`` is reported when no tier is recorded.

    ``snapshot`` is withheld (null) from a label-scoped caller, as ``created_by`` is on an API
    key: the sandbox may come from a snapshot that caller is not allowed to know about. The
    internal ``node_id`` is withheld from such a caller as well. ``job_id`` is reserved and
    always null for every caller.
    """
    allowlist = sandbox.egress_allowlist
    label_scoped = current_label_scope() is not None
    mounts = [
        VolumeMountView(
            volume_id=mount.volume_id, mount_path=mount.mount_path, read_only=mount.read_only
        )
        for mount in decode_mounts(sandbox.labels)
    ]
    return SandboxResponse(
        id=sandbox.id,
        name=sandbox.name,
        state=sandbox.state,
        resources=sandbox.resources,
        env=dict.fromkeys(public_env(sandbox.env), ENV_VALUE_MASK),
        labels=user_labels(sandbox.labels),
        network=sandbox.network,
        public=sandbox.public,
        auto_stop_minutes=sandbox.auto_stop_minutes,
        auto_delete_minutes=sandbox.auto_delete_minutes,
        volumes=mounts,
        image_mounts=decode_image_mounts(sandbox.labels.get(IMAGE_MOUNTS_LABEL)),
        isolation=tier_of(sandbox.labels, default_isolation),
        error_reason=sandbox.error_reason,
        error_code=sandbox.error_code,
        job_id=None,
        node_id=None if label_scoped else sandbox.node_id,
        egress_allowlist=None if allowlist is None else list(allowlist),
        egress_policy_generation=None if allowlist is None else sandbox.egress_policy_generation,
        snapshot=None if label_scoped else sandbox.snapshot,
        created_at=sandbox.created_at,
        updated_at=sandbox.updated_at,
        stop_cause=visible_stop_cause(sandbox),
        stopped_at=visible_stopped_at(sandbox),
    )
