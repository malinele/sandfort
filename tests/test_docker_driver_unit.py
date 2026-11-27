"""Docker driver unit tests: no daemon needed (pure mapping + a fake docker-py client)."""

import io
import logging
import tarfile
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from sandfort.config import Settings
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import NetworkPolicy
from sandfort.drivers.base import (
    ExecRequest,
    ExecResult,
    InstanceState,
    PtySessionHandle,
    SandboxSpec,
    VolumeBind,
)
from sandfort.drivers.docker import client as docker_client
from sandfort.drivers.docker import containers as containers_module
from sandfort.drivers.docker import pty as docker_pty
from sandfort.drivers.docker.containers import (
    KEEPALIVE_ENTRYPOINT,
    RESOLV_CONF_PATH,
    build_create_kwargs,
    create_container,
    fail_fast_resolv_conf_text,
    has_own_network_stack,
    info_from_attrs,
    list_managed_containers,
    remove_container,
    resolv_conf_text,
    start_container,
    stop_container,
)
from sandfort.drivers.docker.disk_reserve import QUOTA_HEADROOM_BYTES
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.docker.hardening import (
    DEFAULT_GVISOR_NAMESERVERS,
    GVISOR_TMP_PATH,
    HardeningOptions,
    build_host_config,
    options_from_settings,
)
from sandfort.drivers.docker.images import pull_image, pull_image_digest
from sandfort.drivers.docker.labels import (
    LABEL_DISK_GIB,
    LABEL_MANAGED,
    LABEL_ORG_ID,
    LABEL_SANDBOX_ID,
    build_labels,
    container_name,
    managed_filters,
)
from sandfort.drivers.docker.networks import EGRESS_NETWORK_NAME
from sandfort.drivers.errors import (
    DriverConflict,
    DriverError,
    DriverNotFound,
    DriverRegistryUnreachable,
)
from sandfort.toolbox.pty import PtyExitCodeDriver
from sandfort.workers.metering import InstanceSizeDriver

errors = pytest.importorskip("docker.errors")

SETTINGS = Settings()
MIB = 1024 * 1024


def make_spec(**overrides: Any) -> SandboxSpec:
    fields: dict[str, Any] = {
        "sandbox_id": "sbx_1",
        "org_id": "org_1",
        "name": "sf-sbx_1",
        "image": "alpine:3.20",
        "resources": ResourceSpec(cpu_millicores=1000, memory_mib=512, disk_gib=2),
    }
    fields.update(overrides)
    return SandboxSpec(**fields)


# --- labels -------------------------------------------------------------------------


def test_container_name_is_deterministic() -> None:
    assert container_name("sbx_1") == "sf-sbx_1"


def test_build_labels_sets_identity_and_keeps_extras() -> None:
    labels = build_labels("sbx_1", "org_1", {"team": "infra"})
    assert labels == {
        LABEL_MANAGED: "true",
        LABEL_SANDBOX_ID: "sbx_1",
        LABEL_ORG_ID: "org_1",
        "team": "infra",
    }


def test_build_labels_identity_cannot_be_spoofed() -> None:
    spoof = {LABEL_MANAGED: "false", LABEL_ORG_ID: "org_evil", LABEL_SANDBOX_ID: "sbx_evil"}
    labels = build_labels("sbx_1", "org_1", spoof)
    assert labels[LABEL_MANAGED] == "true"
    assert labels[LABEL_ORG_ID] == "org_1"
    assert labels[LABEL_SANDBOX_ID] == "sbx_1"


def test_managed_filters_with_and_without_org() -> None:
    assert managed_filters() == {"label": ["sandfort.managed=true"]}
    assert managed_filters("org_1") == {"label": ["sandfort.managed=true", "sandfort.org_id=org_1"]}


# --- hardening ----------------------------------------------------------------------


def test_host_config_maps_resources_exactly() -> None:
    config = build_host_config(make_spec(), SETTINGS)
    assert config["nano_cpus"] == 1_000_000_000
    assert config["mem_limit"] == 512 * MIB == 536_870_912
    assert config["memswap_limit"] == config["mem_limit"]
    assert config["pids_limit"] == 512


def test_host_config_security_posture() -> None:
    config = build_host_config(make_spec(), SETTINGS)
    assert config["cap_drop"] == ["ALL"]
    assert "ALL" not in config["cap_add"]
    assert config["security_opt"] == ["no-new-privileges:true"]
    assert config["init"] is True
    assert config["privileged"] is False
    assert "user" not in config
    assert "storage_opt" not in config


def test_host_config_network_defaults_to_sf_net_and_none_when_blocked() -> None:
    assert build_host_config(make_spec(), SETTINGS)["network_mode"] == "sf-net"
    blocked = make_spec(network=NetworkPolicy(block_all=True))
    assert build_host_config(blocked, SETTINGS)["network_mode"] == "none"


@pytest.mark.parametrize(("memory_mib", "expected_shm"), [(128, 32 * MIB), (4096, 64 * MIB)])
def test_host_config_shm_is_quarter_of_memory_capped_at_64mib(
    memory_mib: int, expected_shm: int
) -> None:
    spec = make_spec(resources=ResourceSpec(memory_mib=memory_mib))
    assert build_host_config(spec, SETTINGS)["shm_size"] == expected_shm


def test_host_config_optional_knobs() -> None:
    options = HardeningOptions(
        user="1000:1000", cgroup_parent="sandfort.slice", runtime="runsc", enforce_disk_quota=True
    )
    config = build_host_config(make_spec(), SETTINGS, options)
    assert config["user"] == "1000:1000"
    assert config["cgroup_parent"] == "sandfort.slice"
    assert config["runtime"] == "runsc"
    assert config["storage_opt"] == {"size": str(2 * 1024**3 + QUOTA_HEADROOM_BYTES)}


def test_host_config_volume_binds() -> None:
    spec = make_spec(
        volumes=(
            VolumeBind("sf-vol-a", "/data"),
            VolumeBind("sf-vol-b", "/ro", read_only=True),
        )
    )
    assert build_host_config(spec, SETTINGS)["volumes"] == {
        "sf-vol-a": {"bind": "/data", "mode": "rw"},
        "sf-vol-b": {"bind": "/ro", "mode": "ro"},
    }


GVISOR = HardeningOptions(runtime="runsc", gvisor=True)
RUNC_VOLUMES = (VolumeBind("sf-vol-a", "/data"), VolumeBind("sf-vol-b", "/ro", read_only=True))
RUNC_KEYS = {
    "nano_cpus",
    "mem_limit",
    "memswap_limit",
    "pids_limit",
    "shm_size",
    "cap_drop",
    "cap_add",
    "security_opt",
    "init",
    "privileged",
    "ulimits",
    "log_config",
    "network_mode",
}


def test_options_enforce_the_disk_quota_in_dev_only_when_the_setting_is_true() -> None:
    enforcing = options_from_settings(Settings(enforce_disk_quota=True))
    plain = options_from_settings(Settings(enforce_disk_quota=False))

    assert enforcing.enforce_disk_quota is True
    assert plain.enforce_disk_quota is False
    assert build_host_config(make_spec(), SETTINGS, enforcing)["storage_opt"] == {
        "size": str(2 * 1024**3 + QUOTA_HEADROOM_BYTES)
    }
    assert "storage_opt" not in build_host_config(make_spec(), SETTINGS, plain)


def test_prod_enforces_the_disk_quota_whatever_the_setting_says() -> None:
    prod = Settings(environment="prod", enforce_disk_quota=False)

    assert options_from_settings(prod).enforce_disk_quota is True


def test_options_from_settings_mark_gvisor_only_for_runsc() -> None:
    assert options_from_settings(Settings(container_runtime="runsc")) == GVISOR
    assert options_from_settings(Settings()) == HardeningOptions()
    assert options_from_settings(Settings(container_runtime="runc")).gvisor is False


def test_gvisor_options_add_no_tmp_mount() -> None:
    config = build_host_config(make_spec(), SETTINGS, GVISOR)

    assert GVISOR_TMP_PATH == "/tmp"
    assert config["runtime"] == "runsc"
    assert "mounts" not in config
    assert "volumes" not in config


def test_gvisor_options_keep_user_volumes_mapped_and_add_no_mounts() -> None:
    config = build_host_config(make_spec(volumes=RUNC_VOLUMES), SETTINGS, GVISOR)

    assert config["volumes"] == {
        "sf-vol-a": {"bind": "/data", "mode": "rw"},
        "sf-vol-b": {"bind": "/ro", "mode": "ro"},
    }
    assert "mounts" not in config


def test_gvisor_options_map_a_user_volume_at_tmp_like_any_other() -> None:
    spec = make_spec(volumes=(VolumeBind("sf-vol-t", "/tmp/"),))

    config = build_host_config(spec, SETTINGS, GVISOR)

    assert config["volumes"] == {"sf-vol-t": {"bind": "/tmp/", "mode": "rw"}}
    assert "mounts" not in config


def test_gvisor_create_kwargs_differ_from_runc_by_runtime_nproc_and_pids() -> None:
    gvisor = build_host_config(make_spec(volumes=RUNC_VOLUMES), SETTINGS, GVISOR)
    runc = build_host_config(make_spec(volumes=RUNC_VOLUMES), SETTINGS)

    varying = ("runtime", "ulimits", "pids_limit")
    assert {k: v for k, v in gvisor.items() if k not in varying} == {
        k: v for k, v in runc.items() if k not in varying
    }
    assert gvisor["ulimits"] == runc["ulimits"] + [{"Name": "nproc", "Soft": 512, "Hard": 512}]
    assert (runc["pids_limit"], gvisor["pids_limit"]) == (512, 1536)


@pytest.mark.parametrize("volumes", [(), RUNC_VOLUMES])
def test_runc_options_leave_the_create_kwargs_unchanged(volumes: tuple[VolumeBind, ...]) -> None:
    spec = make_spec(volumes=volumes)
    runc = build_host_config(spec, SETTINGS, HardeningOptions(runtime="runc"))
    default = build_host_config(spec, SETTINGS)

    assert "mounts" not in runc
    assert "mounts" not in default
    assert {key: value for key, value in runc.items() if key != "runtime"} == default
    assert set(default) == RUNC_KEYS | ({"volumes"} if volumes else set())


@pytest.mark.parametrize("volumes", [(), RUNC_VOLUMES])
@pytest.mark.parametrize(
    ("options", "extra_keys"),
    [
        (HardeningOptions(), set()),
        (HardeningOptions(cgroup_parent="sandfort.slice"), {"cgroup_parent"}),
        (HardeningOptions(default_tier="microvm"), {"userns_mode"}),
        (
            HardeningOptions(cgroup_parent="sandfort.slice", default_tier="microvm"),
            {"cgroup_parent", "userns_mode"},
        ),
    ],
)
def test_create_kwargs_key_set_is_closed_with_and_without_the_hardening_keys(
    volumes: tuple[VolumeBind, ...], options: HardeningOptions, extra_keys: set[str]
) -> None:
    config = build_host_config(make_spec(volumes=volumes), SETTINGS, options)

    assert set(config) == RUNC_KEYS | extra_keys | ({"volumes"} if volumes else set())


TIER_MAP = (("container", ""), ("gvisor", "runsc"), ("microvm", "kata"))
TIERED = Settings(isolation_runtimes=TIER_MAP)
GVISOR_DEFAULT = Settings(isolation_runtimes=TIER_MAP, default_isolation="gvisor")


def test_options_from_settings_carry_the_tier_map_and_the_default_tier_runtime() -> None:
    options = options_from_settings(TIERED)
    gvisor_default = options_from_settings(GVISOR_DEFAULT)

    assert options.tier_runtimes == {"container": "", "gvisor": "runsc", "microvm": "kata"}
    assert (options.default_tier, options.runtime, options.gvisor) == ("container", None, False)
    assert (gvisor_default.runtime, gvisor_default.gvisor) == ("runsc", True)


def test_gvisor_tier_on_a_container_default_gets_runsc_and_no_tmp_mount() -> None:
    options = options_from_settings(TIERED)

    config = build_host_config(make_spec(isolation="gvisor"), SETTINGS, options)

    assert config["runtime"] == "runsc"
    assert "mounts" not in config


@pytest.mark.parametrize("volumes", [(), RUNC_VOLUMES])
def test_container_tier_leaves_the_create_kwargs_unchanged(
    volumes: tuple[VolumeBind, ...],
) -> None:
    options = options_from_settings(TIERED)
    baseline = build_host_config(make_spec(volumes=volumes), SETTINGS)

    spec = make_spec(volumes=volumes, isolation="container")
    tiered = build_host_config(spec, SETTINGS, options)
    untiered = build_host_config(make_spec(volumes=volumes), SETTINGS, options)

    assert tiered == untiered == baseline
    assert "runtime" not in tiered and "mounts" not in tiered


def test_microvm_tier_maps_to_its_runtime_without_gvisor_mode() -> None:
    options = options_from_settings(TIERED)

    config = build_host_config(make_spec(isolation="microvm"), SETTINGS, options)

    assert config["runtime"] == "kata"
    assert "mounts" not in config


def test_gvisor_default_runs_a_container_tier_sandbox_on_the_daemon_default() -> None:
    options = options_from_settings(GVISOR_DEFAULT)

    untiered = build_host_config(make_spec(), SETTINGS, options)
    container = build_host_config(make_spec(isolation="container"), SETTINGS, options)

    assert untiered["runtime"] == "runsc" and "mounts" not in untiered
    assert "runtime" not in container and "mounts" not in container


def test_without_a_tier_map_the_default_tier_keeps_the_container_runtime() -> None:
    options = options_from_settings(Settings(container_runtime="runsc"))

    tiered = build_host_config(make_spec(isolation="container"), SETTINGS, options)

    assert tiered == build_host_config(make_spec(), SETTINGS, options)
    assert tiered["runtime"] == "runsc"


@pytest.mark.parametrize(
    "settings", [Settings(), Settings(isolation_runtimes=(("container", ""),))]
)
def test_a_tier_this_node_does_not_offer_is_refused(settings: Settings) -> None:
    options = options_from_settings(settings)

    with pytest.raises(DriverError, match="isolation 'gvisor' is not configured on this node"):
        build_host_config(make_spec(isolation="gvisor"), SETTINGS, options)


def test_host_config_log_and_ulimits() -> None:
    config = build_host_config(make_spec(), SETTINGS)
    assert config["ulimits"] == [{"Name": "nofile", "Soft": 4096, "Hard": 4096}]
    assert config["log_config"]["Config"] == {"max-size": "10m", "max-file": "3"}


# --- create kwargs ------------------------------------------------------------------


def test_create_kwargs_carry_labels_name_env_and_entrypoint() -> None:
    kwargs = build_create_kwargs(make_spec(env={"FOO": "bar"}, labels={"team": "x"}), SETTINGS)
    assert kwargs["name"] == "sf-sbx_1"
    assert kwargs["environment"] == {"FOO": "bar"}
    assert kwargs["entrypoint"] == list(KEEPALIVE_ENTRYPOINT)
    assert kwargs["labels"][LABEL_MANAGED] == "true"
    assert kwargs["labels"]["team"] == "x"
    assert kwargs["labels"][LABEL_DISK_GIB] == "2"


def test_create_kwargs_reject_reserved_env_names() -> None:
    with pytest.raises(DriverError, match="SANDFORT_API_KEY_PEPPER"):
        build_create_kwargs(make_spec(env={"SANDFORT_API_KEY_PEPPER": "x"}), SETTINGS)


# --- inspect parsing ----------------------------------------------------------------


def make_attrs(**overrides: Any) -> dict[str, Any]:
    attrs: dict[str, Any] = {
        "Id": "abc123",
        "Name": "/sf-sbx_1",
        "Created": "2026-10-30T12:00:00.123456789Z",
        "State": {"Status": "running", "Running": True, "Paused": False},
        "Config": {
            "Image": "alpine:3.20",
            "Labels": {
                LABEL_MANAGED: "true",
                LABEL_SANDBOX_ID: "sbx_1",
                LABEL_ORG_ID: "org_1",
                LABEL_DISK_GIB: "2",
            },
        },
        "HostConfig": {"NanoCpus": 1_000_000_000, "Memory": 512 * MIB},
    }
    attrs.update(overrides)
    return attrs


def test_info_from_attrs_maps_every_field() -> None:
    info = info_from_attrs(make_attrs())
    assert (info.ref, info.name, info.sandbox_id, info.org_id) == (
        "abc123",
        "sf-sbx_1",
        "sbx_1",
        "org_1",
    )
    assert info.state is InstanceState.RUNNING
    assert info.image == "alpine:3.20"
    assert info.resources == ResourceSpec(cpu_millicores=1000, memory_mib=512, disk_gib=2)
    assert info.created_at == datetime(2026, 10, 30, 12, 0, 0, 123456, tzinfo=UTC)


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ({"Status": "created"}, InstanceState.CREATED),
        ({"Status": "running"}, InstanceState.RUNNING),
        ({"Status": "restarting"}, InstanceState.RUNNING),
        ({"Status": "running", "Paused": True}, InstanceState.PAUSED),
        ({"Status": "paused"}, InstanceState.PAUSED),
        ({"Status": "exited"}, InstanceState.EXITED),
        ({"Status": "dead"}, InstanceState.EXITED),
    ],
)
def test_info_from_attrs_maps_state(state: dict[str, Any], expected: InstanceState) -> None:
    assert info_from_attrs(make_attrs(State=state)).state is expected


def test_info_from_attrs_tolerates_unlimited_foreign_resources() -> None:
    attrs = make_attrs(HostConfig={}, Config={"Image": "x", "Labels": None})
    info = info_from_attrs(attrs)
    assert info.sandbox_id == ""
    assert info.resources.cpu_millicores >= 100
    assert info.resources.memory_mib >= 64


# --- fake docker-py client ----------------------------------------------------------


def api_error(cls: type[Exception], status: int) -> Exception:
    response = SimpleNamespace(status_code=status, reason="x", url="http://docker/x")
    return cls("boom", response=response)


class FakeContainer:
    def __init__(self, attrs: dict[str, Any]) -> None:
        self.attrs = attrs


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.create_results: list[Any] = [FakeContainer(make_attrs())]
        self.existing: FakeContainer | None = None
        self.api_failure: Exception | None = None
        self.listed: list[FakeContainer] = []
        self.containers = SimpleNamespace(
            create=self._record("create", self._create),
            get=self._record("get", self._get),
            list=self._record("list", lambda **_: self.listed),
        )
        self.images = SimpleNamespace(pull=self._record("pull", lambda *_: None))
        self.networks = SimpleNamespace(
            list=self._record("net_list", lambda **_: []),
            create=self._record("net_create", lambda *_, **__: None),
        )
        self.api = SimpleNamespace(
            start=self._record("start", self._api),
            stop=self._record("stop", self._api),
            remove_container=self._record("remove", self._api),
            inspect_container=self._record("inspect", lambda *_: make_attrs()),
            put_archive=self._record("put_archive", lambda *_: True),
        )

    def _record(self, label: str, func: Any) -> Any:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((label, args, kwargs))
            return func(*args, **kwargs)

        return wrapper

    def _create(self, *_: Any, **__: Any) -> Any:
        result = self.create_results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def _get(self, name: str) -> Any:
        if self.existing is None:
            raise api_error(errors.NotFound, 404)
        return self.existing

    def _api(self, *_: Any, **__: Any) -> None:
        if self.api_failure is not None:
            raise self.api_failure

    def labels_called(self) -> list[str]:
        return [label for label, _, _ in self.calls]


async def test_create_returns_info_and_ensures_network() -> None:
    client = FakeClient()
    info = await create_container(client, make_spec(), SETTINGS)
    assert info.ref == "abc123"
    assert "net_create" in client.labels_called()
    _, args, kwargs = next(call for call in client.calls if call[0] == "create")
    assert args == ("alpine:3.20",)
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["log_config"].type == "local"


async def test_create_skips_network_when_all_egress_is_blocked() -> None:
    client = FakeClient()
    await create_container(client, make_spec(network=NetworkPolicy(block_all=True)), SETTINGS)
    assert "net_list" not in client.labels_called()


async def test_create_adopts_existing_managed_container_on_conflict() -> None:
    client = FakeClient()
    client.create_results = [api_error(errors.APIError, 409)]
    client.existing = FakeContainer(make_attrs(Id="existing"))
    info = await create_container(client, make_spec(), SETTINGS)
    assert info.ref == "existing"


async def test_create_refuses_to_adopt_unmanaged_container() -> None:
    client = FakeClient()
    client.create_results = [api_error(errors.APIError, 409)]
    client.existing = FakeContainer(make_attrs(Config={"Image": "x", "Labels": {}}))
    with pytest.raises(DriverConflict):
        await create_container(client, make_spec(), SETTINGS)


async def test_create_refuses_to_adopt_other_orgs_container() -> None:
    client = FakeClient()
    client.create_results = [api_error(errors.APIError, 409)]
    other = make_attrs()
    other["Config"]["Labels"] = {**other["Config"]["Labels"], LABEL_ORG_ID: "org_other"}
    client.existing = FakeContainer(other)
    with pytest.raises(DriverConflict):
        await create_container(client, make_spec(), SETTINGS)


async def test_create_pulls_a_missing_image_once_then_retries() -> None:
    client = FakeClient()
    client.create_results = [api_error(errors.ImageNotFound, 404), FakeContainer(make_attrs())]
    await create_container(client, make_spec(), SETTINGS)
    pulls = [call for call in client.calls if call[0] == "pull"]
    assert [call[1] for call in pulls] == [("alpine:3.20",)]


async def test_create_maps_other_api_errors_to_driver_error() -> None:
    client = FakeClient()
    client.create_results = [api_error(errors.APIError, 500)]
    with pytest.raises(DriverError):
        await create_container(client, make_spec(), SETTINGS)


async def test_destroy_is_idempotent_and_passes_volume_flag() -> None:
    client = FakeClient()
    await remove_container(client, "abc", remove_volumes=False)
    _, args, kwargs = next(call for call in client.calls if call[0] == "remove")
    assert args == ("abc",)
    assert kwargs == {"v": False, "force": True}

    client.api_failure = api_error(errors.NotFound, 404)
    await remove_container(client, "abc", remove_volumes=True)  # already gone: no error


async def test_start_of_missing_container_raises_not_found() -> None:
    client = FakeClient()
    client.api_failure = api_error(errors.NotFound, 404)
    with pytest.raises(DriverNotFound):
        await start_container(client, "gone")


async def test_stop_rounds_timeout_up_to_whole_seconds() -> None:
    client = FakeClient()
    await stop_container(client, "abc", 2.2)
    _, _, kwargs = next(call for call in client.calls if call[0] == "stop")
    assert kwargs == {"timeout": 3}


async def test_list_managed_filters_by_label_and_parses_attrs() -> None:
    client = FakeClient()
    client.listed = [FakeContainer(make_attrs())]
    infos = await list_managed_containers(client, "org_1")
    assert [info.sandbox_id for info in infos] == ["sbx_1"]
    _, _, kwargs = next(call for call in client.calls if call[0] == "list")
    assert kwargs == {"all": True, "filters": managed_filters("org_1")}


async def test_driver_delegates_compute_lifecycle() -> None:
    client = FakeClient()
    driver = DockerDriver(SETTINGS, client=client)
    assert driver.name == "docker"
    assert (await driver.create(make_spec())).ref == "abc123"
    assert (await driver.inspect("abc123")).state is InstanceState.RUNNING
    await driver.start("abc123")
    await driver.stop("abc123")
    await driver.destroy("abc123")
    assert {"start", "stop", "remove", "inspect"} <= set(client.labels_called())


# --- client helpers -----------------------------------------------------------------


async def test_run_blocking_returns_the_call_result() -> None:
    assert await docker_client.run_blocking(lambda a, b=0: a + b, 1, b=2) == 3


def test_configure_thread_limit_validates_and_resizes() -> None:
    with pytest.raises(ValueError):
        docker_client.configure_thread_limit(0)
    docker_client.configure_thread_limit(8)
    assert docker_client._get_limiter().total_tokens == 8
    docker_client.configure_thread_limit()
    assert docker_client._get_limiter().total_tokens == docker_client.DEFAULT_THREAD_LIMIT


@pytest.fixture
def fake_docker(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    """Swap docker-py for a module that records how its client factories are called."""
    calls: list[tuple[str, dict[str, Any]]] = []

    def from_env(**kwargs: Any) -> str:
        calls.append(("from_env", kwargs))
        return "env-client"

    def docker_client_class(**kwargs: Any) -> str:
        calls.append(("DockerClient", kwargs))
        return "url-client"

    module = SimpleNamespace(from_env=from_env, DockerClient=docker_client_class)
    monkeypatch.setattr(docker_client, "load_docker_module", lambda: module)
    return calls


def test_make_client_passes_the_pool_size_to_from_env(
    fake_docker: list[tuple[str, dict[str, Any]]],
) -> None:
    assert docker_client.make_client(max_pool_size=64) == "env-client"
    assert fake_docker == [("from_env", {"max_pool_size": 64})]


def test_make_client_passes_the_pool_size_with_an_explicit_base_url(
    fake_docker: list[tuple[str, dict[str, Any]]],
) -> None:
    assert docker_client.make_client("unix:///tmp/docker.sock", max_pool_size=12) == "url-client"
    assert fake_docker == [
        ("DockerClient", {"base_url": "unix:///tmp/docker.sock", "max_pool_size": 12})
    ]


def test_make_client_without_a_pool_size_keeps_the_docker_py_default(
    fake_docker: list[tuple[str, dict[str, Any]]],
) -> None:
    docker_client.make_client()
    docker_client.make_client("unix:///tmp/docker.sock")
    assert fake_docker == [
        ("from_env", {}),
        ("DockerClient", {"base_url": "unix:///tmp/docker.sock"}),
    ]


def test_driver_builds_its_client_with_a_pool_as_wide_as_the_total_thread_limit(
    fake_docker: list[tuple[str, dict[str, Any]]],
) -> None:
    try:
        driver = DockerDriver(Settings(docker_thread_limit=12, docker_bulk_threads=5))
    finally:
        docker_client.configure_thread_limit()
    assert driver._client == "env-client"
    assert fake_docker == [("from_env", {"max_pool_size": 12})]


def test_driver_with_an_injected_client_builds_no_client(
    fake_docker: list[tuple[str, dict[str, Any]]],
) -> None:
    try:
        DockerDriver(Settings(docker_thread_limit=12), client=FakeClient())
    finally:
        docker_client.configure_thread_limit()
    assert fake_docker == []


INTERNAL_URL_TEXT = (
    "404 Client Error for http+docker://localhost/v1.43/images/nope/json: Not Found "
    '("No such image: nope")'
)


def daemon_error(cls: type[Exception], status: int, explanation: str | None) -> Exception:
    response = SimpleNamespace(status_code=status, reason="x", url="http+docker://localhost/v1.43")
    return cls(INTERNAL_URL_TEXT, response=response, explanation=explanation)


def test_error_mapping_prefers_the_daemon_explanation() -> None:
    exc = daemon_error(errors.APIError, 500, "  dial tcp 10.0.0.1:443: i/o timeout  ")
    mapped = docker_client.as_driver_error(exc)
    assert type(mapped) is DriverError
    # the tenant sees the fixed sentence; the pull classifier reads the out-of-band daemon text
    assert str(mapped) == docker_client.GENERIC_DRIVER_MESSAGE
    assert mapped.daemon_text == "dial tcp 10.0.0.1:443: i/o timeout"


def test_error_mapping_gives_other_daemon_text_the_fixed_sentence() -> None:
    mapped = docker_client.as_driver_error(daemon_error(errors.APIError, 500, "  oops  "))
    assert type(mapped) is DriverError
    assert str(mapped) == docker_client.GENERIC_DRIVER_MESSAGE


def test_error_mapping_strips_the_internal_url_without_an_explanation() -> None:
    for explanation in (None, "", "   "):
        mapped = docker_client.as_driver_error(daemon_error(errors.APIError, 500, explanation))
        assert mapped is not None
        message = str(mapped)
        assert message == docker_client.GENERIC_DRIVER_MESSAGE
        assert "+docker" not in message
        assert "localhost" not in message
        assert "/v1." not in message


def test_clean_message_strips_the_internal_url_without_an_explanation() -> None:
    for explanation in (None, "", "   "):
        message = docker_client.clean_message(daemon_error(errors.APIError, 500, explanation))
        assert "+docker" not in message
        assert "localhost" not in message
        assert "/v1." not in message
        assert message.startswith("500 Server Error: x")


def test_error_mapping_keeps_the_not_found_and_conflict_types() -> None:
    not_found = docker_client.as_driver_error(
        daemon_error(errors.NotFound, 404, "No such container: web"), ref="sf-1"
    )
    conflict = docker_client.as_driver_error(daemon_error(errors.APIError, 409, "name in use"))
    assert type(not_found) is DriverNotFound
    assert str(not_found) == "No such container: web"
    assert type(conflict) is DriverConflict
    assert str(conflict) == docker_client.CONFLICT_MESSAGE
    assert conflict.daemon_text == "name in use"


DISK_FULL_RAW = (
    "Error setting up pivot dir: mkdir /var/lib/docker/overlay2/abc123/merged/x: "
    "no space left on device"
)


@pytest.mark.parametrize("status", [500, 409])
@pytest.mark.parametrize(
    "raw", [DISK_FULL_RAW, DISK_FULL_RAW.replace("no space left", "No Space LEFT")]
)
def test_error_mapping_turns_a_full_disk_into_an_actionable_conflict(status: int, raw: str) -> None:
    mapped = docker_client.as_driver_error(daemon_error(errors.APIError, status, raw), ref="sf-1")
    assert type(mapped) is DriverConflict
    assert str(mapped) == docker_client.DISK_FULL_MESSAGE
    assert "/var/lib/docker" not in str(mapped)
    assert "pivot" not in str(mapped)


def test_translate_errors_raises_the_disk_full_conflict() -> None:
    with (
        pytest.raises(DriverConflict) as caught,
        docker_client.translate_errors("sf-1", "container.start"),
    ):
        raise daemon_error(errors.APIError, 500, DISK_FULL_RAW)
    assert str(caught.value) == docker_client.DISK_FULL_MESSAGE
    assert "/var/lib/docker" not in str(caught.value)


def test_error_mapping_gives_an_unrelated_api_error_the_fixed_sentence() -> None:
    mapped = docker_client.as_driver_error(daemon_error(errors.APIError, 500, "boom"), ref="sf-1")
    assert type(mapped) is DriverError
    assert mapped.message == docker_client.GENERIC_DRIVER_MESSAGE
    assert "boom" not in mapped.message
    assert mapped.ref == "sf-1"


def test_error_mapping_redacts_a_full_container_id() -> None:
    container_id = "0123456789abcdef" * 4
    explanation = f"Could not find the file /data/x in container {container_id}"
    mapped = docker_client.as_driver_error(daemon_error(errors.NotFound, 404, explanation))
    assert type(mapped) is DriverNotFound
    assert container_id not in str(mapped)
    assert str(mapped) == docker_client.NOT_FOUND_MESSAGE
    assert container_id not in str(mapped.daemon_text)
    assert mapped.daemon_text == "Could not find the file /data/x in the sandbox container"


def test_error_mapping_redacts_a_bare_full_container_id() -> None:
    container_id = "fedcba9876543210" * 4
    explanation = f"no such file or directory (id {container_id})"
    mapped = docker_client.as_driver_error(daemon_error(errors.NotFound, 404, explanation))
    assert mapped is not None
    assert container_id not in str(mapped)
    assert str(mapped) == docker_client.NOT_FOUND_MESSAGE
    assert mapped.daemon_text == "no such file or directory (id the sandbox container)"


def test_error_mapping_redacts_a_short_container_id() -> None:
    explanation = "Could not find the file /data/x in container 0123456789ab"
    mapped = docker_client.as_driver_error(daemon_error(errors.NotFound, 404, explanation))
    assert mapped is not None
    assert "0123456789ab" not in str(mapped)
    assert str(mapped) == docker_client.NOT_FOUND_MESSAGE
    assert mapped.daemon_text == "Could not find the file /data/x in the sandbox container"


def test_make_client_connect_failure_message_is_cleaned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def from_env(**_: Any) -> None:
        raise errors.DockerException("Error while fetching http+docker://localhost/v1.43/version")

    monkeypatch.setattr(
        docker_client, "load_docker_module", lambda: SimpleNamespace(from_env=from_env)
    )
    with pytest.raises(DriverError) as caught:
        docker_client.make_client()
    assert "+docker" not in str(caught.value)
    assert str(caught.value).startswith("cannot connect to the Docker daemon: ")


PULL_HELPERS = [pull_image, pull_image_digest]
PULL_DENIED_TEXT = (
    "pull access denied for {ref}, repository does not exist or may require 'docker login'"
)


def failing_pull_client(failure: Exception) -> FakeClient:
    client = FakeClient()

    def pull(*_: Any, **__: Any) -> None:
        raise failure

    client.images.pull = pull
    return client


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_pull_not_found_becomes_a_clean_not_found(helper: Any) -> None:
    client = failing_pull_client(daemon_error(errors.NotFound, 404, "No such image: marco-snap1"))
    with pytest.raises(DriverNotFound) as caught:
        await helper(client, "marco-snap1")
    assert str(caught.value) == "no such image or snapshot: marco-snap1"


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_pull_access_denied_becomes_a_clean_not_found(helper: Any) -> None:
    explanation = PULL_DENIED_TEXT.format(ref="marco-snap1")
    client = failing_pull_client(daemon_error(errors.APIError, 500, explanation))
    with pytest.raises(DriverNotFound) as caught:
        await helper(client, "marco-snap1")
    message = str(caught.value)
    assert message == "no such image or snapshot: marco-snap1"
    assert "docker login" not in message
    assert "pull access denied" not in message


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_pull_unrelated_daemon_error_keeps_its_own_message(helper: Any) -> None:
    client = failing_pull_client(daemon_error(errors.APIError, 500, "the daemon is overloaded"))
    with pytest.raises(DriverError) as caught:
        await helper(client, "alpine:3.20")
    assert type(caught.value) is DriverError
    assert str(caught.value) == "could not pull alpine:3.20"


def create_client_with_failing_pull(failure: Exception) -> FakeClient:
    """A client whose create reports image-not-found and whose follow-up pull then fails."""
    client = failing_pull_client(failure)
    client.create_results = [api_error(errors.ImageNotFound, 404)]
    return client


async def test_create_inline_pull_not_found_becomes_a_clean_not_found() -> None:
    spec = make_spec()
    failure = daemon_error(errors.NotFound, 404, "No such image: alpine:3.20")
    client = create_client_with_failing_pull(failure)
    with pytest.raises(DriverNotFound) as caught:
        await create_container(client, spec, SETTINGS)
    assert str(caught.value) == f"no such image or snapshot: {spec.image}"


async def test_create_inline_pull_access_denied_becomes_a_clean_not_found() -> None:
    spec = make_spec()
    explanation = PULL_DENIED_TEXT.format(ref=spec.image)
    client = create_client_with_failing_pull(daemon_error(errors.APIError, 500, explanation))
    with pytest.raises(DriverNotFound) as caught:
        await create_container(client, spec, SETTINGS)
    message = str(caught.value)
    assert message == f"no such image or snapshot: {spec.image}"
    assert "docker login" not in message
    assert "pull access denied" not in message


async def test_create_inline_pull_unrelated_failure_still_propagates() -> None:
    failure = daemon_error(errors.APIError, 500, "the daemon is overloaded")
    client = create_client_with_failing_pull(failure)
    with pytest.raises(DriverError) as caught:
        await create_container(client, make_spec(), SETTINGS)
    assert type(caught.value) is DriverError
    assert str(caught.value) == f"could not pull {make_spec().image}"


def test_clean_message_replaces_the_pull_denial_sentence() -> None:
    explanation = PULL_DENIED_TEXT.format(ref="nope/missing:1")
    message = docker_client.clean_message(daemon_error(errors.APIError, 500, explanation))
    assert message == "the image could not be pulled"
    assert "docker login" not in message
    assert "pull access denied" not in message


def test_clean_message_keeps_text_around_the_pull_denial_sentence() -> None:
    explanation = "Error response from daemon: " + PULL_DENIED_TEXT.format(ref="x/y")
    message = docker_client.clean_message(daemon_error(errors.APIError, 500, explanation))
    assert message == "Error response from daemon: the image could not be pulled"


DNS_FAILURE_TEXT = (
    'failed to resolve reference "docker.io/nonexistent/image:nope": failed to do request: '
    'Head "https://registry-1.docker.io/v2/nonexistent/image/manifests/nope": dial tcp: '
    "lookup registry-1.docker.io on 127.0.0.53:53: server misbehaving"
)
REGISTRY_UNREACHABLE = (
    "could not pull {ref}: the registry did not answer (a transient network problem, or a "
    "registry host that does not exist); check the name, then try again"
)


@pytest.mark.parametrize("helper", PULL_HELPERS)
async def test_pull_dns_failure_becomes_a_clean_registry_error(helper: Any) -> None:
    ref = "nonexistent/image:nope"
    client = failing_pull_client(daemon_error(errors.APIError, 500, DNS_FAILURE_TEXT))
    with pytest.raises(DriverError) as caught:
        await helper(client, ref)
    assert type(caught.value) is DriverRegistryUnreachable
    assert str(caught.value) == REGISTRY_UNREACHABLE.format(ref=ref)
    assert "127.0.0.53" not in str(caught.value)


@pytest.mark.parametrize(
    "text",
    [
        "net/http: TLS handshake timeout",
        "dial tcp 10.0.0.1:443: i/o timeout",
        "dial tcp 10.0.0.1:443: connect: connection refused",
        "lookup registry-1.docker.io: no such host",
        "Temporary failure in name resolution",
    ],
)
async def test_pull_other_registry_network_failures_share_the_clean_error(text: str) -> None:
    client = failing_pull_client(daemon_error(errors.APIError, 500, text))
    with pytest.raises(DriverError) as caught:
        await pull_image(client, "alpine:3.20")
    assert type(caught.value) is DriverRegistryUnreachable
    assert str(caught.value) == REGISTRY_UNREACHABLE.format(ref="alpine:3.20")


async def test_pull_denied_text_wins_over_network_markers() -> None:
    explanation = PULL_DENIED_TEXT.format(ref="x/y") + ": dial tcp: lookup r on 1.2.3.4:53"
    client = failing_pull_client(daemon_error(errors.APIError, 500, explanation))
    with pytest.raises(DriverNotFound) as caught:
        await pull_image(client, "x/y")
    assert str(caught.value) == "no such image or snapshot: x/y"


async def test_create_inline_pull_dns_failure_becomes_a_clean_registry_error() -> None:
    spec = make_spec()
    client = create_client_with_failing_pull(daemon_error(errors.APIError, 500, DNS_FAILURE_TEXT))
    with pytest.raises(DriverError) as caught:
        await create_container(client, spec, SETTINGS)
    assert type(caught.value) is DriverRegistryUnreachable
    assert str(caught.value) == REGISTRY_UNREACHABLE.format(ref=spec.image)
    assert "127.0.0.53" not in str(caught.value)


@pytest.mark.parametrize("resolver", ["127.0.0.53:53", "[::1]:53"])
def test_clean_message_strips_the_resolver_address(resolver: str) -> None:
    text = f"dial tcp: lookup registry-1.docker.io on {resolver}: server misbehaving"
    message = docker_client.clean_message(daemon_error(errors.APIError, 500, text))
    assert message == "dial tcp: lookup registry-1.docker.io: server misbehaving"
    assert resolver not in message


def test_translate_errors_leaves_unrelated_exceptions_alone() -> None:
    with pytest.raises(KeyError), docker_client.translate_errors("x", "container.inspect"):
        raise KeyError("unrelated")


# --- gVisor resolv.conf -------------------------------------------------------------

CUSTOM_NAMESERVERS = ("9.9.9.9", "2606:4700:4700::1111", "1.0.0.1")
RUNSC_HOST_CONFIG = {"Runtime": "runsc", "NetworkMode": "sf-net"}


def test_resolv_conf_text_for_the_default_nameservers() -> None:
    assert DEFAULT_GVISOR_NAMESERVERS == ("1.1.1.1", "8.8.8.8")
    assert resolv_conf_text(DEFAULT_GVISOR_NAMESERVERS) == (
        "nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions ndots:0\n"
    )


def test_resolv_conf_text_keeps_a_custom_list_in_order() -> None:
    assert resolv_conf_text(CUSTOM_NAMESERVERS) == (
        "nameserver 9.9.9.9\nnameserver 2606:4700:4700::1111\nnameserver 1.0.0.1\noptions ndots:0\n"
    )


def test_options_from_settings_carry_the_parsed_gvisor_nameservers() -> None:
    custom = Settings(gvisor_dns="9.9.9.9, 2606:4700:4700::1111,1.0.0.1")
    assert options_from_settings(custom).gvisor_nameservers == CUSTOM_NAMESERVERS
    assert options_from_settings(Settings(gvisor_dns="")).gvisor_nameservers == ()
    assert options_from_settings(Settings()).gvisor_nameservers == DEFAULT_GVISOR_NAMESERVERS


@pytest.fixture
def dns_writes(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ExecRequest]]:
    """Replace the exec the start helper uses; each call is recorded and succeeds."""
    writes: list[tuple[str, ExecRequest]] = []

    async def fake_exec_run(_client: Any, ref: str, request: ExecRequest) -> ExecResult:
        writes.append((ref, request))
        return ExecResult(exit_code=0)

    monkeypatch.setattr(containers_module, "exec_run", fake_exec_run)
    return writes


def client_running(host_config: dict[str, Any]) -> FakeClient:
    """A fake client whose container inspects with ``host_config``."""
    client = FakeClient()
    client.api.inspect_container = lambda *_: make_attrs(HostConfig=host_config)
    return client


async def test_start_writes_resolv_conf_as_root_for_a_runsc_container(
    dns_writes: list[tuple[str, ExecRequest]],
) -> None:
    client = client_running(RUNSC_HOST_CONFIG)

    await start_container(client, "abc", DEFAULT_GVISOR_NAMESERVERS)

    [(ref, request)] = dns_writes
    assert ref == "abc"
    assert request.user == "0"
    assert request.argv[-1] == RESOLV_CONF_PATH == "/etc/resolv.conf"
    assert request.stdin == resolv_conf_text(DEFAULT_GVISOR_NAMESERVERS).encode()
    assert client.labels_called() == ["put_archive", "start"]


@pytest.mark.parametrize(
    "host_config",
    [
        {"Runtime": "runc", "NetworkMode": "sf-net"},
        {"Runtime": "runc", "NetworkMode": EGRESS_NETWORK_NAME},
        {"NetworkMode": "sf-net"},
        {"NetworkMode": EGRESS_NETWORK_NAME},
    ],
)
async def test_start_skips_runc_containers_on_attached_networks(
    dns_writes: list[tuple[str, ExecRequest]], host_config: dict[str, Any]
) -> None:
    await start_container(client_running(host_config), "abc", DEFAULT_GVISOR_NAMESERVERS)

    assert dns_writes == []


@pytest.mark.parametrize("runtime", ["runc", "", "runsc", "kata", "kata-qemu"])
async def test_start_writes_the_fail_fast_text_for_network_none_on_every_runtime(
    dns_writes: list[tuple[str, ExecRequest]], runtime: str
) -> None:
    host_config = {"NetworkMode": "none", "Runtime": runtime}
    client = client_running(host_config)

    await start_container(client, "abc", DEFAULT_GVISOR_NAMESERVERS)

    [(ref, request)] = dns_writes
    assert ref == "abc"
    assert request.stdin == fail_fast_resolv_conf_text().encode()
    assert request.user == "0"
    assert request.argv[-1] == RESOLV_CONF_PATH
    assert client.labels_called()[-1] == "start"


async def test_a_failing_write_for_network_none_does_not_fail_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def failing_exec_run(_client: Any, _ref: str, _request: ExecRequest) -> ExecResult:
        raise DriverError("exec exploded")

    monkeypatch.setattr(containers_module, "exec_run", failing_exec_run)
    client = client_running({"Runtime": "runc", "NetworkMode": "none"})

    await start_container(client, "abc", DEFAULT_GVISOR_NAMESERVERS)

    assert client.labels_called() == ["start"]


@pytest.mark.parametrize("runtime", ["runsc", "kata", "kata-qemu", "kata-clh"])
async def test_start_writes_the_nameservers_for_runsc_and_kata_runtimes(
    dns_writes: list[tuple[str, ExecRequest]], runtime: str
) -> None:
    client = client_running({"Runtime": runtime, "NetworkMode": "sf-net"})

    await start_container(client, "abc", DEFAULT_GVISOR_NAMESERVERS)

    [(_, request)] = dns_writes
    assert request.stdin == resolv_conf_text(DEFAULT_GVISOR_NAMESERVERS).encode()


@pytest.mark.parametrize("runtime", ["runsc", "kata", "kata-qemu"])
async def test_start_writes_the_fail_fast_text_on_the_egress_network(
    dns_writes: list[tuple[str, ExecRequest]], runtime: str
) -> None:
    client = client_running({"Runtime": runtime, "NetworkMode": EGRESS_NETWORK_NAME})

    await start_container(client, "abc", DEFAULT_GVISOR_NAMESERVERS)

    [(_, request)] = dns_writes
    assert request.stdin == b"nameserver 127.0.0.1\noptions timeout:1 attempts:1\n"
    assert request.stdin == fail_fast_resolv_conf_text().encode()
    assert request.user == "0"
    assert request.argv[-1] == RESOLV_CONF_PATH


async def test_start_on_the_egress_network_with_no_nameservers_leaves_resolv_conf_alone(
    dns_writes: list[tuple[str, ExecRequest]],
) -> None:
    client = client_running({"Runtime": "runsc", "NetworkMode": EGRESS_NETWORK_NAME})

    await start_container(client, "abc", ())

    assert dns_writes == []


@pytest.mark.parametrize(
    ("runtime", "expected"),
    [
        ("runsc", True),
        ("kata", True),
        ("kata-qemu", True),
        ("runc", False),
        ("", False),
        ("nokata", False),
    ],
)
def test_has_own_network_stack_matches_runsc_and_kata_names(runtime: str, expected: bool) -> None:
    assert has_own_network_stack(runtime) is expected


def test_fail_fast_resolv_conf_text_is_a_pure_fixed_text() -> None:
    assert fail_fast_resolv_conf_text() == fail_fast_resolv_conf_text()
    assert fail_fast_resolv_conf_text() == ("nameserver 127.0.0.1\noptions timeout:1 attempts:1\n")


async def test_start_with_no_nameservers_does_not_inspect_or_write(
    dns_writes: list[tuple[str, ExecRequest]],
) -> None:
    client = client_running(RUNSC_HOST_CONFIG)

    await start_container(client, "abc")
    await start_container(client, "abc", ())

    assert dns_writes == []
    assert "inspect" not in client.labels_called()


@pytest.mark.parametrize(
    "failure",
    [DriverError("exec exploded"), RuntimeError("daemon went away"), ExecResult(exit_code=1)],
)
async def test_a_failing_resolv_conf_write_only_logs_a_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, failure: Any
) -> None:
    async def failing_exec_run(_client: Any, _ref: str, _request: ExecRequest) -> ExecResult:
        if isinstance(failure, ExecResult):
            return failure
        raise failure

    monkeypatch.setattr(containers_module, "exec_run", failing_exec_run)
    client = client_running(RUNSC_HOST_CONFIG)

    with caplog.at_level(logging.WARNING, logger=containers_module.logger.name):
        await start_container(client, "abc", DEFAULT_GVISOR_NAMESERVERS)

    assert "start" in client.labels_called()
    assert any("gVisor nameservers" in record.getMessage() for record in caplog.records)


async def test_a_failing_inspect_before_the_write_does_not_fail_start(
    dns_writes: list[tuple[str, ExecRequest]], caplog: pytest.LogCaptureFixture
) -> None:
    client = FakeClient()

    def broken_inspect(*_: Any) -> dict[str, Any]:
        raise api_error(errors.APIError, 500)

    client.api.inspect_container = broken_inspect

    with caplog.at_level(logging.WARNING, logger=containers_module.logger.name):
        await start_container(client, "abc", DEFAULT_GVISOR_NAMESERVERS)

    assert dns_writes == []
    assert any("gVisor nameservers" in record.getMessage() for record in caplog.records)


async def test_driver_start_writes_the_configured_nameservers_for_runsc(
    dns_writes: list[tuple[str, ExecRequest]],
) -> None:
    options = options_from_settings(Settings(gvisor_dns="9.9.9.9"))
    driver = DockerDriver(SETTINGS, client=client_running(RUNSC_HOST_CONFIG), options=options)

    await driver.start("abc")

    [(_, request)] = dns_writes
    assert request.stdin == b"nameserver 9.9.9.9\noptions ndots:0\n"


async def test_driver_start_decides_from_the_container_not_the_deployment_runtime(
    dns_writes: list[tuple[str, ExecRequest]],
) -> None:
    """A per-sandbox gvisor tier on a runc deployment still gets the write."""
    options = options_from_settings(Settings())
    assert options.runtime is None and options.gvisor is False
    driver = DockerDriver(SETTINGS, client=client_running(RUNSC_HOST_CONFIG), options=options)

    await driver.start("abc")

    assert len(dns_writes) == 1


async def test_driver_start_with_an_empty_list_leaves_resolv_conf_alone(
    dns_writes: list[tuple[str, ExecRequest]],
) -> None:
    options = options_from_settings(Settings(container_runtime="runsc", gvisor_dns=""))
    driver = DockerDriver(SETTINGS, client=client_running(RUNSC_HOST_CONFIG), options=options)

    await driver.start("abc")

    assert dns_writes == []


# --- gVisor /tmp marker -------------------------------------------------------------

TMP_MARKER = ".sandfort-keep"


def client_inspecting(**attrs: Any) -> FakeClient:
    """A fake client whose container inspects with ``make_attrs(**attrs)``."""
    client = FakeClient()
    client.api.inspect_container = lambda *_: make_attrs(**attrs)
    return client


def tar_members(data: bytes) -> list[tarfile.TarInfo]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
        return tar.getmembers()


def puts(client: FakeClient) -> list[tuple[str, str, bytes]]:
    """``(ref, path, tar bytes)`` of every recorded put_archive call."""
    calls = [args for label, args, _ in client.calls if label == "put_archive"]
    return [(args[0], args[1], args[2]) for args in calls]


def raising(failure: Exception) -> Any:
    def fail(*_: Any) -> bool:
        raise failure

    return fail


async def test_start_puts_an_empty_marker_into_tmp_before_starting_a_runsc_container() -> None:
    client = client_running(RUNSC_HOST_CONFIG)

    await start_container(client, "abc")

    [(ref, path, data)] = puts(client)
    assert (ref, path) == ("abc", "/tmp")
    [member] = tar_members(data)
    assert (member.name, member.isfile(), member.size) == (TMP_MARKER, True, 0)
    assert client.labels_called() == ["put_archive", "start"]


@pytest.mark.parametrize("runtime", ["runc", "", "kata", "kata-qemu", "kata-clh"])
async def test_start_leaves_runc_and_kata_containers_without_a_marker(runtime: str) -> None:
    client = client_running({"Runtime": runtime, "NetworkMode": "sf-net"})

    await start_container(client, "abc")

    assert client.labels_called() == ["start"]


async def test_start_leaves_a_container_without_a_runtime_field_without_a_marker() -> None:
    client = client_running({"NetworkMode": "sf-net"})

    await start_container(client, "abc")

    assert client.labels_called() == ["start"]


async def test_every_start_of_a_runsc_container_puts_the_marker_again() -> None:
    client = client_running(RUNSC_HOST_CONFIG)

    await start_container(client, "abc")
    await start_container(client, "abc")

    assert client.labels_called() == ["put_archive", "start", "put_archive", "start"]


async def test_start_creates_tmp_in_the_archive_when_the_image_has_none() -> None:
    client = client_running(RUNSC_HOST_CONFIG)
    attempts: list[tuple[str, bytes]] = []

    def put(_ref: str, path: str, data: bytes) -> bool:
        attempts.append((path, data))
        if path == "/tmp":
            raise api_error(errors.NotFound, 404)
        return True

    client.api.put_archive = put

    await start_container(client, "abc")

    assert [path for path, _ in attempts] == ["/tmp", "/"]
    directory, marker = tar_members(attempts[1][1])
    assert (directory.name, directory.isdir(), directory.mode) == ("tmp", True, 0o1777)
    assert (marker.name, marker.isfile(), marker.size) == (f"tmp/{TMP_MARKER}", True, 0)
    assert client.labels_called() == ["start"]


@pytest.mark.parametrize("destination", ["/tmp", "/tmp/"])
async def test_start_skips_the_marker_when_a_volume_is_mounted_at_tmp(destination: str) -> None:
    mounts = [{"Type": "volume", "Destination": destination}]
    client = client_inspecting(HostConfig=RUNSC_HOST_CONFIG, Mounts=mounts)

    await start_container(client, "abc")

    assert client.labels_called() == ["start"]


async def test_start_puts_the_marker_when_only_other_paths_are_mounted() -> None:
    mounts = [
        {"Type": "volume", "Destination": "/data"},
        {"Type": "volume", "Destination": "/tmpx"},
    ]
    client = client_inspecting(HostConfig=RUNSC_HOST_CONFIG, Mounts=mounts)

    await start_container(client, "abc")

    assert client.labels_called() == ["put_archive", "start"]


@pytest.mark.parametrize(
    "put",
    [
        raising(api_error(errors.APIError, 500)),
        raising(RuntimeError("daemon went away")),
        lambda *_: False,
    ],
)
async def test_a_failing_marker_put_only_logs_a_warning(
    caplog: pytest.LogCaptureFixture, put: Any
) -> None:
    client = client_running(RUNSC_HOST_CONFIG)
    client.api.put_archive = put

    with caplog.at_level(logging.WARNING, logger=containers_module.logger.name):
        await start_container(client, "abc")

    assert client.labels_called() == ["start"]
    assert any(TMP_MARKER in record.getMessage() for record in caplog.records)


async def test_a_failing_inspect_before_the_marker_does_not_fail_start(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = FakeClient()
    client.api.inspect_container = raising(api_error(errors.APIError, 500))

    with caplog.at_level(logging.WARNING, logger=containers_module.logger.name):
        await start_container(client, "abc")

    assert client.labels_called() == ["start"]
    assert any(TMP_MARKER in record.getMessage() for record in caplog.records)


async def test_start_of_a_missing_runsc_container_still_raises_not_found() -> None:
    client = client_running(RUNSC_HOST_CONFIG)
    client.api_failure = api_error(errors.NotFound, 404)

    with pytest.raises(DriverNotFound):
        await start_container(client, "gone")


async def test_driver_start_decides_the_marker_from_the_container_runtime() -> None:
    """A per-sandbox gvisor tier on a runc deployment still gets the marker."""
    options = options_from_settings(Settings(gvisor_dns=""))
    assert options.runtime is None and options.gvisor is False
    client = client_running(RUNSC_HOST_CONFIG)

    await DockerDriver(SETTINGS, client=client, options=options).start("abc")

    assert client.labels_called() == ["put_archive", "start"]


# --- instance_size_bytes (metering size capability) ---------------------------------


def size_client(result: Any) -> Any:
    """A client whose low-level ``api.containers`` returns ``result`` (or raises it)."""
    calls: list[dict[str, Any]] = []

    def containers(**kwargs: Any) -> Any:
        calls.append(kwargs)
        if isinstance(result, Exception):
            raise result
        return result

    return SimpleNamespace(api=SimpleNamespace(containers=containers), calls=calls)


async def test_instance_size_bytes_returns_the_writable_layer_size() -> None:
    client = size_client([{"Id": "abc", "SizeRw": 4096, "SizeRootFs": 99999}])

    assert await DockerDriver(SETTINGS, client=client).instance_size_bytes("abc") == 4096


async def test_instance_size_bytes_asks_docker_for_sizes_filtered_by_id() -> None:
    client = size_client([{"SizeRw": 1}])

    await DockerDriver(SETTINGS, client=client).instance_size_bytes("abc")

    assert client.calls == [{"all": True, "size": True, "filters": {"id": "abc"}}]


@pytest.mark.parametrize(
    "result",
    [
        [],
        [{"Id": "abc"}],
        [{"Id": "abc", "SizeRw": None}],
        [{"Id": "abc", "SizeRw": "4096"}],
        [{"Id": "abc", "SizeRw": 1.5}],
        [{"Id": "abc", "SizeRw": True}],
        ["not-a-mapping"],
        RuntimeError("daemon unreachable"),
    ],
    ids=["not-found", "missing", "none", "str", "float", "bool", "bad-entry", "raises"],
)
async def test_instance_size_bytes_is_none_when_no_size_is_available(result: Any) -> None:
    client = size_client(result)

    assert await DockerDriver(SETTINGS, client=client).instance_size_bytes("abc") is None


async def test_instance_size_bytes_logs_a_docker_failure_at_debug(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = size_client(RuntimeError("daemon unreachable"))

    with caplog.at_level(logging.DEBUG, logger=containers_module.logger.name):
        await DockerDriver(SETTINGS, client=client).instance_size_bytes("abc")

    assert [r.levelno for r in caplog.records if "abc" in r.getMessage()] == [logging.DEBUG]


def test_docker_driver_satisfies_the_metering_size_protocol() -> None:
    assert isinstance(DockerDriver(SETTINGS, client=size_client([])), InstanceSizeDriver)


# --- pty exit code -----------------------------------------------------------------


def pty_driver(inspect: Any) -> tuple[DockerDriver, PtySessionHandle]:
    """A driver holding one live pty whose exec inspects through ``inspect``."""
    client = FakeClient()
    client.api.exec_inspect = inspect
    driver = DockerDriver(SETTINGS, client=client)
    pty = docker_pty.DockerPty(client, "abc", "exec_1", object(), "/tmp/.sf-pty-test.pid")
    return driver, driver._ptys.add(pty)


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ({"Running": False, "ExitCode": 3}, 3),
        ({"Running": False, "ExitCode": 0}, 0),
        ({"Running": False, "ExitCode": 255}, 255),
        ({"Running": True, "ExitCode": None}, None),
        ({"Running": True, "ExitCode": 0}, None),
        ({"Running": False, "ExitCode": None}, None),
        ({"Running": False}, None),
        ({"Running": False, "ExitCode": "3"}, None),
        ({"Running": False, "ExitCode": True}, None),
    ],
)
async def test_docker_pty_exit_code_reads_the_exec_exit_code(
    state: dict[str, Any], expected: int | None
) -> None:
    driver, handle = pty_driver(lambda exec_id: state)

    assert await driver.pty_exit_code(handle) == expected


async def test_docker_pty_exit_code_inspects_the_exec_of_the_pty() -> None:
    seen: list[str] = []

    def inspect(exec_id: str) -> dict[str, Any]:
        seen.append(exec_id)
        return {"Running": False, "ExitCode": 7}

    driver, handle = pty_driver(inspect)

    assert await docker_pty.pty_exit_code(driver._ptys, handle) == 7
    assert seen == ["exec_1"]


async def test_docker_pty_exit_code_is_none_when_docker_fails() -> None:
    def inspect(exec_id: str) -> dict[str, Any]:
        raise RuntimeError("daemon unreachable")

    driver, handle = pty_driver(inspect)

    assert await driver.pty_exit_code(handle) is None


async def test_docker_pty_exit_code_is_none_for_an_unknown_handle() -> None:
    driver, _ = pty_driver(lambda exec_id: {"Running": False, "ExitCode": 3})

    assert await driver.pty_exit_code(PtySessionHandle("dockerpty-unknown")) is None


def test_docker_driver_satisfies_the_pty_exit_code_capability() -> None:
    assert isinstance(DockerDriver(SETTINGS, client=FakeClient()), PtyExitCodeDriver)
