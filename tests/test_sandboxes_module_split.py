"""Characterization of the sandboxes service surface, kept green across the module split."""

import ast
import dataclasses
import importlib
import inspect
from pathlib import Path
from typing import Any

import pytest

import sandfort.api.routes.sandboxes as sandbox_routes
import sandfort.services.sandboxes as sandboxes
from sandfort.services import (
    admission,
    label_scope,
    sandbox_create_intent,
    sandbox_create_rules,
    sandbox_jobs,
    sandbox_mounting,
    sandbox_queries,
    sandbox_resize,
    sandbox_service_base,
    sandbox_snapshot_resolution,
    sandbox_update,
)

MODULE_NAMES = (
    "CreateSandboxCommand",
    "DEFAULT_IMAGE",
    "DELETE_MAX_ATTEMPTS",
    "LIVE_SCAN_PAGE",
    "MAX_WAIT_S",
    "MIN_AUTO_MINUTES",
    "MountingLifecycle",
    "PendingSnapshotReader",
    "POLL_INTERVAL_S",
    "RESIZE_FAILED_MESSAGE",
    "SNAPSHOT_ID_PREFIX",
    "SandboxService",
    "StandbyClaimer",
    "audit_capacity_refusal",
    "audit_key_cap_refusal",
    "with_image_mounts_label",
)

ASYNC_METHODS = (
    "get",
    "list",
    "create",
    "update",
    "start",
    "stop",
    "reset",
    "delete",
    "_commit_create_intent",
    "_sample_volumes",
    "_refuse_over_quota",
    "_refuse_over_limit_mounts",
    "_require_under_key_cap",
    "_reserve_on_start",
    "_refuse_while_snapshotting",
    "_recreate_if_resized",
    "_guarded",
    "_replace_container",
    "_create_from_resize_image",
    "_resize_image_exists",
    "_resize_image_id",
    "_discard_resize_image",
    "_release",
    "_load",
    "_place",
    "_enqueue",
    "_with_snapshot_id",
    "_inherit_snapshot_tier",
    "_inherit_snapshot_resources",
    "_require_visible_snapshot",
    "_resolve_image",
)

SYNC_METHODS = (
    "_releasing",
    "_with_carried_mounts",
    "_with_default_network",
    "_enforced_network",
    "_create_note",
    "_new_sandbox",
    "_check_resource_maximum",
    "_validate_create",
    "_sandbox_env",
    "_validate_labels",
    "_validate_isolation",
    "_validate_minutes",
)

STATIC_METHODS = (
    "_require_under_key_cap",
    "_guarded",
    "_discard_resize_image",
    "_with_carried_mounts",
    "_enforced_network",
    "_create_note",
    "_validate_labels",
    "_validate_minutes",
)

IMPORTER_MODULES = (
    "sandfort.api.deps",
    "sandfort.api.wiring",
    "sandfort.api.routes.sandbox_preview",
    "sandfort.api.routes.sandboxes",
    "sandfort.services.warm_pool",
)

COMMAND_FIELDS = (
    "name",
    "snapshot",
    "resources",
    "inherit_resources",
    "env",
    "labels",
    "network",
    "auto_stop_minutes",
    "auto_delete_minutes",
    "public",
    "volumes",
    "standby",
    "spec_hash",
    "egress_allowlist",
    "isolation",
)

COMMAND_DEFAULTS = (
    None,
    None,
    "<factory>",
    False,
    "<factory>",
    "<factory>",
    "<factory>",
    15,
    -1,
    False,
    (),
    False,
    None,
    None,
    None,
)

MOVED_NAMES = (
    ("sandbox_commands", "CreateSandboxCommand"),
    ("sandbox_commands", "StandbyClaimer"),
    ("sandbox_commands", "PendingSnapshotReader"),
    ("sandbox_commands", "DEFAULT_IMAGE"),
    ("sandbox_commands", "SNAPSHOT_ID_PREFIX"),
    ("sandbox_mounting", "MountingLifecycle"),
    ("sandbox_mounting", "with_image_mounts_label"),
    ("sandbox_resize", "RESIZE_FAILED_MESSAGE"),
    ("sandbox_queries", "MAX_WAIT_S"),
    ("sandbox_queries", "POLL_INTERVAL_S"),
    ("sandbox_queries", "LIVE_SCAN_PAGE"),
    ("sandbox_create_rules", "MIN_AUTO_MINUTES"),
)

MOVED_PRIVATE_NAMES = frozenset(
    {"_live_by_scanning", "_live_in_scope", "_key_cap_error", "_ENV_NAME"}
)

MIXIN_METHODS = (
    "get",
    "list",
    "_load",
    "_recreate_if_resized",
    "_guarded",
    "_replace_container",
    "_create_from_resize_image",
    "_resize_image_exists",
    "_resize_image_id",
    "_discard_resize_image",
    "_with_carried_mounts",
    "_with_default_network",
    "_enforced_network",
    "_create_note",
    "_new_sandbox",
    "_check_resource_maximum",
    "_validate_create",
    "_sandbox_env",
    "_validate_labels",
    "_validate_isolation",
    "_validate_minutes",
    "_with_snapshot_id",
    "_inherit_snapshot_tier",
    "_inherit_snapshot_resources",
    "_require_visible_snapshot",
    "_resolve_image",
    "_commit_create_intent",
    "_sample_volumes",
    "_refuse_over_quota",
    "_refuse_over_limit_mounts",
    "_require_under_key_cap",
    "_place",
    "_enqueue",
    "update",
)

SPLIT_MODULES = (
    "sandbox_commands.py",
    "sandbox_mounting.py",
    "sandbox_service_base.py",
    "sandbox_resize.py",
    "sandbox_queries.py",
    "sandbox_create_rules.py",
    "sandbox_snapshot_resolution.py",
    "sandbox_create_intent.py",
    "sandbox_update.py",
    "sandboxes.py",
)

SERVICE_MRO = (
    "SandboxService",
    "SandboxCreateIntentMixin",
    "SnapshotResolutionMixin",
    "SandboxUpdateMixin",
    "SandboxCreateRulesMixin",
    "SandboxResizeMixin",
    "SandboxQueriesMixin",
    "SandboxServiceBase",
    "object",
)

SERVICES_DIR = Path(__file__).resolve().parents[1] / "src" / "sandfort" / "services"
MAX_MODULE_LINES = 400


def _default_of(field: "dataclasses.Field[Any]") -> Any:
    if field.default is dataclasses.MISSING and field.default_factory is not dataclasses.MISSING:
        return "<factory>"
    return field.default


@pytest.mark.parametrize("name", MODULE_NAMES)
def test_every_public_name_is_a_module_attribute(name: str) -> None:
    assert hasattr(sandboxes, name)


def test_constants_keep_their_values() -> None:
    assert sandboxes.DEFAULT_IMAGE == "python:3.12-slim"
    assert sandboxes.MAX_WAIT_S == 60.0
    assert sandboxes.POLL_INTERVAL_S == 0.1
    assert sandboxes.MIN_AUTO_MINUTES == -1
    assert sandboxes.DELETE_MAX_ATTEMPTS == 3
    assert sandboxes.SNAPSHOT_ID_PREFIX == "snap_"
    assert sandboxes.LIVE_SCAN_PAGE == label_scope.SCAN_PAGE
    assert sandboxes.RESIZE_FAILED_MESSAGE == (
        "resize could not prepare the sandbox's container; try again or contact the operator"
    )


def test_refusal_helpers_are_the_admission_functions() -> None:
    assert sandboxes.audit_capacity_refusal is admission.audit_capacity_refusal
    assert sandboxes.audit_key_cap_refusal is admission.audit_key_cap_refusal


def test_logger_name_is_unchanged() -> None:
    assert sandboxes.logger.name == "sandfort.services.sandboxes"


def test_mounting_lifecycle_extends_lifecycle_with_static_spec() -> None:
    assert issubclass(sandboxes.MountingLifecycle, sandbox_jobs.Lifecycle)
    spec = inspect.getattr_static(sandboxes.MountingLifecycle, "spec")
    assert isinstance(spec, staticmethod)


def test_create_command_is_a_frozen_slots_dataclass() -> None:
    cls = sandboxes.CreateSandboxCommand
    assert dataclasses.is_dataclass(cls)
    assert cls.__dataclass_params__.frozen is True
    assert "__slots__" in vars(cls)


def test_create_command_field_names_and_order() -> None:
    names = [f.name for f in dataclasses.fields(sandboxes.CreateSandboxCommand)]
    assert names == list(COMMAND_FIELDS)


def test_create_command_field_defaults() -> None:
    defaults = [_default_of(f) for f in dataclasses.fields(sandboxes.CreateSandboxCommand)]
    assert defaults == list(COMMAND_DEFAULTS)


@pytest.mark.parametrize("name", ASYNC_METHODS)
def test_service_async_method_is_a_coroutine_function(name: str) -> None:
    service = sandboxes.SandboxService
    assert hasattr(service, name)
    assert inspect.iscoroutinefunction(getattr(service, name))


@pytest.mark.parametrize("name", SYNC_METHODS)
def test_service_sync_method_is_a_plain_callable(name: str) -> None:
    service = sandboxes.SandboxService
    assert hasattr(service, name)
    member = getattr(service, name)
    assert callable(member)
    assert not inspect.iscoroutinefunction(member)


@pytest.mark.parametrize("name", STATIC_METHODS)
def test_service_static_method_stays_static(name: str) -> None:
    assert isinstance(inspect.getattr_static(sandboxes.SandboxService, name), staticmethod)


@pytest.mark.parametrize("module_name", IMPORTER_MODULES)
def test_importer_module_still_imports(module_name: str) -> None:
    assert importlib.import_module(module_name) is not None


def test_routes_reexport_the_same_create_command() -> None:
    assert sandbox_routes.CreateSandboxCommand is sandboxes.CreateSandboxCommand


@pytest.mark.parametrize(("module_name", "name"), MOVED_NAMES)
def test_moved_name_is_reexported_from_sandboxes(module_name: str, name: str) -> None:
    module = importlib.import_module(f"sandfort.services.{module_name}")
    assert getattr(sandboxes, name) is getattr(module, name)


def test_service_inherits_the_leaf_mixins() -> None:
    service = sandboxes.SandboxService
    base = sandbox_service_base.SandboxServiceBase
    assert issubclass(service, sandbox_resize.SandboxResizeMixin)
    assert issubclass(service, sandbox_queries.SandboxQueriesMixin)
    assert issubclass(sandbox_resize.SandboxResizeMixin, base)
    assert issubclass(sandbox_queries.SandboxQueriesMixin, base)
    assert issubclass(service, base)


def test_split_modules_log_under_the_sandboxes_logger_name() -> None:
    assert sandbox_mounting.logger.name == "sandfort.services.sandboxes"
    assert sandbox_resize.logger.name == "sandfort.services.sandboxes"


@pytest.mark.parametrize("name", MIXIN_METHODS)
def test_moved_method_is_not_redefined_on_the_service(name: str) -> None:
    assert name not in vars(sandboxes.SandboxService)


def test_moved_names_are_not_redefined_in_sandboxes() -> None:
    tree = ast.parse((SERVICES_DIR / "sandboxes.py").read_text(encoding="utf-8"))
    defined: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            defined.add(node.name)
        elif isinstance(node, ast.Assign):
            defined.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            defined.add(node.target.id)
    moved = {name for _, name in MOVED_NAMES} | MOVED_PRIVATE_NAMES
    assert defined.isdisjoint(moved)


@pytest.mark.parametrize("file_name", SPLIT_MODULES)
def test_split_module_stays_under_the_line_limit(file_name: str) -> None:
    lines = (SERVICES_DIR / file_name).read_text(encoding="utf-8").splitlines()
    assert len(lines) < MAX_MODULE_LINES


def test_service_mro_is_the_planned_mixin_order() -> None:
    assert tuple(cls.__name__ for cls in sandboxes.SandboxService.__mro__) == SERVICE_MRO


def test_service_inherits_the_create_path_mixins() -> None:
    service = sandboxes.SandboxService
    rules = sandbox_create_rules.SandboxCreateRulesMixin
    assert issubclass(service, sandbox_create_intent.SandboxCreateIntentMixin)
    assert issubclass(service, sandbox_update.SandboxUpdateMixin)
    snapshots = sandbox_snapshot_resolution.SnapshotResolutionMixin
    assert issubclass(sandbox_create_intent.SandboxCreateIntentMixin, snapshots)
    assert issubclass(snapshots, rules)
    assert issubclass(sandbox_update.SandboxUpdateMixin, rules)
    assert issubclass(rules, sandbox_service_base.SandboxServiceBase)


def test_min_auto_minutes_is_reexported_from_create_rules() -> None:
    assert sandboxes.MIN_AUTO_MINUTES is sandbox_create_rules.MIN_AUTO_MINUTES


def test_class_level_static_access_reaches_the_mixin_functions() -> None:
    service = sandboxes.SandboxService
    rules = sandbox_create_rules.SandboxCreateRulesMixin
    intent = sandbox_create_intent.SandboxCreateIntentMixin
    assert service._create_note is rules._create_note
    assert service._require_under_key_cap is intent._require_under_key_cap


@pytest.mark.parametrize("name", ("create", "start"))
def test_create_and_start_stay_on_the_service(name: str) -> None:
    assert name in vars(sandboxes.SandboxService)
