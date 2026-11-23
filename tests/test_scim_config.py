"""SCIM settings: off by default, ``viewer`` default role, bad values fail at load time."""

import pytest

from sandfort.config import ENV_PREFIX, VALID_SCIM_ROLES, Settings
from sandfort.domain.user import OrgRole

ENABLED = f"{ENV_PREFIX}SCIM_ENABLED"
DEFAULT_ROLE = f"{ENV_PREFIX}SCIM_DEFAULT_ROLE"


def test_dataclass_defaults_are_off_and_viewer() -> None:
    settings = Settings()

    assert settings.scim_enabled is False
    assert settings.scim_default_role == "viewer"


def test_empty_environment_loads_the_defaults() -> None:
    settings = Settings.from_env({})

    assert settings.scim_enabled is False
    assert settings.scim_default_role == OrgRole.VIEWER.value


def test_valid_roles_are_exactly_the_org_roles() -> None:
    assert set(VALID_SCIM_ROLES) == {role.value for role in OrgRole}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("true", True), ("1", True), ("YES", True), ("on", True), ("false", False), ("0", False)],
)
def test_scim_enabled_is_parsed_as_a_boolean(raw: str, expected: bool) -> None:
    assert Settings.from_env({ENABLED: raw}).scim_enabled is expected


def test_scim_enabled_rejects_a_non_boolean() -> None:
    with pytest.raises(ValueError, match=ENABLED):
        Settings.from_env({ENABLED: "maybe"})


@pytest.mark.parametrize("role", [role.value for role in OrgRole])
def test_every_org_role_is_an_accepted_default_role(role: str) -> None:
    assert Settings.from_env({DEFAULT_ROLE: role}).scim_default_role == role


def test_default_role_is_stripped_before_it_is_checked() -> None:
    assert Settings.from_env({DEFAULT_ROLE: "  developer "}).scim_default_role == "developer"


@pytest.mark.parametrize("role", ["owner", "root", "Admin", "", "   ", "admin,viewer"])
def test_a_bad_default_role_is_a_startup_error(role: str) -> None:
    with pytest.raises(ValueError, match=DEFAULT_ROLE):
        Settings.from_env({DEFAULT_ROLE: role})


def test_scim_can_be_enabled_with_a_default_role_together() -> None:
    settings = Settings.from_env({ENABLED: "true", DEFAULT_ROLE: "developer"})

    assert settings.scim_enabled is True
    assert settings.scim_default_role == "developer"
