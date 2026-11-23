"""SCIM slice seven: member <-> User resource, immutability and ListResponse paging.

Pure unit tests: no database, no http, no settings. Covers the Attribute mapping and Filter and
pagination sections of ``docs/scim-design.md``. The error table is in ``test_scim_discovery.py``.
"""

import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from sandfort.api.scim.errors import MUTABILITY, ScimValidationError, describe_failure
from sandfort.api.scim.patch import (
    INVALID_SYNTAX,
    INVALID_VALUE,
    MAX_EXTERNAL_ID_LENGTH,
    NameChange,
    PatchChange,
)
from sandfort.api.scim.resources import (
    LIST_RESPONSE_SCHEMA,
    SCIM_MAX_COUNT,
    USER_SCHEMA,
    PageWindow,
    UserInput,
    ensure_patch_unchanged,
    ensure_unchanged,
    list_response,
    member_to_resource,
    page_window,
    parse_user_resource,
)
from sandfort.domain.user import OrgRole, User
from sandfort.errors import ValidationFailed
from sandfort.services.user_admin import Member

BASE = "https://sf.example/scim/v2"
CREATED = datetime(2026, 11, 2, 9, 35, 0, tzinfo=UTC)
PLUS_TWO = timezone(timedelta(hours=2))


def make_user(
    index: int = 0,
    *,
    email: str | None = None,
    display_name: str = "Alice Doe",
    created_at: datetime = CREATED,
    disabled_at: datetime | None = None,
) -> User:
    return User(
        id=f"usr_{index:03d}",
        email=email or f"user{index}@example.com",
        display_name=display_name,
        created_at=created_at,
        disabled_at=disabled_at,
    )


def make_member(
    index: int = 0,
    *,
    role: OrgRole = OrgRole.VIEWER,
    external_id: str | None = None,
    **user_fields: Any,
) -> Member:
    return Member(user=make_user(index, **user_fields), role=role, external_id=external_id)


def make_members(count: int) -> list[Member]:
    return [make_member(index) for index in range(count)]


def body(**fields: Any) -> dict[str, Any]:
    return {"schemas": [USER_SCHEMA], "userName": "Alice@Example.com", **fields}


def scim_type_of(raw: object) -> str | None:
    with pytest.raises(ValidationFailed) as info:
        parse_user_resource(raw)
    failure = describe_failure(info.value)
    assert failure.status == 400
    return failure.scim_type


def counts(response: dict[str, Any]) -> tuple[int, int, int]:
    return response["totalResults"], response["startIndex"], response["itemsPerPage"]


def ids(response: dict[str, Any]) -> list[str]:
    return [resource["id"] for resource in response["Resources"]]


# --- member -> resource -------------------------------------------------------------------


def test_member_renders_the_full_user_resource() -> None:
    member = make_member(1, role=OrgRole.DEVELOPER, external_id="okta-77", email="Ann@Example.com")

    assert member_to_resource(member, base_url=BASE) == {
        "schemas": [USER_SCHEMA],
        "id": "usr_001",
        "externalId": "okta-77",
        "userName": "ann@example.com",
        "name": {"formatted": "Alice Doe"},
        "displayName": "Alice Doe",
        "emails": [{"value": "ann@example.com", "type": "work", "primary": True}],
        "active": True,
        "roles": [{"value": "developer", "primary": True}],
        "meta": {
            "resourceType": "User",
            "created": "2026-11-02T09:35:00Z",
            "location": f"{BASE}/Users/usr_001",
        },
    }


def test_member_without_external_id_has_no_external_id_key() -> None:
    assert "externalId" not in member_to_resource(make_member(), base_url=BASE)


def test_active_is_false_only_when_the_global_user_is_disabled() -> None:
    disabled = make_member(disabled_at=CREATED)

    assert member_to_resource(disabled, base_url=BASE)["active"] is False
    assert member_to_resource(make_member(), base_url=BASE)["active"] is True


def test_created_is_utc_for_naive_and_offset_timestamps() -> None:
    naive = make_member(created_at=datetime(2026, 11, 2, 9, 35, 0))
    offset = make_member(created_at=datetime(2026, 11, 2, 9, 35, 0, tzinfo=PLUS_TWO))

    assert member_to_resource(naive, base_url=BASE)["meta"]["created"] == "2026-11-02T09:35:00Z"
    assert member_to_resource(offset, base_url=BASE)["meta"]["created"] == "2026-11-02T07:35:00Z"


def test_location_ignores_a_trailing_slash_on_the_base_url() -> None:
    resource = member_to_resource(make_member(2), base_url=f"{BASE}/")

    assert resource["meta"]["location"] == f"{BASE}/Users/usr_002"


# --- resource -> input, and the round trip ------------------------------------------------


@pytest.mark.parametrize("role", list(OrgRole))
def test_member_to_resource_and_back_keeps_every_mapped_value(role: OrgRole) -> None:
    member = make_member(3, role=role, external_id="ext-3", display_name="Carol Danvers")

    parsed = parse_user_resource(json.loads(json.dumps(member_to_resource(member, base_url=BASE))))

    assert parsed == UserInput(
        user_name=member.user.email,
        display_name="Carol Danvers",
        role=role,
        external_id="ext-3",
        active=True,
    )


def test_minimal_body_is_normalised_and_leaves_the_rest_absent() -> None:
    parsed = parse_user_resource(body())

    assert parsed == UserInput(user_name="alice@example.com")
    assert parsed.new_display_name == "alice"


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({"displayName": " Alice D ", "name": {"formatted": "Other"}}, "Alice D"),
        ({"name": {"formatted": "Alice Formatted", "givenName": "A"}}, "Alice Formatted"),
        ({"name": {"givenName": "Alice", "familyName": "Doe"}}, "Alice Doe"),
        ({"name": {"familyName": "Doe"}}, "Doe"),
        ({"displayName": "  ", "name": {"givenName": "Alice"}}, "Alice"),
    ],
)
def test_display_name_is_display_name_then_formatted_then_given_and_family(
    fields: dict[str, Any], expected: str
) -> None:
    parsed = parse_user_resource(body(**fields))

    assert parsed.display_name == expected
    assert parsed.new_display_name == expected


@pytest.mark.parametrize(
    "raw",
    [None, [], "text", {"userName": "a@b.c"}, {"schemas": ["other"], "userName": "a@b.c"}],
)
def test_a_body_that_is_not_a_user_resource_is_invalid_syntax(raw: object) -> None:
    assert scim_type_of(raw) == INVALID_SYNTAX


@pytest.mark.parametrize("user_name", [None, "", "   ", 7, ["a@b.c"]])
def test_user_name_is_required(user_name: object) -> None:
    assert scim_type_of(body(userName=user_name)) == INVALID_VALUE


@pytest.mark.parametrize("fields", [{"displayName": 5}, {"name": "A"}, {"name": {"formatted": 1}}])
def test_malformed_names_are_invalid_value(fields: dict[str, Any]) -> None:
    assert scim_type_of(body(**fields)) == INVALID_VALUE


def test_work_and_primary_emails_must_equal_user_name_and_others_are_ignored() -> None:
    same = [{"value": "ALICE@example.com", "type": "work", "primary": "True"}]
    other = [{"value": "home@example.com", "type": "home"}]

    assert parse_user_resource(body(emails=same)).user_name == "alice@example.com"
    assert parse_user_resource(body(emails=other)).user_name == "alice@example.com"


@pytest.mark.parametrize(
    "emails",
    [
        [{"value": "x@example.com", "type": "work"}],
        [{"value": "x@example.com", "primary": True}],
        [{"value": "x@example.com", "primary": "true"}],
        [{"type": "work"}],
        ["alice@example.com"],
        "alice@example.com",
    ],
)
def test_a_conflicting_or_malformed_emails_value_is_invalid_value(emails: object) -> None:
    assert scim_type_of(body(emails=emails)) == INVALID_VALUE


def test_roles_name_one_role_and_empty_means_absent() -> None:
    primary = [{"value": "admin", "primary": True}]

    assert parse_user_resource(body(roles=primary)).role is OrgRole.ADMIN
    assert parse_user_resource(body(roles=[{"value": "viewer"}])).role is OrgRole.VIEWER
    assert parse_user_resource(body(roles=[])).role is None
    assert parse_user_resource(body(roles=None)).role is None


@pytest.mark.parametrize(
    "roles",
    [
        [{"value": "owner", "primary": True}],
        [{"value": "admin"}, {"value": "viewer"}],
        [{"primary": True}],
        "admin",
    ],
)
def test_unknown_conflicting_or_malformed_roles_are_invalid_value(roles: object) -> None:
    assert scim_type_of(body(roles=roles)) == INVALID_VALUE


def test_external_id_is_kept_and_blank_means_absent() -> None:
    assert parse_user_resource(body(externalId="okta-1")).external_id == "okta-1"
    assert parse_user_resource(body(externalId="  ")).external_id is None


@pytest.mark.parametrize("external_id", [12, "x" * (MAX_EXTERNAL_ID_LENGTH + 1)])
def test_a_bad_external_id_is_invalid_value(external_id: object) -> None:
    assert scim_type_of(body(externalId=external_id)) == INVALID_VALUE


def test_active_is_a_boolean_or_absent() -> None:
    assert parse_user_resource(body(active=False)).active is False
    assert parse_user_resource(body()).active is None
    assert scim_type_of(body(active="false")) == INVALID_VALUE


def test_refusals_never_repeat_a_request_value() -> None:
    secret = "sf_scim_supersecret"
    raw = body(roles=[{"value": secret}], emails=[{"value": secret, "type": "work"}])

    with pytest.raises(ValidationFailed) as info:
        parse_user_resource(raw)

    assert secret not in info.value.message


# --- immutability -------------------------------------------------------------------------


def test_unchanged_values_are_a_no_op_and_absent_values_are_ignored() -> None:
    user = make_user(display_name="Alice Doe")

    ensure_unchanged(user)
    ensure_unchanged(user, user_name=" USER0@example.com ", display_name=" Alice Doe ")


@pytest.mark.parametrize("changed", [{"user_name": "other@example.com"}, {"display_name": "Bob"}])
def test_a_different_user_name_or_display_name_is_mutability(changed: dict[str, str]) -> None:
    with pytest.raises(ScimValidationError) as info:
        ensure_unchanged(make_user(), **changed)

    assert describe_failure(info.value).scim_type == MUTABILITY
    assert "other@example.com" not in info.value.message


def test_patch_values_follow_the_same_immutability_rule() -> None:
    user = make_user(display_name="Alice Doe")
    same_name = NameChange(given_name="Alice", family_name="Doe")

    ensure_patch_unchanged(user, PatchChange(active=False, role=OrgRole.ADMIN))
    ensure_patch_unchanged(user, PatchChange(display_name="Alice Doe"))
    ensure_patch_unchanged(user, PatchChange(user_name="USER0@example.com"))
    ensure_patch_unchanged(user, PatchChange(name=NameChange(formatted="Alice Doe")))
    ensure_patch_unchanged(user, PatchChange(name=same_name))


@pytest.mark.parametrize(
    "change",
    [
        PatchChange(display_name="Alice Other"),
        PatchChange(user_name="other@example.com"),
        PatchChange(name=NameChange(formatted="Alice Other")),
        PatchChange(name=NameChange(given_name="Alice")),
    ],
)
def test_a_patch_that_changes_an_immutable_value_is_mutability(change: PatchChange) -> None:
    with pytest.raises(ScimValidationError) as info:
        ensure_patch_unchanged(make_user(display_name="Alice Doe"), change)

    assert describe_failure(info.value).scim_type == MUTABILITY


# --- ListResponse paging arithmetic -------------------------------------------------------


@pytest.mark.parametrize(
    ("start_index", "count", "expected"),
    [
        (None, None, PageWindow(1, SCIM_MAX_COUNT)),
        (0, None, PageWindow(1, SCIM_MAX_COUNT)),
        (-5, 10, PageWindow(1, 10)),
        (3, 10, PageWindow(3, 10)),
        (1, SCIM_MAX_COUNT + 1, PageWindow(1, SCIM_MAX_COUNT)),
        (1, 10_000, PageWindow(1, SCIM_MAX_COUNT)),
        (1, 0, PageWindow(1, 0)),
        (1, -3, PageWindow(1, 0)),
    ],
)
def test_page_window_clamps_start_and_count(
    start_index: int | None, count: int | None, expected: PageWindow
) -> None:
    assert page_window(start_index, count) == expected


def test_list_response_defaults_return_everything_with_the_five_envelope_keys() -> None:
    response = list_response(make_members(5), base_url=BASE)

    assert set(response) == {"schemas", "totalResults", "startIndex", "itemsPerPage", "Resources"}
    assert response["schemas"] == [LIST_RESPONSE_SCHEMA]
    assert counts(response) == (5, 1, 5)
    assert ids(response) == [f"usr_{index:03d}" for index in range(5)]


def test_list_response_pages_are_one_based_slices() -> None:
    members = make_members(5)

    middle = list_response(members, base_url=BASE, start_index=2, count=2)
    last = list_response(members, base_url=BASE, start_index=5, count=3)
    clamped = list_response(members, base_url=BASE, start_index=-4, count=1)

    assert (ids(middle), counts(middle)) == (["usr_001", "usr_002"], (5, 2, 2))
    assert (ids(last), counts(last)) == (["usr_004"], (5, 5, 1))
    assert (ids(clamped), counts(clamped)) == (["usr_000"], (5, 1, 1))


def test_list_response_start_past_the_end_is_an_empty_page_with_the_total() -> None:
    response = list_response(make_members(5), base_url=BASE, start_index=9, count=10)

    assert response["Resources"] == []
    assert counts(response) == (5, 9, 0)


def test_list_response_count_zero_returns_only_the_total() -> None:
    response = list_response(make_members(5), base_url=BASE, start_index=1, count=0)

    assert response["Resources"] == []
    assert counts(response) == (5, 1, 0)


def test_list_response_caps_count_at_the_maximum_page_size() -> None:
    members = make_members(SCIM_MAX_COUNT + 20)

    default = list_response(members, base_url=BASE)
    explicit = list_response(members, base_url=BASE, count=5_000)
    second = list_response(members, base_url=BASE, start_index=SCIM_MAX_COUNT + 1)

    assert default["itemsPerPage"] == explicit["itemsPerPage"] == SCIM_MAX_COUNT
    assert default["totalResults"] == SCIM_MAX_COUNT + 20
    assert second["itemsPerPage"] == 20


def test_list_response_for_no_members_is_empty_not_an_error() -> None:
    response = list_response([], base_url=BASE)

    assert response["Resources"] == []
    assert counts(response) == (0, 1, 0)
