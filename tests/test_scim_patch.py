"""SCIM slice six: ``parse_patch`` folds PatchOp operations into one normalized change.

Covers the three accepted shapes as Okta (value object without ``path``) and Entra (``path``,
string booleans) send them, atomic folding, and every refused operation. Pure unit tests: no
database, no http, no settings.
"""

import copy
import dataclasses
from typing import Any

import pytest

from sandfort.api.scim.patch import (
    MAX_EXTERNAL_ID_LENGTH,
    PATCH_OP_SCHEMA,
    NameChange,
    PatchChange,
    PatchError,
    parse_patch,
    role_from_entries,
    role_from_name,
)
from sandfort.domain.user import OrgRole
from sandfort.errors import ValidationFailed

ROLES_PRIMARY = 'roles[primary eq "True"].value'
LONG_ROLE_ENTRY = {"value": "viewer", "display": "Viewer", "type": "AppRole"}


def _body(*operations: object) -> dict[str, Any]:
    return {"schemas": [PATCH_OP_SCHEMA], "Operations": list(operations)}


def _refusal(body: object) -> PatchError:
    with pytest.raises(PatchError) as info:
        parse_patch(body)
    return info.value


def _refused_op(operation: object, scim_type: str) -> None:
    assert _refusal(_body(operation)).scim_type == scim_type


# --- shape 1: replace active -------------------------------------------------------------

ACTIVE_VALUES = [
    pytest.param(False, False, id="bool-false"),
    pytest.param(True, True, id="bool-true"),
    pytest.param("False", False, id="entra-string-false"),
    pytest.param("True", True, id="entra-string-true"),
    pytest.param("false", False, id="lower-string-false"),
    pytest.param("true", True, id="lower-string-true"),
]
NOT_BOOLEANS = ["yes", "", "0", " True", "s3cret", 0, 1, None, [], {}, [True]]


@pytest.mark.parametrize(("value", "expected"), ACTIVE_VALUES)
def test_entra_replaces_active_by_path(value: object, expected: bool) -> None:
    change = parse_patch(_body({"op": "Replace", "path": "active", "value": value}))

    assert change == PatchChange(active=expected)


@pytest.mark.parametrize(("value", "expected"), ACTIVE_VALUES)
def test_okta_replaces_active_in_a_value_object(value: object, expected: bool) -> None:
    change = parse_patch(_body({"op": "replace", "value": {"active": value}}))

    assert change == PatchChange(active=expected)


@pytest.mark.parametrize("value", NOT_BOOLEANS)
def test_active_refuses_every_non_boolean(value: object) -> None:
    _refused_op({"op": "replace", "path": "active", "value": value}, "invalidValue")
    _refused_op({"op": "replace", "value": {"active": value}}, "invalidValue")


def test_active_without_a_value_is_refused() -> None:
    _refused_op({"op": "replace", "path": "active"}, "invalidValue")


def test_active_path_is_matched_case_insensitively() -> None:
    change = parse_patch(_body({"op": "replace", "path": "Active", "value": "False"}))

    assert change == PatchChange(active=False)


# --- shape 2: replace a top-level attribute ------------------------------------------------


@pytest.mark.parametrize("path", ["externalId", "ExternalId", "externalid"])
def test_entra_replaces_external_id_by_path(path: str) -> None:
    change = parse_patch(_body({"op": "Replace", "path": path, "value": "ext-1"}))

    assert change == PatchChange(external_id="ext-1")


def test_okta_replaces_external_id_in_a_value_object() -> None:
    change = parse_patch(_body({"op": "replace", "value": {"externalId": "ext-1"}}))

    assert change == PatchChange(external_id="ext-1")


def test_external_id_at_the_length_limit_is_accepted() -> None:
    value = "x" * MAX_EXTERNAL_ID_LENGTH

    change = parse_patch(_body({"op": "replace", "path": "externalId", "value": value}))

    assert change == PatchChange(external_id=value)


@pytest.mark.parametrize(
    "value",
    ["", "   ", None, 5, True, ["ext"], {"v": 1}, "x" * (MAX_EXTERNAL_ID_LENGTH + 1)],
)
def test_external_id_refuses_a_bad_value(value: object) -> None:
    _refused_op({"op": "replace", "path": "externalId", "value": value}, "invalidValue")
    _refused_op({"op": "replace", "value": {"externalId": value}}, "invalidValue")


def test_display_name_and_user_name_are_returned_as_requested() -> None:
    by_path = parse_patch(
        _body(
            {"op": "replace", "path": "displayName", "value": "Ada Lovelace"},
            {"op": "replace", "path": "userName", "value": "Ada@Example.com"},
        )
    )
    by_value = parse_patch(
        _body(
            {
                "op": "replace",
                "value": {"displayName": "Ada Lovelace", "userName": "Ada@Example.com"},
            }
        )
    )

    expected = PatchChange(display_name="Ada Lovelace", user_name="Ada@Example.com")
    assert by_path == expected
    assert by_value == expected


@pytest.mark.parametrize("attribute", ["displayName", "userName"])
@pytest.mark.parametrize("value", ["", "  ", None, 5, False, ["a"], {"a": "b"}])
def test_text_attributes_refuse_a_bad_value(attribute: str, value: object) -> None:
    _refused_op({"op": "replace", "path": attribute, "value": value}, "invalidValue")
    _refused_op({"op": "replace", "value": {attribute: value}}, "invalidValue")


def test_name_is_returned_as_requested() -> None:
    value = {"givenName": "Ada", "familyName": "Lovelace"}

    by_path = parse_patch(_body({"op": "replace", "path": "name", "value": value}))
    by_value = parse_patch(_body({"op": "replace", "value": {"name": value}}))

    expected = PatchChange(name=NameChange(given_name="Ada", family_name="Lovelace"))
    assert by_path == expected
    assert by_value == expected


def test_name_formatted_is_carried_and_empty_or_null_parts_are_absent() -> None:
    change = parse_patch(
        _body(
            {
                "op": "replace",
                "path": "name",
                "value": {"formatted": "Ada L.", "givenName": "", "familyName": None},
            }
        )
    )

    assert change == PatchChange(name=NameChange(formatted="Ada L."))


@pytest.mark.parametrize(
    "value",
    [
        "Ada",
        None,
        ["Ada"],
        {},
        {"middleName": "M"},
        {"givenName": "Ada", "honorificPrefix": "Dr"},
        {"givenName": 5},
        {"givenName": ["Ada"]},
        {"givenName": ""},
        {"givenName": None, "familyName": ""},
    ],
)
def test_name_refuses_a_bad_value(value: object) -> None:
    _refused_op({"op": "replace", "path": "name", "value": value}, "invalidValue")
    _refused_op({"op": "replace", "value": {"name": value}}, "invalidValue")


def test_a_value_object_may_name_several_attributes() -> None:
    change = parse_patch(
        _body({"op": "replace", "value": {"active": "True", "externalId": "ext-9"}})
    )

    assert change == PatchChange(active=True, external_id="ext-9")


@pytest.mark.parametrize("op", ["remove", "Remove", "REMOVE"])
@pytest.mark.parametrize("path", ["externalId", "ExternalId"])
def test_remove_external_id_clears_it(op: str, path: str) -> None:
    change = parse_patch(_body({"op": op, "path": path}))

    assert change == PatchChange(clear_external_id=True)
    assert change.external_id is None


# --- shape 3: add or replace the role ------------------------------------------------------


@pytest.mark.parametrize("op", ["add", "replace", "Add", "Replace", "ADD"])
@pytest.mark.parametrize(
    ("entries", "role"),
    [
        ([{"value": "viewer", "primary": True}], OrgRole.VIEWER),
        ([{"value": "developer", "primary": "True"}], OrgRole.DEVELOPER),
        ([{"value": "admin", "primary": "False"}], OrgRole.ADMIN),
        ([{"value": "admin"}], OrgRole.ADMIN),
        ([{"value": "viewer", "primary": True}, {"value": "viewer"}], OrgRole.VIEWER),
        ([LONG_ROLE_ENTRY], OrgRole.VIEWER),
    ],
)
def test_role_by_roles_path(op: str, entries: list[dict[str, object]], role: OrgRole) -> None:
    change = parse_patch(_body({"op": op, "path": "roles", "value": entries}))

    assert change == PatchChange(role=role)


@pytest.mark.parametrize("op", ["add", "replace", "Replace"])
@pytest.mark.parametrize(
    "path",
    [
        ROLES_PRIMARY,
        'roles[primary eq "true"].value',
        'ROLES[primary EQ "TRUE"].VALUE',
        'roles[ primary  eq  "True" ].value',
    ],
)
def test_role_by_primary_filter_path(op: str, path: str) -> None:
    change = parse_patch(_body({"op": op, "path": path, "value": "developer"}))

    assert change == PatchChange(role=OrgRole.DEVELOPER)


@pytest.mark.parametrize("path", ["roles", ROLES_PRIMARY])
@pytest.mark.parametrize("value", ["owner", "Admin", "", None, 5, True])
def test_role_refuses_a_name_outside_the_role_enum(path: str, value: object) -> None:
    operation_value: object = [{"value": value}] if path == "roles" else value

    _refused_op({"op": "replace", "path": path, "value": operation_value}, "invalidValue")


@pytest.mark.parametrize(
    "value",
    [
        "viewer",
        None,
        {"value": "viewer"},
        [],
        ["viewer"],
        [None],
        [{"primary": True}],
        [{"value": 5}],
        [{"value": None}],
        [{"value": "admin"}, {"value": "viewer"}],
        [{"value": "admin", "primary": True}, {"value": "viewer"}],
        [{"value": "viewer", "primary": True}, {"value": "owner"}],
    ],
)
def test_roles_path_refuses_a_bad_entry_list(value: object) -> None:
    _refused_op({"op": "replace", "path": "roles", "value": value}, "invalidValue")


@pytest.mark.parametrize("value", [["viewer"], [{"value": "viewer"}], {"value": "viewer"}, 5])
def test_primary_filter_path_needs_a_string_value(value: object) -> None:
    _refused_op({"op": "replace", "path": ROLES_PRIMARY, "value": value}, "invalidValue")


@pytest.mark.parametrize(
    "path",
    [
        'roles[primary eq "False"].value',
        "roles[primary eq True].value",
        'roles[value eq "admin"].value',
        'roles[primary eq "True"]',
        'roles[primary eq "True"].display',
        "roles.value",
    ],
)
def test_other_role_paths_are_invalid_paths(path: str) -> None:
    _refused_op({"op": "replace", "path": path, "value": "viewer"}, "invalidPath")


def test_role_in_a_pathless_value_object_is_refused() -> None:
    _refused_op(
        {"op": "replace", "value": {"roles": [{"value": "viewer", "primary": True}]}},
        "invalidPath",
    )


def test_role_helpers_resolve_exact_names_only() -> None:
    assert role_from_name("admin") is OrgRole.ADMIN
    assert role_from_entries([{"value": "viewer"}]) is OrgRole.VIEWER
    with pytest.raises(PatchError):
        role_from_name("ADMIN")
    with pytest.raises(PatchError):
        role_from_entries([])


# --- both providers, whole requests --------------------------------------------------------


def test_okta_deactivation_request() -> None:
    change = parse_patch(_body({"op": "replace", "value": {"active": False}}))

    assert change == PatchChange(active=False)


def test_entra_deactivation_request() -> None:
    change = parse_patch(_body({"op": "Replace", "path": "active", "value": "False"}))

    assert change == PatchChange(active=False)


def test_entra_multi_operation_request() -> None:
    primary_developer = [{"value": "developer", "primary": True}]

    change = parse_patch(
        _body(
            {"op": "Replace", "path": "active", "value": "True"},
            {"op": "Add", "path": "roles", "value": primary_developer},
            {"op": "Replace", "path": "externalId", "value": "ext-7"},
            {"op": "Remove", "path": "externalId"},
        )
    )

    assert change == PatchChange(active=True, role=OrgRole.DEVELOPER, clear_external_id=True)


# --- atomic folding -------------------------------------------------------------------------


def test_operations_fold_into_one_change() -> None:
    change = parse_patch(
        _body(
            {"op": "replace", "path": "active", "value": "True"},
            {"op": "replace", "path": ROLES_PRIMARY, "value": "admin"},
            {"op": "replace", "value": {"externalId": "ext-2", "displayName": "Ada"}},
            {"op": "replace", "path": "userName", "value": "ada@example.com"},
        )
    )

    assert change == PatchChange(
        active=True,
        role=OrgRole.ADMIN,
        external_id="ext-2",
        display_name="Ada",
        user_name="ada@example.com",
    )


def test_a_later_operation_wins_for_the_same_field() -> None:
    change = parse_patch(
        _body(
            {"op": "replace", "path": "active", "value": True},
            {"op": "replace", "path": "active", "value": "False"},
            {"op": "replace", "path": "roles", "value": [{"value": "admin"}]},
            {"op": "add", "path": ROLES_PRIMARY, "value": "viewer"},
            {"op": "replace", "path": "externalId", "value": "first"},
            {"op": "replace", "path": "externalId", "value": "second"},
        )
    )

    assert change == PatchChange(active=False, role=OrgRole.VIEWER, external_id="second")


def test_remove_after_replace_clears_the_external_id() -> None:
    change = parse_patch(
        _body(
            {"op": "replace", "path": "externalId", "value": "ext-1"},
            {"op": "remove", "path": "externalId"},
        )
    )

    assert change.clear_external_id is True
    assert change.external_id is None


def test_replace_after_remove_sets_the_external_id() -> None:
    change = parse_patch(
        _body(
            {"op": "remove", "path": "externalId"},
            {"op": "replace", "path": "externalId", "value": "ext-2"},
        )
    )

    assert change.clear_external_id is False
    assert change.external_id == "ext-2"


def test_a_refused_operation_refuses_the_whole_patch() -> None:
    body = _body(
        {"op": "replace", "path": "active", "value": "False"},
        {"op": "replace", "path": ROLES_PRIMARY, "value": "admin"},
        {"op": "replace", "path": "password", "value": "x"},
    )
    before = copy.deepcopy(body)

    error = _refusal(body)

    assert error.scim_type == "invalidPath"
    assert error.message.startswith("Operation 3: ")
    assert body == before


@pytest.mark.parametrize(
    "bad",
    [
        {"op": "replace", "path": "active", "value": "maybe"},
        {"op": "remove", "path": "displayName"},
        {"op": "add", "path": "externalId", "value": "ext"},
        {"op": "move", "path": "active"},
        "replace",
    ],
)
def test_a_bad_operation_after_good_ones_returns_no_partial_change(bad: object) -> None:
    good = {"op": "replace", "path": "externalId", "value": "ext-1"}
    also_good = {"op": "replace", "path": "active", "value": False}

    with pytest.raises(PatchError):
        parse_patch(_body(good, also_good, bad))


def test_a_bad_first_operation_is_reported_as_operation_one() -> None:
    error = _refusal(_body({"op": "bogus"}, {"op": "replace", "path": "active", "value": True}))

    assert error.message.startswith("Operation 1: ")


# --- refused operations ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "emails",
        'emails[type eq "work"].value',
        "name.givenName",
        "name.formatted",
        "password",
        "groups",
        "meta",
        "id",
        "active.value",
        "urn:ietf:params:scim:schemas:core:2.0:User:userName",
        "uſerName",
        "",
        "   ",
        5,
        ["active"],
        {"path": "active"},
        True,
    ],
)
def test_replace_of_an_unsupported_path_is_an_invalid_path(path: object) -> None:
    _refused_op({"op": "replace", "path": path, "value": "x"}, "invalidPath")


@pytest.mark.parametrize(
    "path",
    ["active", "externalId", "displayName", "name", "userName", "emails", "password"],
)
def test_add_of_anything_but_roles_is_an_invalid_path(path: str) -> None:
    _refused_op({"op": "add", "path": path, "value": "x"}, "invalidPath")


def test_add_without_a_path_is_an_invalid_path() -> None:
    _refused_op({"op": "add", "value": {"externalId": "ext-1"}}, "invalidPath")
    _refused_op({"op": "Add", "value": {"active": False}}, "invalidPath")


@pytest.mark.parametrize(
    "path",
    [
        None,
        "active",
        "roles",
        ROLES_PRIMARY,
        "displayName",
        "userName",
        "name",
        "emails",
        'emails[type eq "work"]',
        "password",
        "",
        5,
    ],
)
def test_remove_of_anything_but_external_id_is_an_invalid_path(path: object) -> None:
    operation: dict[str, object] = {"op": "remove"}
    if path is not None:
        operation["path"] = path

    _refused_op(operation, "invalidPath")


@pytest.mark.parametrize("value", ["x", ["x"], 5, None, {}])
def test_pathless_replace_needs_a_non_empty_value_object(value: object) -> None:
    _refused_op({"op": "replace", "value": value}, "invalidValue")


def test_pathless_replace_without_a_value_is_refused() -> None:
    _refused_op({"op": "replace"}, "invalidValue")


@pytest.mark.parametrize(
    "value",
    [
        {"emails": [{"value": "a@example.com"}]},
        {"password": "x"},
        {"groups": []},
        {"name.givenName": "Ada"},
        {"active": False, "password": "x"},
        {"externalId": "ext", "meta": {}},
    ],
)
def test_pathless_replace_of_an_unsupported_attribute_is_an_invalid_path(value: object) -> None:
    _refused_op({"op": "replace", "value": value}, "invalidPath")


@pytest.mark.parametrize(
    "op",
    [
        "move",
        "test",
        "copy",
        "set",
        "",
        " replace",
        "replace ",
        "rеplace",
        None,
        5,
        ["replace"],
    ],
)
def test_an_unsupported_operation_name_is_an_invalid_value(op: object) -> None:
    _refused_op({"op": op, "path": "active", "value": True}, "invalidValue")


def test_a_missing_operation_name_is_an_invalid_value() -> None:
    _refused_op({"path": "active", "value": True}, "invalidValue")


@pytest.mark.parametrize("operation", ["replace", None, 5, ["replace"], []])
def test_an_operation_that_is_not_an_object_is_invalid_syntax(operation: object) -> None:
    _refused_op(operation, "invalidSyntax")


ACTIVE_OPERATION = {"op": "replace", "path": "active", "value": True}


@pytest.mark.parametrize(
    "body",
    [
        None,
        [],
        "x",
        5,
        {},
        {"Operations": [ACTIVE_OPERATION]},
        {"schemas": [], "Operations": [ACTIVE_OPERATION]},
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "Operations": [ACTIVE_OPERATION],
        },
        {"schemas": PATCH_OP_SCHEMA, "Operations": [ACTIVE_OPERATION]},
        {"schemas": [PATCH_OP_SCHEMA]},
        {"schemas": [PATCH_OP_SCHEMA], "Operations": []},
        {"schemas": [PATCH_OP_SCHEMA], "Operations": None},
        {"schemas": [PATCH_OP_SCHEMA], "Operations": "replace"},
        {"schemas": [PATCH_OP_SCHEMA], "Operations": ACTIVE_OPERATION},
        {"schemas": [PATCH_OP_SCHEMA], "operations": [ACTIVE_OPERATION]},
    ],
)
def test_a_malformed_envelope_is_invalid_syntax(body: object) -> None:
    assert _refusal(body).scim_type == "invalidSyntax"


# --- error and result shape -----------------------------------------------------------------


def test_patch_error_is_a_400_validation_failure() -> None:
    error = _refusal(_body({"op": "bogus"}))

    assert isinstance(error, ValidationFailed)
    assert error.status == 400


def test_refusals_do_not_repeat_request_values() -> None:
    secret = "s3cret-value"
    refusals = [
        _refusal(_body({"op": "replace", "path": "active", "value": secret})),
        _refusal(_body({"op": "replace", "path": "roles", "value": [{"value": secret}]})),
        _refusal(_body({"op": "replace", "path": ROLES_PRIMARY, "value": secret})),
        _refusal(_body({"op": "replace", "value": {"name": {secret: "x"}}})),
        _refusal(_body({"op": secret, "path": "active", "value": True})),
        _refusal(_body({"op": "replace", "value": {secret: "x"}})),
    ]

    assert all(secret not in error.message for error in refusals)


def test_an_unsupported_path_is_echoed_clipped() -> None:
    error = _refusal(_body({"op": "replace", "path": "p" * 500, "value": "x"}))

    assert "p" * 60 in error.message
    assert "p" * 61 not in error.message


def test_the_change_set_is_immutable() -> None:
    change = parse_patch(_body({"op": "replace", "path": "active", "value": False}))

    with pytest.raises(dataclasses.FrozenInstanceError):
        change.active = True  # type: ignore[misc]
