"""SCIM slice seven: the static protocol documents, discovery and the error table.

Pure unit tests. Discovery (``docs/scim-design.md``, Discovery): no bulk, no etag, no sort, no
password change, no groups, no extensions, and ``userName eq`` as the single filter form.
Errors (same document, Errors): every row of the table maps to its status and scimType.
"""

import json
import logging
from typing import Any

import pytest
from fastapi.exceptions import RequestValidationError

from sandfort.api.errors import INTERNAL_MESSAGE
from sandfort.api.scim.discovery import (
    RESOURCE_TYPE_SCHEMA,
    SCHEMA_SCHEMA,
    SERVICE_PROVIDER_CONFIG_SCHEMA,
    SUPPORTED_FILTER,
    resource_types,
    schemas,
    service_provider_config,
)
from sandfort.api.scim.errors import (
    ERROR_SCHEMA,
    MUTABILITY,
    UNIQUENESS,
    ScimFailure,
    ScimValidationError,
    describe_failure,
)
from sandfort.api.scim.filters import parse_user_filter
from sandfort.api.scim.patch import INVALID_PATH, INVALID_SYNTAX, INVALID_VALUE, PatchError
from sandfort.api.scim.resources import LIST_RESPONSE_SCHEMA, SCIM_MAX_COUNT, USER_SCHEMA
from sandfort.errors import (
    Conflict,
    Forbidden,
    InvalidState,
    NotFound,
    PayloadTooLarge,
    RateLimited,
    Unauthorized,
    ValidationFailed,
)
from sandfort.services.api_key_admin import ScopeEscalation

BASE = "https://sf.example/scim/v2"
EXPECTED_ATTRIBUTES = [
    "id",
    "externalId",
    "userName",
    "name",
    "displayName",
    "emails",
    "active",
    "roles",
    "meta",
]


def user_schema() -> dict[str, Any]:
    (document,) = schemas(BASE)["Resources"]
    return document


def attribute(name: str) -> dict[str, Any]:
    (found,) = [item for item in user_schema()["attributes"] if item["name"] == name]
    return found


# --- ServiceProviderConfig ----------------------------------------------------------------


def test_service_provider_config_states_what_is_and_is_not_supported() -> None:
    config = service_provider_config(BASE)

    assert config["schemas"] == [SERVICE_PROVIDER_CONFIG_SCHEMA]
    assert config["patch"] == {"supported": True}
    assert config["filter"] == {"supported": True, "maxResults": SCIM_MAX_COUNT}
    assert config["bulk"]["supported"] is False
    assert config["etag"] == {"supported": False}
    assert config["sort"] == {"supported": False}
    assert config["changePassword"] == {"supported": False}


def test_the_filter_result_cap_is_one_hundred() -> None:
    assert service_provider_config(BASE)["filter"]["maxResults"] == 100


def test_bulk_advertises_no_operations() -> None:
    bulk = service_provider_config(BASE)["bulk"]

    assert (bulk["maxOperations"], bulk["maxPayloadSize"]) == (0, 0)


def test_one_bearer_token_authentication_scheme() -> None:
    (scheme,) = service_provider_config(BASE)["authenticationSchemes"]

    assert scheme["type"] == "oauthbearertoken"
    assert scheme["primary"] is True
    assert "API keys and session tokens are not accepted" in scheme["description"]


def test_service_provider_config_meta_points_at_itself() -> None:
    meta = service_provider_config(f"{BASE}/")["meta"]

    assert meta == {
        "resourceType": "ServiceProviderConfig",
        "location": f"{BASE}/ServiceProviderConfig",
    }


# --- ResourceTypes ------------------------------------------------------------------------


def test_resource_types_lists_user_at_users_and_nothing_else() -> None:
    document = resource_types(BASE)

    assert document["schemas"] == [LIST_RESPONSE_SCHEMA]
    assert [document[key] for key in ("totalResults", "startIndex", "itemsPerPage")] == [1, 1, 1]
    (user,) = document["Resources"]
    assert user["schemas"] == [RESOURCE_TYPE_SCHEMA]
    assert (user["id"], user["name"], user["endpoint"]) == ("User", "User", "/Users")
    assert user["schema"] == USER_SCHEMA
    assert user["meta"]["location"] == f"{BASE}/ResourceTypes/User"


def test_resource_types_name_the_single_filter_form_and_no_extensions() -> None:
    (user,) = resource_types(BASE)["Resources"]

    assert SUPPORTED_FILTER in user["description"]
    assert "schemaExtensions" not in user


# --- Schemas ------------------------------------------------------------------------------


def test_schemas_lists_only_the_core_user_schema() -> None:
    document = schemas(BASE)

    assert document["schemas"] == [LIST_RESPONSE_SCHEMA]
    assert document["totalResults"] == 1
    (core,) = document["Resources"]
    assert core["schemas"] == [SCHEMA_SCHEMA]
    assert core["id"] == USER_SCHEMA
    assert core["meta"]["location"] == f"{BASE}/Schemas/{USER_SCHEMA}"


def test_user_schema_attributes_match_the_mapping_table() -> None:
    names = [item["name"] for item in user_schema()["attributes"]]

    assert names == EXPECTED_ATTRIBUTES


@pytest.mark.parametrize(
    ("name", "mutability"),
    [
        ("id", "readOnly"),
        ("externalId", "readWrite"),
        ("userName", "immutable"),
        ("name", "immutable"),
        ("displayName", "immutable"),
        ("emails", "immutable"),
        ("active", "readWrite"),
        ("roles", "readWrite"),
        ("meta", "readOnly"),
    ],
)
def test_user_schema_declares_the_mutability(name: str, mutability: str) -> None:
    assert attribute(name)["mutability"] == mutability


def test_user_name_is_required_unique_and_names_the_single_filter_form() -> None:
    user_name = attribute("userName")

    assert user_name["required"] is True
    assert user_name["uniqueness"] == "server"
    assert SUPPORTED_FILTER in user_name["description"]


def test_roles_offer_exactly_the_three_org_roles() -> None:
    roles = attribute("roles")
    value = next(part for part in roles["subAttributes"] if part["name"] == "value")

    assert roles["multiValued"] is True
    assert value["canonicalValues"] == ["admin", "developer", "viewer"]


def test_meta_has_no_last_modified() -> None:
    names = [part["name"] for part in attribute("meta")["subAttributes"]]

    assert names == ["resourceType", "created", "location"]


def test_supported_filter_is_user_name_eq_only() -> None:
    assert SUPPORTED_FILTER == 'userName eq "<value>"'


# --- the documents say nothing about groups, bulk, etag or extensions ----------------------


def test_no_document_mentions_groups_or_extensions() -> None:
    documents = [service_provider_config(BASE), resource_types(BASE), schemas(BASE)]
    text = json.dumps(documents).lower()

    assert "group" not in text
    assert "enterprise" not in text
    assert "extension" not in text


def test_builders_return_fresh_documents_each_call() -> None:
    first = service_provider_config(BASE)
    first["bulk"]["supported"] = True
    first["authenticationSchemes"].clear()
    schemas(BASE)["Resources"][0]["attributes"].clear()

    second = service_provider_config(BASE)

    assert second["bulk"]["supported"] is False
    assert len(second["authenticationSchemes"]) == 1
    assert len(user_schema()["attributes"]) == len(EXPECTED_ATTRIBUTES)


def test_documents_round_trip_through_json_and_never_hold_a_token() -> None:
    documents = [service_provider_config(BASE), resource_types(BASE), schemas(BASE)]
    text = json.dumps(documents)

    assert json.loads(text) == documents
    assert "sf_scim_" not in text


# --- the error table ----------------------------------------------------------------------


def _filter_error() -> Exception:
    try:
        parse_user_filter('userName co "x"')
    except ValidationFailed as exc:
        return exc
    raise AssertionError("filter was accepted")


ERROR_TABLE = [
    pytest.param(Unauthorized("token revoked"), 401, None, "token revoked", id="unauthorized"),
    pytest.param(Forbidden("no scope"), 403, None, "no scope", id="forbidden"),
    pytest.param(ScopeEscalation("too much"), 403, None, "too much", id="scope-escalation"),
    pytest.param(NotFound("member gone"), 404, None, "member gone", id="not-found"),
    pytest.param(Conflict("already a member"), 409, UNIQUENESS, "already a member", id="conflict"),
    pytest.param(InvalidState("keep one admin"), 409, None, "keep one admin", id="last-admin"),
    pytest.param(ValidationFailed("bad email"), 400, INVALID_VALUE, "bad email", id="validation"),
    pytest.param(PatchError(INVALID_PATH, "bad path"), 400, INVALID_PATH, "bad path", id="path"),
    pytest.param(PatchError(INVALID_SYNTAX, "bad op"), 400, INVALID_SYNTAX, "bad op", id="syntax"),
    pytest.param(
        ScimValidationError(MUTABILITY, "immutable"), 400, MUTABILITY, "immutable", id="mutability"
    ),
    pytest.param(_filter_error(), 400, "invalidFilter", None, id="filter"),
    pytest.param(
        json.JSONDecodeError("Expecting value", "{", 1),
        400,
        INVALID_SYNTAX,
        "request body is not valid JSON",
        id="bad-json",
    ),
]


@pytest.mark.parametrize(("exc", "status", "scim_type", "detail"), ERROR_TABLE)
def test_every_row_of_the_error_table(
    exc: Exception, status: int, scim_type: str | None, detail: str | None
) -> None:
    failure = describe_failure(exc)

    assert (failure.status, failure.scim_type) == (status, scim_type)
    assert failure.detail == (detail or getattr(exc, "message", None))
    expected: dict[str, Any] = {"schemas": [ERROR_SCHEMA], "status": str(status)}
    if scim_type is not None:
        expected["scimType"] = scim_type
    assert failure.body() == {**expected, "detail": failure.detail}
    assert isinstance(failure.body()["status"], str)


def test_request_validation_is_invalid_value_and_never_echoes_the_input() -> None:
    issue = {
        "type": "missing",
        "loc": ("body", "userName"),
        "msg": "Field required",
        "input": {"token": "sf_scim_leak"},
    }
    second = {**issue, "loc": ("query", "count")}

    failure = describe_failure(RequestValidationError([issue, second]))

    assert (failure.status, failure.scim_type) == (400, INVALID_VALUE)
    assert failure.detail == "body.userName: Field required; query.count: Field required"
    assert "sf_scim_leak" not in failure.detail


def test_request_validation_reports_at_most_five_issues() -> None:
    issues = [{"type": "x", "loc": ("body", index), "msg": "bad"} for index in range(9)]

    failure = describe_failure(RequestValidationError(issues))

    assert failure.detail.count("bad") == 5


def test_request_validation_without_issues_has_a_generic_detail() -> None:
    failure = describe_failure(RequestValidationError([]))

    assert (failure.status, failure.scim_type) == (400, INVALID_VALUE)
    assert failure.detail == "request validation failed"


def test_unparsable_json_is_invalid_syntax() -> None:
    issues = [{"type": "json_invalid", "loc": ("body", 1), "msg": "JSON decode error"}]

    failure = describe_failure(RequestValidationError(issues))

    assert (failure.status, failure.scim_type) == (400, INVALID_SYNTAX)
    assert failure.detail == "request body is not valid JSON"


def test_any_other_exception_is_a_generic_500_and_the_cause_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "Bearer sf_scim_deadbeef_topsecret"

    with caplog.at_level(logging.ERROR, logger="sandfort.api.scim.errors"):
        failure = describe_failure(RuntimeError(secret))

    assert (failure.status, failure.scim_type, failure.detail) == (500, None, INTERNAL_MESSAGE)
    assert secret not in json.dumps(failure.body())
    assert [record.levelno for record in caplog.records] == [logging.ERROR]
    assert caplog.records[0].exc_info is not None


def test_a_platform_error_outside_the_table_is_a_generic_500() -> None:
    failure = describe_failure(PayloadTooLarge("body is 9 GiB"))

    assert (failure.status, failure.scim_type, failure.detail) == (500, None, INTERNAL_MESSAGE)


def test_rate_limiting_is_429_with_retry_after_and_no_scim_type() -> None:
    failure = describe_failure(RateLimited("slow down", retry_after_s=7))

    assert (failure.status, failure.scim_type, failure.detail) == (429, None, "slow down")
    assert failure.headers == {"Retry-After": "7"}
    assert failure.body()["status"] == "429"


def test_failure_body_omits_scim_type_when_there_is_none() -> None:
    assert ScimFailure(404, "gone").body() == {
        "schemas": [ERROR_SCHEMA],
        "status": "404",
        "detail": "gone",
    }
