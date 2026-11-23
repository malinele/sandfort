"""SCIM discovery documents: ServiceProviderConfig, ResourceTypes and Schemas.

Pure builders, no http routing, no database (``docs/scim-design.md``, Discovery). Each call
returns fresh dicts, so a caller can never mutate shared state. The documents are honest about
the limits of this first version: ``patch`` is supported, ``bulk``, ``changePassword``,
``sort`` and ``etag`` are not, ``filter`` is supported with ``maxResults`` equal to the page
cap and its only form is ``userName eq "<value>"``. ``User`` is the only resource type and the
only schema: there is no ``Group``, no enterprise extension and no ``lastModified``, and the
documents say so by omission.
"""

from collections.abc import Sequence
from typing import Any, Final

from sandfort.api.scim.resources import (
    SCIM_MAX_COUNT,
    USER_RESOURCE_TYPE,
    USER_SCHEMA,
    list_envelope,
)
from sandfort.domain.user import OrgRole

SERVICE_PROVIDER_CONFIG_SCHEMA: Final = (
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
)
RESOURCE_TYPE_SCHEMA: Final = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
SCHEMA_SCHEMA: Final = "urn:ietf:params:scim:schemas:core:2.0:Schema"
SUPPORTED_FILTER: Final = 'userName eq "<value>"'
USERS_ENDPOINT: Final = "/Users"

_READ_WRITE: Final = "readWrite"
_READ_ONLY: Final = "readOnly"
_IMMUTABLE: Final = "immutable"
_BEARER_SPEC_URI: Final = "https://www.rfc-editor.org/info/rfc6750"


def service_provider_config(base_url: str) -> dict[str, Any]:
    """The ServiceProviderConfig document; ``base_url`` is the ``/scim/v2`` URL of this server."""
    return {
        "schemas": [SERVICE_PROVIDER_CONFIG_SCHEMA],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": SCIM_MAX_COUNT},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "SCIM bearer token",
                "description": "A per-organization SCIM token sent as an Authorization: Bearer "
                "header. API keys and session tokens are not accepted.",
                "specUri": _BEARER_SPEC_URI,
                "primary": True,
            }
        ],
        "meta": _meta("ServiceProviderConfig", f"{_root(base_url)}/ServiceProviderConfig"),
    }


def resource_types(base_url: str) -> dict[str, Any]:
    """The ResourceTypes ListResponse: ``User`` at ``/Users`` and nothing else."""
    return list_envelope([_user_resource_type(base_url)], total=1)


def schemas(base_url: str) -> dict[str, Any]:
    """The Schemas ListResponse: the core user schema and nothing else."""
    return list_envelope([_user_schema(base_url)], total=1)


def _root(base_url: str) -> str:
    return base_url.rstrip("/")


def _meta(resource_type: str, location: str) -> dict[str, str]:
    return {"resourceType": resource_type, "location": location}


def _user_resource_type(base_url: str) -> dict[str, Any]:
    return {
        "schemas": [RESOURCE_TYPE_SCHEMA],
        "id": USER_RESOURCE_TYPE,
        "name": USER_RESOURCE_TYPE,
        "endpoint": USERS_ENDPOINT,
        "description": "A member of the organization. The only supported filter is "
        f"{SUPPORTED_FILTER}.",
        "schema": USER_SCHEMA,
        "meta": _meta("ResourceType", f"{_root(base_url)}/ResourceTypes/{USER_RESOURCE_TYPE}"),
    }


def _user_schema(base_url: str) -> dict[str, Any]:
    return {
        "schemas": [SCHEMA_SCHEMA],
        "id": USER_SCHEMA,
        "name": USER_RESOURCE_TYPE,
        "description": "Organization member. userName, displayName, name and emails are "
        "immutable after create because the user is shared by every organization.",
        "attributes": _user_attributes(),
        "meta": _meta("Schema", f"{_root(base_url)}/Schemas/{USER_SCHEMA}"),
    }


def _user_attributes() -> list[dict[str, Any]]:
    return [
        _attribute(
            "id",
            "string",
            "Sandfort user id, stable across deactivation cycles.",
            mutability=_READ_ONLY,
            case_exact=True,
            uniqueness="server",
        ),
        _attribute(
            "externalId",
            "string",
            "Identifier assigned by the provider, unique within the organization.",
            case_exact=True,
        ),
        _attribute(
            "userName",
            "string",
            "The lowercased email. The only supported filter is " + SUPPORTED_FILTER + ".",
            mutability=_IMMUTABLE,
            required=True,
            uniqueness="server",
        ),
        _name_attribute(),
        _attribute(
            "displayName",
            "string",
            "Display name of the user.",
            mutability=_IMMUTABLE,
        ),
        _emails_attribute(),
        _attribute(
            "active",
            "boolean",
            "False removes the membership; the user can be created again.",
        ),
        _roles_attribute(),
        _meta_attribute(),
    ]


def _name_attribute() -> dict[str, Any]:
    parts = [
        _attribute(part, "string", f"The {label} name.", mutability=_IMMUTABLE)
        for part, label in (
            ("formatted", "full formatted"),
            ("givenName", "given"),
            ("familyName", "family"),
        )
    ]
    return _attribute(
        "name",
        "complex",
        "Name of the user; only formatted is returned.",
        mutability=_IMMUTABLE,
        sub_attributes=parts,
    )


def _emails_attribute() -> dict[str, Any]:
    parts = [
        _attribute("value", "string", "The email address.", mutability=_IMMUTABLE),
        _attribute(
            "type", "string", "Always work.", mutability=_IMMUTABLE, canonical_values=["work"]
        ),
        _attribute("primary", "boolean", "Always true.", mutability=_IMMUTABLE),
    ]
    return _attribute(
        "emails",
        "complex",
        "One entry derived from userName; a work or primary value in a request must equal it.",
        mutability=_IMMUTABLE,
        multi_valued=True,
        sub_attributes=parts,
    )


def _roles_attribute() -> dict[str, Any]:
    parts = [
        _attribute(
            "value",
            "string",
            "The organization role.",
            canonical_values=[role.value for role in OrgRole],
        ),
        _attribute("primary", "boolean", "Always true; one role per member."),
    ]
    return _attribute(
        "roles",
        "complex",
        "One role. Without a role a created member gets the configured default role.",
        multi_valued=True,
        sub_attributes=parts,
    )


def _meta_attribute() -> dict[str, Any]:
    parts = [
        _attribute("resourceType", "string", "Always User.", mutability=_READ_ONLY),
        _attribute("created", "dateTime", "Creation time of the user.", mutability=_READ_ONLY),
        _attribute("location", "reference", "URL of the resource.", mutability=_READ_ONLY),
    ]
    return _attribute(
        "meta",
        "complex",
        "Resource metadata; there is no lastModified and no version.",
        mutability=_READ_ONLY,
        sub_attributes=parts,
    )


def _attribute(
    name: str,
    kind: str,
    description: str,
    *,
    mutability: str = _READ_WRITE,
    required: bool = False,
    multi_valued: bool = False,
    case_exact: bool = False,
    uniqueness: str = "none",
    sub_attributes: Sequence[dict[str, Any]] | None = None,
    canonical_values: Sequence[str] | None = None,
) -> dict[str, Any]:
    attribute: dict[str, Any] = {
        "name": name,
        "type": kind,
        "multiValued": multi_valued,
        "description": description,
        "required": required,
        "caseExact": case_exact,
        "mutability": mutability,
        "returned": "default",
        "uniqueness": uniqueness,
    }
    if sub_attributes is not None:
        attribute["subAttributes"] = list(sub_attributes)
    if canonical_values is not None:
        attribute["canonicalValues"] = list(canonical_values)
    return attribute
