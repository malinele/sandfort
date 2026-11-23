"""SCIM User resources: the mapping between a member and the SCIM shape, in both directions.

Pure functions over domain objects and plain values, no http routing, no database
(``docs/scim-design.md``, Attribute mapping and Filter and pagination).

Out: ``member_to_resource`` renders a ``Member`` (user plus role and external id in one org) as a
User resource. ``id`` is ``User.id``, ``userName`` and the one ``emails`` entry come from the
lowercased email, ``displayName`` and ``name.formatted`` from ``User.display_name``, ``active``
is true unless the global ``User.disabled_at`` is set, ``roles`` is one primary entry and
``meta`` carries ``resourceType``, ``created`` and ``location`` (no ``lastModified``, no
version). ``meta.created`` is the creation time of the user row, which the ``Member`` carries.

In: ``parse_user_resource`` validates a create or replace body and returns a ``UserInput``.
Absent values are ``None`` so the caller decides: no role on create means the configured
default, no role on replace keeps the current one. ``ensure_unchanged`` and
``ensure_patch_unchanged`` apply the immutability rule for ``userName``, ``displayName`` and
``name`` against the stored user: an unchanged value is a no-op, a different one is
``mutability``. Refusal messages never repeat a request value.

``list_response`` slices a member list in memory: ``startIndex`` is 1-based (lower values are 1),
``count`` defaults to and is capped at ``SCIM_MAX_COUNT``, ``count=0`` returns ``totalResults``
and no resources.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from sandfort.api.scim.errors import MUTABILITY, ScimValidationError
from sandfort.api.scim.patch import (
    INVALID_SYNTAX,
    INVALID_VALUE,
    MAX_EXTERNAL_ID_LENGTH,
    PatchChange,
    role_from_entries,
)
from sandfort.domain.user import OrgRole, User
from sandfort.services.user_admin import Member

USER_SCHEMA: Final = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_RESPONSE_SCHEMA: Final = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_MEDIA_TYPE: Final = "application/scim+json"
USER_RESOURCE_TYPE: Final = "User"
SCIM_MAX_COUNT: Final = 100
FIRST_INDEX: Final = 1


@dataclass(frozen=True, slots=True)
class UserInput:
    """A validated create or replace body; ``None`` means the request did not carry the value.

    ``user_name`` is stripped and lowercased. ``display_name`` is the one the request named
    (``displayName``, else ``name.formatted``, else given plus family name).
    """

    user_name: str
    display_name: str | None = None
    role: OrgRole | None = None
    external_id: str | None = None
    active: bool | None = None

    @property
    def new_display_name(self) -> str:
        """The display name for a new user: the requested one, else the ``userName`` local part."""
        return self.display_name or self.user_name.partition("@")[0]


@dataclass(frozen=True, slots=True)
class PageWindow:
    """The effective page: ``start_index`` is 1-based and ``count`` is already capped."""

    start_index: int
    count: int


def member_to_resource(member: Member, *, base_url: str) -> dict[str, Any]:
    """Render ``member`` as a SCIM User; ``base_url`` is the ``/scim/v2`` URL of this server."""
    user = member.user
    resource: dict[str, Any] = {"schemas": [USER_SCHEMA], "id": user.id}
    if member.external_id is not None:
        resource["externalId"] = member.external_id
    resource.update(
        {
            "userName": user.email,
            "name": {"formatted": user.display_name},
            "displayName": user.display_name,
            "emails": [{"value": user.email, "type": "work", "primary": True}],
            "active": user.disabled_at is None,
            "roles": [{"value": member.role.value, "primary": True}],
            "meta": {
                "resourceType": USER_RESOURCE_TYPE,
                "created": _timestamp(user.created_at),
                "location": f"{base_url.rstrip('/')}/Users/{user.id}",
            },
        }
    )
    return resource


def parse_user_resource(body: object) -> UserInput:
    """Validate a decoded User body (create or replace) and return what it asks for."""
    if not isinstance(body, Mapping):
        raise ScimValidationError(INVALID_SYNTAX, "request body must be a JSON object")
    schemas = body.get("schemas")
    if not isinstance(schemas, list) or USER_SCHEMA not in schemas:
        raise ScimValidationError(INVALID_SYNTAX, f"schemas must contain {USER_SCHEMA}")
    user_name = _user_name(body.get("userName"))
    _check_emails(body.get("emails"), user_name)
    return UserInput(
        user_name=user_name,
        display_name=_requested_display_name(body),
        role=_requested_role(body.get("roles")),
        external_id=_requested_external_id(body.get("externalId")),
        active=_requested_active(body.get("active")),
    )


def ensure_unchanged(
    user: User, *, user_name: str | None = None, display_name: str | None = None
) -> None:
    """Refuse a requested ``userName`` or display name that differs from the stored user.

    The user row is shared by every org the person belongs to, so one org's provider cannot
    rewrite it. A value equal to the stored one is accepted as a no-op.
    """
    if user_name is not None and user_name.strip().lower() != user.email:
        raise ScimValidationError(MUTABILITY, "userName is immutable after create")
    if display_name is not None and display_name.strip() != user.display_name:
        raise ScimValidationError(MUTABILITY, "displayName and name are immutable after create")


def ensure_patch_unchanged(user: User, change: PatchChange) -> None:
    """Apply ``ensure_unchanged`` to the ``userName``, ``displayName`` and ``name`` of a patch."""
    ensure_unchanged(user, user_name=change.user_name, display_name=change.display_name)
    if change.name is not None:
        name = change.name
        text = _name_text(name.formatted, name.given_name, name.family_name)
        ensure_unchanged(user, display_name=text)


def page_window(start_index: int | None, count: int | None) -> PageWindow:
    """Clamp the paging parameters: start at 1 or later, 0 to ``SCIM_MAX_COUNT`` items."""
    start = FIRST_INDEX if start_index is None else max(start_index, FIRST_INDEX)
    size = SCIM_MAX_COUNT if count is None else min(max(count, 0), SCIM_MAX_COUNT)
    return PageWindow(start_index=start, count=size)


def list_response(
    members: Sequence[Member],
    *,
    base_url: str,
    start_index: int | None = None,
    count: int | None = None,
) -> dict[str, Any]:
    """A ``ListResponse`` with the requested page of ``members`` rendered as User resources.

    ``totalResults`` counts every member, ``startIndex`` is the effective 1-based start and
    ``itemsPerPage`` the number of resources returned. A start past the end is an empty page.
    """
    window = page_window(start_index, count)
    offset = window.start_index - FIRST_INDEX
    page = members[offset : offset + window.count]
    resources = [member_to_resource(member, base_url=base_url) for member in page]
    return list_envelope(resources, total=len(members), start_index=window.start_index)


def list_envelope(
    resources: Sequence[Mapping[str, Any]], *, total: int, start_index: int = FIRST_INDEX
) -> dict[str, Any]:
    """The ``ListResponse`` envelope around already rendered ``resources``."""
    return {
        "schemas": [LIST_RESPONSE_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": len(resources),
        "Resources": list(resources),
    }


def _timestamp(value: datetime) -> str:
    """ISO 8601 in UTC with a ``Z`` suffix; a naive value is taken as UTC."""
    moment = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return moment.isoformat().replace("+00:00", "Z")


def _invalid(message: str) -> ScimValidationError:
    return ScimValidationError(INVALID_VALUE, message)


def _user_name(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _invalid("userName is required and must be a non-empty string")
    return value.strip().lower()


def _optional_text(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise _invalid(f"{label} must be a string")
    return value.strip() or None


def _name_text(formatted: str | None, given: str | None, family: str | None) -> str | None:
    """``formatted``, else the given and family names joined by a space, else ``None``."""
    if formatted:
        return formatted.strip()
    joined = " ".join(part.strip() for part in (given, family) if part and part.strip())
    return joined or None


def _requested_display_name(body: Mapping[Any, Any]) -> str | None:
    display_name = _optional_text(body.get("displayName"), "displayName")
    if display_name is not None:
        return display_name
    name = body.get("name")
    if name is None:
        return None
    if not isinstance(name, Mapping):
        raise _invalid("name must be an object")
    return _name_text(
        _optional_text(name.get("formatted"), "name.formatted"),
        _optional_text(name.get("givenName"), "name.givenName"),
        _optional_text(name.get("familyName"), "name.familyName"),
    )


def _check_emails(value: object, user_name: str) -> None:
    """A work or primary ``emails`` value must equal ``userName``; other entries are ignored."""
    if value is None:
        return
    if not isinstance(value, list):
        raise _invalid("emails must be a list")
    for entry in value:
        address = entry.get("value") if isinstance(entry, Mapping) else None
        if not isinstance(address, str):
            raise _invalid("every emails entry needs a string value")
        if _is_work_or_primary(entry) and address.strip().lower() != user_name:
            raise _invalid("the work or primary email must equal userName")


def _is_work_or_primary(entry: Mapping[Any, Any]) -> bool:
    kind, primary = entry.get("type"), entry.get("primary")
    is_work = isinstance(kind, str) and kind.lower() == "work"
    is_primary = primary is True or (isinstance(primary, str) and primary.lower() == "true")
    return is_work or is_primary


def _requested_role(value: object) -> OrgRole | None:
    if value is None or value == []:
        return None
    return role_from_entries(value)


def _requested_external_id(value: object) -> str | None:
    text = _optional_text(value, "externalId")
    if text is not None and len(text) > MAX_EXTERNAL_ID_LENGTH:
        raise _invalid(f"externalId is longer than {MAX_EXTERNAL_ID_LENGTH}")
    return text


def _requested_active(value: object) -> bool | None:
    if value is None or isinstance(value, bool):
        return value
    raise _invalid("active must be a boolean")
