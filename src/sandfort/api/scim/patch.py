"""SCIM PATCH parsing: fold PatchOp operations into one normalized change set.

Pure functions, no database, no http, no settings (``docs/scim-design.md``, PATCH shapes).
All operations are parsed first and folded in order into one immutable ``PatchChange``; a
single refused operation raises and no partial change exists, which is what makes the patch
atomic. Accepted shapes, from Okta (value object without ``path``) and Entra (``path``, and
booleans that may arrive as the strings ``"True"`` and ``"False"``):

1. ``replace`` of ``active``, by path or as ``{"active": ...}`` in an object value.
2. ``replace`` of ``externalId``, ``displayName``, ``name`` or ``userName``, by path or in an
   object value. ``remove`` is accepted for ``externalId`` only.
3. ``add`` or ``replace`` of the role: path ``roles`` with a list of role objects, or path
   ``roles[primary eq "True"].value`` with a string.

Operation names and attribute names are matched case-insensitively. Everything else is refused
with scimType ``invalidPath`` or ``invalidValue`` (``invalidSyntax`` for a malformed envelope).
The immutability rule for ``displayName``, ``name`` and ``userName`` (``mutability``) needs the
stored values, so it is applied by the caller on the requested values returned here. Refusal
messages never repeat a request value; only an unsupported ``path`` is echoed, clipped.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from sandfort.domain.user import OrgRole
from sandfort.errors import ValidationFailed

PATCH_OP_SCHEMA: Final = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
MAX_EXTERNAL_ID_LENGTH: Final = 255

INVALID_SYNTAX: Final = "invalidSyntax"
INVALID_PATH: Final = "invalidPath"
INVALID_VALUE: Final = "invalidValue"

_OPERATIONS: Final = frozenset({"add", "replace", "remove"})
_ATTRIBUTES: Final = {
    "active": "active",
    "externalid": "externalId",
    "displayname": "displayName",
    "name": "name",
    "username": "userName",
}
_NAME_KEYS: Final = ("formatted", "givenName", "familyName")
_BOOLEANS: Final = {"true": True, "false": False}
_ROLE_NAMES: Final = frozenset(role.value for role in OrgRole)
_ROLES_PRIMARY_PATH: Final = re.compile(
    r'roles\[\s*primary\s+eq\s+"true"\s*\]\.value',
    re.IGNORECASE | re.ASCII,
)
_PATH_ECHO_LIMIT: Final = 60


class PatchError(ValidationFailed):
    """A PATCH body or operation is refused (HTTP 400); ``scim_type`` names the SCIM error."""

    def __init__(self, scim_type: str, message: str) -> None:
        super().__init__(message)
        self.scim_type = scim_type


@dataclass(frozen=True, slots=True)
class NameChange:
    """Requested ``name`` sub-attributes; ``None`` means the request did not carry it."""

    formatted: str | None = None
    given_name: str | None = None
    family_name: str | None = None


@dataclass(frozen=True, slots=True)
class PatchChange:
    """The normalized result of a PATCH; ``None`` / ``False`` mean "no change requested".

    ``external_id`` sets the value, ``clear_external_id`` clears it (never both). ``user_name``
    is as sent; compare it lowercased. ``display_name``, ``name`` and ``user_name`` are
    requested values that the caller checks against the immutable stored ones.
    """

    active: bool | None = None
    role: OrgRole | None = None
    external_id: str | None = None
    clear_external_id: bool = False
    display_name: str | None = None
    name: NameChange | None = None
    user_name: str | None = None


def parse_patch(body: object) -> PatchChange:
    """Validate a decoded PatchOp body and fold its operations into one ``PatchChange``."""
    change = PatchChange()
    for position, raw in enumerate(_operations(body), start=1):
        try:
            change = _merge(change, _parse_operation(raw))
        except PatchError as exc:
            raise PatchError(exc.scim_type, f"Operation {position}: {exc.message}") from exc
    return change


def role_from_entries(value: object) -> OrgRole:
    """Resolve a SCIM ``roles`` list to one ``OrgRole``.

    The list must be non-empty, every entry needs a string ``value`` and all entries must name
    the same role, so the primary entry and the only entry agree. More than one distinct value
    or a value outside ``OrgRole`` is ``invalidValue``.
    """
    if not isinstance(value, list) or not value:
        raise PatchError(INVALID_VALUE, "roles must be a non-empty list of role objects")
    names: list[str] = []
    for entry in value:
        name = entry.get("value") if isinstance(entry, Mapping) else None
        if not isinstance(name, str):
            raise PatchError(INVALID_VALUE, "every roles entry needs a string value")
        names.append(name)
    if len(set(names)) > 1:
        raise PatchError(INVALID_VALUE, "roles must name one role, not several")
    return role_from_name(names[0])


def role_from_name(value: object) -> OrgRole:
    """Return the ``OrgRole`` named exactly ``value`` or raise ``invalidValue``."""
    if not isinstance(value, str) or value not in _ROLE_NAMES:
        raise PatchError(INVALID_VALUE, "role must be admin, developer or viewer")
    return OrgRole(value)


def _operations(body: object) -> list[object]:
    if not isinstance(body, Mapping):
        raise PatchError(INVALID_SYNTAX, "request body must be a JSON object")
    schemas = body.get("schemas")
    if not isinstance(schemas, list) or PATCH_OP_SCHEMA not in schemas:
        raise PatchError(INVALID_SYNTAX, f"schemas must contain {PATCH_OP_SCHEMA}")
    operations = body.get("Operations")
    if not isinstance(operations, list) or not operations:
        raise PatchError(INVALID_SYNTAX, "Operations must be a non-empty list")
    return operations


def _parse_operation(raw: object) -> PatchChange:
    if not isinstance(raw, Mapping):
        raise PatchError(INVALID_SYNTAX, "operation must be a JSON object")
    op = raw.get("op")
    name = _fold(op) if isinstance(op, str) else ""
    if name not in _OPERATIONS:
        raise PatchError(INVALID_VALUE, "op must be add, replace or remove")
    path = _path(raw)
    if name == "remove":
        return _remove(path)
    if path is None:
        return _without_path(name, raw.get("value"))
    return _with_path(name, path, raw.get("value"))


def _path(operation: Mapping[object, object]) -> str | None:
    path = operation.get("path")
    if path is None:
        return None
    if not isinstance(path, str) or not path.strip():
        raise PatchError(INVALID_PATH, "path must be a non-empty string")
    return path.strip()


def _remove(path: str | None) -> PatchChange:
    if path is None or _attribute(path) != "externalId":
        raise PatchError(INVALID_PATH, "remove is supported for externalId only")
    return PatchChange(clear_external_id=True)


def _without_path(op: str, value: object) -> PatchChange:
    if op != "replace":
        raise PatchError(INVALID_PATH, "add is supported for roles only, with a roles path")
    if not isinstance(value, Mapping) or not value:
        raise PatchError(INVALID_VALUE, "value must be a non-empty object when path is absent")
    change = PatchChange()
    for key, item in value.items():
        attribute = _attribute(key) if isinstance(key, str) else None
        if attribute is None:
            raise PatchError(INVALID_PATH, "value names an attribute that cannot be patched")
        change = _merge(change, _attribute_change(attribute, item))
    return change


def _with_path(op: str, path: str, value: object) -> PatchChange:
    if _fold(path) == "roles":
        return PatchChange(role=role_from_entries(value))
    if _ROLES_PRIMARY_PATH.fullmatch(path):
        return PatchChange(role=role_from_name(value))
    attribute = _attribute(path)
    if op == "add" or attribute is None:
        raise PatchError(INVALID_PATH, f"path {_echo(path)} is not supported for {op}")
    return _attribute_change(attribute, value)


def _attribute_change(attribute: str, value: object) -> PatchChange:
    match attribute:
        case "active":
            return PatchChange(active=_boolean(value))
        case "externalId":
            return PatchChange(external_id=_external_id(value))
        case "displayName":
            return PatchChange(display_name=_text(value, attribute))
        case "userName":
            return PatchChange(user_name=_text(value, attribute))
        case "name":
            return PatchChange(name=_name(value))
    raise PatchError(INVALID_PATH, "attribute cannot be patched")


def _boolean(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.isascii() and value.lower() in _BOOLEANS:
        return _BOOLEANS[value.lower()]
    raise PatchError(INVALID_VALUE, "active must be a boolean or the string True or False")


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PatchError(INVALID_VALUE, f"{label} must be a non-empty string")
    return value


def _external_id(value: object) -> str:
    text = _text(value, "externalId")
    if len(text) > MAX_EXTERNAL_ID_LENGTH:
        raise PatchError(INVALID_VALUE, f"externalId is longer than {MAX_EXTERNAL_ID_LENGTH}")
    return text


def _name(value: object) -> NameChange:
    if not isinstance(value, Mapping) or not value:
        raise PatchError(INVALID_VALUE, "name must be a non-empty object")
    if any(key not in _NAME_KEYS for key in value):
        raise PatchError(INVALID_VALUE, "name supports formatted, givenName and familyName only")
    parts = [value.get(key) for key in _NAME_KEYS]
    if any(part is not None and not isinstance(part, str) for part in parts):
        raise PatchError(INVALID_VALUE, "name sub-attributes must be strings")
    formatted, given_name, family_name = (part or None for part in parts)
    if formatted is None and given_name is None and family_name is None:
        raise PatchError(INVALID_VALUE, "name must carry at least one non-empty sub-attribute")
    return NameChange(formatted=formatted, given_name=given_name, family_name=family_name)


def _merge(base: PatchChange, delta: PatchChange) -> PatchChange:
    """Fold ``delta`` over ``base``: a later operation wins for the field it names."""
    external_id, clear = base.external_id, base.clear_external_id
    if delta.external_id is not None or delta.clear_external_id:
        external_id, clear = delta.external_id, delta.clear_external_id
    return PatchChange(
        active=base.active if delta.active is None else delta.active,
        role=base.role if delta.role is None else delta.role,
        external_id=external_id,
        clear_external_id=clear,
        display_name=base.display_name if delta.display_name is None else delta.display_name,
        name=base.name if delta.name is None else delta.name,
        user_name=base.user_name if delta.user_name is None else delta.user_name,
    )


def _attribute(name: str) -> str | None:
    return _ATTRIBUTES.get(_fold(name))


def _fold(text: str) -> str:
    """Lowercase ASCII text; leave anything else alone so look-alikes never match."""
    return text.lower() if text.isascii() else text


def _echo(path: str) -> str:
    clipped = path if len(path) <= _PATH_ECHO_LIMIT else path[:_PATH_ECHO_LIMIT] + "..."
    return repr(clipped)
