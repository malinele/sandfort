"""Audit rows of the admin CLI's key and org provisioning (B6).

``bootstrap`` and ``create-org`` open an org's own audit chain: ``org.created`` first, then
``api_key.created`` for the first key, both through the caller's unit of work so they commit with
the org and the key (``AuditRecorder`` never commits). The actor is the ``platform_admin``
``sandfort-admin`` the other admin commands use; no API key id is invented. Details carry the
name, prefix and scopes only, never the plaintext key or its hash.
"""

from typing import Any

from sandfort.clock import SystemClock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType
from sandfort.domain.org import ApiKey, Org
from sandfort.domain.quota import OrgQuota
from sandfort.services.api_key_admin import KEY_CREATED, TARGET_TYPE
from sandfort.services.audit import AuditRecorder

ORG_CREATED = "org.created"
ORG_TARGET_TYPE = "organization"


def key_created_details(key: ApiKey) -> dict[str, Any]:
    """The ``api_key.created`` details of an admin-CLI key: metadata only, no secret."""
    return {
        "name": key.name,
        "prefix": key.prefix,
        "scopes": sorted(scope.value for scope in key.scopes),
        "sandbox_labels": None,
        "max_sandboxes": None,
        "shared_volume_labels": None,
        "expires_at": None,
        "is_platform_admin": key.is_platform_admin,
    }


async def record_key_created(uow: UnitOfWorkPort, key: ApiKey, *, actor_id: str) -> None:
    """Add the ``api_key.created`` row for ``key``; the caller commits."""
    await AuditRecorder(SystemClock()).record(
        uow,
        org_id=key.org_id,
        actor_type=ActorType.PLATFORM_ADMIN,
        actor_id=actor_id,
        action=KEY_CREATED,
        target_type=TARGET_TYPE,
        target_id=key.id,
        details=key_created_details(key),
    )


async def record_org_provisioned(
    uow: UnitOfWorkPort,
    org: Org,
    key: ApiKey,
    *,
    actor_id: str,
    created_via: str,
    default_quota: OrgQuota,
) -> None:
    """Add the genesis rows of ``org``'s chain: ``org.created``, then its first key's row.

    ``default_quota`` is recorded only when it differs from the unlimited default (the same
    condition under which a quota row is written). The caller commits.
    """
    quota = default_quota.model_dump() if default_quota != OrgQuota() else None
    await AuditRecorder(SystemClock()).record(
        uow,
        org_id=org.id,
        actor_type=ActorType.PLATFORM_ADMIN,
        actor_id=actor_id,
        action=ORG_CREATED,
        target_type=ORG_TARGET_TYPE,
        target_id=org.id,
        details={
            "name": org.name,
            "slug": org.slug,
            "created_via": created_via,
            "default_quota": quota,
        },
    )
    await record_key_created(uow, key, actor_id=actor_id)
