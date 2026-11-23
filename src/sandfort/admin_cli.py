"""``sandfort-admin``: bootstrap the first org and platform-admin key, run migrations.

Run as ``python -m sandfort.admin_cli <command>``; settings come from ``SANDFORT_*``
env. ``bootstrap`` prints the plaintext key to stdout exactly once (only its
salted hash is stored) and refuses to run when a platform-admin key exists.
``create-org`` provisions additional orgs the same way, refusing duplicate slugs.
``create-key`` issues a replacement org-wide key for an existing org (lost plaintext).
``revoke-key`` revokes a key from the host (platform-admin keys too); logic in ``admin_keys``.
``repair-labels`` rewrites unreadable characters in stored sandbox labels.
"""

import asyncio
import re
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Annotated, NamedTuple

import typer
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import exists, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort import admin_doctor, admin_keys
from sandfort.auth.api_keys import generate_api_key
from sandfort.auth.scopes import ALL_SCOPES
from sandfort.clock import SystemClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.models.api_keys import ApiKeyRow
from sandfort.db.models.sandboxes import SandboxRow
from sandfort.db.repositories.api_keys import SqlApiKeyRepository
from sandfort.db.repositories.orgs import SqlOrgRepository
from sandfort.db.repositories.ports import ChainedAuditEvent, UnitOfWorkPort
from sandfort.db.repositories.quotas import SqlQuotaRepository
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType
from sandfort.domain.org import ApiKey, Org
from sandfort.domain.quota import OrgQuota
from sandfort.errors import Conflict, NotFound, SandfortError, ValidationFailed
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.api_key_admin import KEY_CREATED, TARGET_TYPE
from sandfort.services.audit import AuditRecorder
from sandfort.services.audit_chain import (
    REANCHOR_ACTION,
    ChainFinding,
    ChainPolicy,
    ChainVerifier,
    FindingKind,
    HeadWatcher,
    ReanchorReason,
    SignedHead,
    export_line,
    invalid_head_finding,
    parse_heads,
    sign_head,
)
from sandfort.services.audit_export_digest import ExportDigest
from sandfort.services.audit_head_signing import (
    ALG,
    canonical_payload,
    load_public_key,
    verify_payload,
)

BOOTSTRAP_KEY_NAME = "bootstrap-admin"
BOOTSTRAP_ACTOR = "sandfort-admin"
DEFAULT_KEY_NAME = "admin"
MAX_KEY_NAME_LENGTH = 255
MAX_ORG_NAME_LENGTH = 255
SLUG_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
EXIT_CHAIN_MISMATCH = 3
PUBLIC_KEY_OPTION = "--public-key"
USAGE_EXIT_CODE = 2  # the code click/typer use for a bad command line
AUDIT_PAGE_SIZE = 500
MAX_NOTE_LENGTH = 1000
MAX_OPERATOR_LENGTH = 255
REPAIR_PAGE_SIZE = 500
REPLACEMENT_CHAR = "�"
# Any surrogate left in a Python ``str`` is a lone one (a valid pair decodes to one character).
UNREADABLE_CHARS = re.compile("[\x00\ud800-\udfff]")

app = typer.Typer(help="Sandfort server administration.", no_args_is_help=True)


class IssuedKey(NamedTuple):
    """A freshly provisioned key: the plaintext and the identifiers that name it."""

    key: str
    org_id: str
    key_id: str
    prefix: str


def bootstrap(org_name: str, org_slug: str) -> str:
    """Create the org and a platform-admin key; return the plaintext key."""
    return _provision(org_name, org_slug, first_org=True).key


def create_org(org_name: str, org_slug: str) -> str:
    """Create an additional org and its platform-admin key; return the plaintext key."""
    return _provision(org_name, org_slug, first_org=False).key


def create_key(
    org_slug: str | None, org_id: str | None, name: str, *, platform_admin: bool = False
) -> str:
    """Issue an org-wide key (all scopes) for an existing org; return the plaintext key."""
    if (org_slug is None) == (org_id is None):
        raise ValidationFailed("give exactly one of --org-slug and --org-id")
    if not name.strip() or len(name) > MAX_KEY_NAME_LENGTH:
        raise ValidationFailed(f"key name must be 1-{MAX_KEY_NAME_LENGTH} characters")
    settings = _provisioning_settings()
    return asyncio.run(_create_key_async(settings, org_slug, org_id, name, platform_admin))


def revoke_key(
    org_slug: str | None,
    org_id: str | None,
    key_id: str | None,
    prefix: str | None,
    *,
    cascade: bool = False,
) -> str:
    """Revoke one key straight in the database; return the line to print."""
    org_slug, org_id, key_id, prefix = admin_keys.check_selectors(org_slug, org_id, key_id, prefix)
    settings = _provisioning_settings()
    outcome = asyncio.run(
        admin_keys.revoke_key_async(
            settings, org_slug, org_id, key_id, prefix, cascade=cascade, actor_id=BOOTSTRAP_ACTOR
        )
    )
    return admin_keys.describe(outcome)


def migrate(revision: str = "head") -> None:
    """Upgrade the configured database to ``revision``."""
    command.upgrade(_alembic_config(Settings.from_env()), revision)


def main() -> None:
    app()


@app.command("bootstrap")
def bootstrap_command(
    org_name: Annotated[str, typer.Option(help="Display name of the first organization.")],
    org_slug: Annotated[str, typer.Option(help="Unique lowercase slug, e.g. 'acme'.")],
) -> None:
    """Create the first org and a platform-admin key; print the key exactly once.

    Stdout is exactly the key. The org id, the key id and the key prefix go to stderr.
    """
    _provision_and_print(org_name, org_slug, first_org=True)


@app.command("create-org")
def create_org_command(
    org_name: Annotated[str, typer.Option(help="Display name of the new organization.")],
    org_slug: Annotated[str, typer.Option(help="Unique lowercase slug, e.g. 'acme'.")],
    platform_admin: Annotated[
        bool,
        typer.Option(
            "--platform-admin/--no-platform-admin",
            help="Issue a platform-admin key (default). Use --no-platform-admin for tenants.",
        ),
    ] = True,
) -> None:
    """Create an additional org and its key; print the key exactly once.

    The key is a platform-admin key by default. --no-platform-admin is recommended for tenant
    organizations: a platform-admin key passes the platform check on PUT /v1/org/quota, so a
    tenant holding one could change its own quota.

    Stdout is exactly the key. The org id, the key id and the key prefix go to stderr.
    """
    _provision_and_print(org_name, org_slug, first_org=False, platform_admin=platform_admin)


def _provision_and_print(
    org_name: str, org_slug: str, *, first_org: bool, platform_admin: bool = True
) -> None:
    """Provision an org and its key: the key on stdout, its identifiers and hints on stderr."""
    try:
        issued = _provision(org_name, org_slug, first_org=first_org, platform_admin=platform_admin)
    except (SandfortError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(issued.key)
    typer.echo(f"org id: {issued.org_id}", err=True)
    typer.echo(f"key id: {issued.key_id}", err=True)
    typer.echo(f"key prefix: {issued.prefix}", err=True)
    _echo_key_hints()


@app.command("create-key")
def create_key_command(
    org_slug: Annotated[str | None, typer.Option(help="Slug of the existing org.")] = None,
    org_id: Annotated[str | None, typer.Option(help="Id of the existing org, not slug.")] = None,
    name: Annotated[str, typer.Option(help="Name of the new key.")] = DEFAULT_KEY_NAME,
    platform_admin: Annotated[
        bool, typer.Option("--platform-admin", help="Make it a platform-admin key.")
    ] = False,
) -> None:
    """Issue a new org-wide key (full scope set) for an existing org; print it exactly once.

    Recovery of a lost key: issue a new one, then revoke the old one. When the lost key was the
    bootstrap key or another platform-admin key, pass --platform-admin (only a platform-admin
    key can revoke one over the API) or revoke it from the host with revoke-key. Records an
    api_key.created audit event in the org.
    """
    _run_and_print_key(lambda: create_key(org_slug, org_id, name, platform_admin=platform_admin))


@app.command("revoke-key")
def revoke_key_command(
    org_slug: Annotated[str | None, typer.Option(help="Slug of the existing org.")] = None,
    org_id: Annotated[str | None, typer.Option(help="Id of the existing org, not slug.")] = None,
    key_id: Annotated[str | None, typer.Option(help="Id of the key to revoke.")] = None,
    prefix: Annotated[
        str | None, typer.Option(help="Prefix of the key to revoke, e.g. sf_live_ab12cd34.")
    ] = None,
    cascade: Annotated[
        bool, typer.Option("--cascade", help="Also revoke the key's live descendants.")
    ] = False,
) -> None:
    """Revoke an API key from the host, platform-admin keys included; no API key needed.

    Give one of --org-slug and --org-id and one of --key-id and --prefix. A prefix that matches
    several keys revokes nothing and lists them. Revoking a revoked key is a no-op (exit 0).
    Writes an api_key.revoked audit event as the platform admin sandfort-admin. --cascade
    revokes live descendants (keys minted by the key) with the API's own cascade logic.
    """
    try:
        line = revoke_key(org_slug, org_id, key_id, prefix, cascade=cascade)
    except admin_keys.BlankSelector as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=USAGE_EXIT_CODE) from exc
    except (SandfortError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(line)


@app.command("migrate")
def migrate_command(
    revision: Annotated[str, typer.Option(help="Target alembic revision.")] = "head",
) -> None:
    """Apply database migrations."""
    try:
        migrate(revision)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"database upgraded to {revision}", err=True)


@app.command("audit-verify")
def audit_verify_command(
    head: Annotated[
        Path | None,
        typer.Option(help="An audit-export file whose signed head lines the chain must reach."),
    ] = None,
    public_key: Annotated[
        str | None,
        typer.Option(
            "--public-key",
            help="Ed25519 public key (urlsafe base64); --head lines must be signed by it.",
        ),
    ] = None,
) -> None:
    """Verify every org's audit hash chain; exit 3 when any row fails.

    With a chain key set, unkeyed rows from before the key are accepted while
    SANDFORT_AUDIT_CHAIN_ACCEPT_UNKEYED is true, and their number is reported. With --head the
    signed head lines of an earlier export must still be reached (detects truncation). With
    --public-key as well (audit_public_key of GET /v1/status), each head's Ed25519 signature
    must verify with that key; an unsigned head or a bad signature is a head_invalid finding.
    """
    anchor = _head_public_key(public_key, head)
    try:
        heads = _read_heads(head) if head is not None else []
        checked, findings, acknowledged, unkeyed = asyncio.run(
            _audit_verify_async(Settings.from_env(), heads, anchor)
        )
    except (SandfortError, ValueError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    for finding in findings:
        typer.echo(finding.render())
    if findings:
        typer.echo(f"audit chain broken: {len(findings)} finding(s) in {checked} rows", err=True)
        raise typer.Exit(code=EXIT_CHAIN_MISMATCH)
    suffix = f" ({acknowledged} acknowledged finding(s))" if acknowledged else ""
    suffix += f" ({unkeyed} unkeyed row(s) accepted)" if unkeyed else ""
    typer.echo(f"ok: {checked} audit rows verified{suffix}")


@app.command("doctor")
def doctor_command(
    as_json: Annotated[bool, typer.Option("--json", help="Print checks as a JSON list.")] = False,
) -> None:
    """Check the docker host and settings for production; exit 1 when any check FAILs."""
    try:
        settings = Settings.from_env()
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    code = admin_doctor.run_doctor(settings, as_json=as_json, echo=typer.echo)
    if code:
        raise typer.Exit(code=code)


@app.command("audit-reanchor")
def audit_reanchor_command(
    org_id: Annotated[str, typer.Option("--org", help="The org whose chain to re-anchor.")],
    note: Annotated[str, typer.Option(help="Why the findings are acknowledged (kept in the row).")],
    operator: Annotated[
        str | None,
        typer.Option(help="Name of the operator running the command (kept in the row)."),
    ] = None,
    reason_code: Annotated[
        ReanchorReason | None,
        typer.Option("--reason-code", help="Reason category (kept in the row)."),
    ] = None,
) -> None:
    """Acknowledge an org's historical chain findings with one audit.chain_reanchored event.

    Runs a full verify of the org; if it has unacknowledged findings, appends one chained
    event naming the last row with a finding. From then on verify reports findings up to
    that row as acknowledged and no longer fails on them. It acknowledges, it never hides:
    no row is changed or removed, every finding stays in the history and in audit-export,
    and a later break still fails verify. With no findings nothing is written. Prints the
    event id. --operator and --reason-code go together and are stored next to the note.
    """
    try:
        who = _reanchor_operator(operator, reason_code)
        event_id = asyncio.run(_audit_reanchor_async(Settings.from_env(), org_id, note, who))
    except (SandfortError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if event_id is None:
        typer.echo("no findings: nothing to re-anchor")
        return
    typer.echo(event_id)


@app.command("audit-export")
def audit_export_command(
    org_id: Annotated[str | None, typer.Option(help="Only this org; default is every org.")] = None,
    output: Annotated[Path | None, typer.Option(help="File to write; default is stdout.")] = None,
) -> None:
    """Write audit rows, hash fields included, as ndjson (one object per line).

    With SANDFORT_AUDIT_CHAIN_KEY set, each org's rows are followed by one signed head line
    (last row id, its hash, the org's row count, first row id and a SHA-256 of its exported
    lines, an HMAC over them); audit-verify --head checks against it.
    """
    try:
        settings = Settings.from_env()
        if output is None:
            exported = asyncio.run(_audit_export_async(settings, org_id, typer.echo))
        else:
            with output.open("w", encoding="utf-8") as handle:
                exported = asyncio.run(
                    _audit_export_async(settings, org_id, lambda line: handle.write(line + "\n"))
                )
    except (SandfortError, ValueError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"exported {exported} audit rows", err=True)


@app.command("repair-labels")
def repair_labels_command(
    org_id: Annotated[
        str | None, typer.Option("--org", help="Only this org; default every org.")
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Report the rows without changing them.")
    ] = False,
) -> None:
    """Rewrite lone surrogates and NUL in stored sandbox labels to U+FFFD.

    Such rows (written before the round-53 input guard) never match a label filter. Prints the
    id of each changed sandbox, then the count. Audit rows are never read or written, so the
    audit chain stays byte-identical; the repair itself is not audited.
    """
    try:
        changed = asyncio.run(_repair_labels_async(Settings.from_env(), org_id, dry_run=dry_run))
    except (SandfortError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    for sandbox_id in changed:
        typer.echo(sandbox_id)
    verb = "would repair" if dry_run else "repaired"
    typer.echo(f"{verb} labels of {len(changed)} sandbox row(s)")


def _run_and_print_key(create: Callable[[], str]) -> None:
    try:
        key = create()
    except (SandfortError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(key)
    _echo_key_hints()


def _echo_key_hints() -> None:
    typer.echo("Store this key now; it cannot be shown again.", err=True)
    typer.echo("Use it as the api_key of the SDK Client, or run: sandfort login", err=True)


def _provision(
    org_name: str, org_slug: str, *, first_org: bool, platform_admin: bool = True
) -> IssuedKey:
    _validate_org(org_name, org_slug)
    settings = _provisioning_settings()
    return asyncio.run(
        _provision_async(
            settings, org_name, org_slug, first_org=first_org, platform_admin=platform_admin
        )
    )


def _provisioning_settings() -> Settings:
    settings = Settings.from_env()
    if not settings.api_key_pepper:
        raise ValidationFailed("SANDFORT_API_KEY_PEPPER must be set before provisioning")
    return settings


def _validate_org(org_name: str, org_slug: str) -> None:
    if not org_name.strip() or len(org_name) > MAX_ORG_NAME_LENGTH:
        raise ValidationFailed(f"org name must be 1-{MAX_ORG_NAME_LENGTH} characters")
    if not SLUG_PATTERN.fullmatch(org_slug):
        raise ValidationFailed(
            "org slug must be 1-63 lowercase letters, digits or '-', "
            "starting and ending with a letter or digit"
        )


def _alembic_config(settings: Settings) -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    # ConfigParser interpolation treats '%' specially.
    config.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
    return config


async def _provision_async(
    settings: Settings,
    org_name: str,
    org_slug: str,
    *,
    first_org: bool,
    platform_admin: bool = True,
) -> IssuedKey:
    engine = create_engine(settings)
    try:
        async with create_session_factory(engine)() as session, session.begin():
            if first_org:
                await _refuse_if_bootstrapped(session)
            await _refuse_duplicate_slug(session, org_slug)
            key = await _create_org_and_key(
                session, settings, org_name, org_slug, platform_admin=platform_admin
            )
    finally:
        await engine.dispose()
    return key


async def _refuse_if_bootstrapped(session: AsyncSession) -> None:
    stmt = select(exists().where(ApiKeyRow.is_platform_admin.is_(True)))
    if (await session.execute(stmt)).scalar():
        raise Conflict("already bootstrapped: a platform-admin key exists")


async def _refuse_duplicate_slug(session: AsyncSession, org_slug: str) -> None:
    if await SqlOrgRepository(session).get_by_slug(org_slug) is not None:
        raise Conflict(f"organization slug already exists: {org_slug}")


async def _create_org_and_key(
    session: AsyncSession,
    settings: Settings,
    org_name: str,
    org_slug: str,
    *,
    platform_admin: bool,
) -> IssuedKey:
    now = SystemClock().now()
    org = Org(id=new_org_id(), name=org_name, slug=org_slug, created_at=now)
    generated = generate_api_key(settings.api_key_pepper)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name=BOOTSTRAP_KEY_NAME,
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=ALL_SCOPES,
        is_platform_admin=platform_admin,
        created_by=BOOTSTRAP_ACTOR,
        created_at=now,
    )
    await SqlOrgRepository(session).add(org)
    default_quota = settings.default_org_quota()
    if default_quota != OrgQuota():  # unset everywhere: no row, the org stays unlimited
        await SqlQuotaRepository(session).upsert_limits(org.id, default_quota, now)
    await SqlApiKeyRepository(session).add(key)
    return IssuedKey(generated.key, org.id, key.id, key.prefix)


async def _create_key_async(
    settings: Settings, org_slug: str | None, org_id: str | None, name: str, platform_admin: bool
) -> str:
    engine = create_engine(settings)
    try:
        async with UnitOfWork(create_session_factory(engine)) as uow:
            if org_slug is not None:
                org = await uow.orgs.get_by_slug(org_slug)
            else:
                org = await uow.orgs.get(org_id or "")
            if org is None:
                raise NotFound(f"unknown organisation {org_slug or org_id}")
            generated = generate_api_key(settings.api_key_pepper)
            now = SystemClock().now()
            key = ApiKey(
                id=new_api_key_id(),
                org_id=org.id,
                name=name,
                prefix=generated.prefix,
                secret_hash=generated.secret_hash,
                scopes=ALL_SCOPES,
                is_platform_admin=platform_admin,
                created_by=BOOTSTRAP_ACTOR,
                created_at=now,
            )
            await uow.api_keys.add(key)
            await AuditRecorder(SystemClock()).record(
                uow,
                org_id=org.id,
                actor_type=ActorType.PLATFORM_ADMIN,
                actor_id=BOOTSTRAP_ACTOR,
                action=KEY_CREATED,
                target_type=TARGET_TYPE,
                target_id=key.id,
                details={
                    "name": name,
                    "prefix": key.prefix,
                    "scopes": sorted(scope.value for scope in ALL_SCOPES),
                    "sandbox_labels": None,
                    "max_sandboxes": None,
                    "shared_volume_labels": None,
                    "expires_at": None,
                    "is_platform_admin": platform_admin,
                },
            )
            await uow.commit()
    finally:
        await engine.dispose()
    return generated.key


def _read_heads(path: Path) -> list[SignedHead]:
    with path.open(encoding="utf-8") as handle:
        heads = parse_heads(handle)
    if not heads:
        raise ValidationFailed(f"{path} holds no signed audit head line")
    return heads


def _head_public_key(text: str | None, head: Path | None) -> Ed25519PublicKey | None:
    """The ``--public-key`` value as a key; a usage error (exit 2) when unusable."""
    if text is None:
        return None
    if head is None:
        raise typer.BadParameter(
            "needs --head (the export whose heads to check)", param_hint=PUBLIC_KEY_OPTION
        )
    try:
        return load_public_key(text.strip())
    except ValueError:
        raise typer.BadParameter(
            "must be an Ed25519 public key: 32 bytes in urlsafe base64",
            param_hint=PUBLIC_KEY_OPTION,
        ) from None


def _head_signature_finding(head: SignedHead, key: Ed25519PublicKey) -> ChainFinding | None:
    """A ``head_invalid`` finding when ``head`` is not signed by ``key``; else ``None``."""
    if head.signature is None or head.alg is None:
        detail = "head is not signed (no Ed25519 signature) but --public-key was given"
    elif head.alg != ALG:
        detail = f"head signature algorithm {head.alg!r} is not {ALG}"
    elif not verify_payload(key, canonical_payload(head.to_record()), head.signature):
        detail = "head Ed25519 signature does not verify with --public-key"
    else:
        return None
    return ChainFinding(FindingKind.HEAD_INVALID, head.org_id, head.row_id, detail)


async def _audit_verify_async(
    settings: Settings,
    heads: list[SignedHead] | None = None,
    public_key: Ed25519PublicKey | None = None,
) -> tuple[int, list[ChainFinding], int, int]:
    """Rows checked, unacknowledged findings, acknowledged and accepted-unkeyed counts."""
    policy = ChainPolicy.from_settings(settings)
    findings: list[ChainFinding] = []
    watchers: dict[str, list[HeadWatcher]] = {}
    for head in heads or []:
        if policy.key is None:
            raise ValidationFailed("verifying a head file needs SANDFORT_AUDIT_CHAIN_KEY")
        bad_signature = None if public_key is None else _head_signature_finding(head, public_key)
        if bad_signature is not None:
            findings.append(bad_signature)
        if head.valid(policy.key):
            watchers.setdefault(head.org_id, []).append(HeadWatcher(head))
        else:
            findings.append(invalid_head_finding(head))
    engine = create_engine(settings)
    checked = 0
    acknowledged = 0
    unkeyed = 0
    try:
        async with UnitOfWork(create_session_factory(engine)) as uow:
            org_ids = list(await uow.audit.org_ids())
            for org_id in org_ids:
                verifier = ChainVerifier(policy=policy)
                async for row in _org_rows(uow, org_id):
                    checked += 1
                    verifier.check(row)
                    for watcher in watchers.get(org_id, []):
                        watcher.observe(row)
                verdict = verifier.verdict()
                findings.extend(verdict.findings)
                acknowledged += verdict.acknowledged
                unkeyed += verdict.unkeyed_accepted
    finally:
        await engine.dispose()
    for watcher in (item for group in watchers.values() for item in group):
        missing = watcher.finding()
        if missing is not None:
            findings.append(missing)
    return checked, findings, acknowledged, unkeyed


def _reanchor_operator(operator: str | None, reason_code: ReanchorReason | None) -> dict[str, str]:
    """The ``operator``/``reason_code`` details of a re-anchor; both or neither."""
    if operator is None and reason_code is None:
        return {}
    if operator is None or reason_code is None:
        raise ValidationFailed("--operator and --reason-code must be given together")
    name = operator.strip()
    if not name or len(name) > MAX_OPERATOR_LENGTH:
        raise ValidationFailed(f"operator must be 1-{MAX_OPERATOR_LENGTH} characters")
    return {"operator": name, "reason_code": reason_code.value}


async def _audit_reanchor_async(
    settings: Settings, org_id: str, note: str, who: dict[str, str] | None = None
) -> str | None:
    if not note.strip() or len(note) > MAX_NOTE_LENGTH:
        raise ValidationFailed(f"note must be 1-{MAX_NOTE_LENGTH} characters")
    engine = create_engine(settings)
    try:
        async with UnitOfWork(create_session_factory(engine)) as uow:
            if await uow.orgs.get(org_id) is None:
                raise NotFound(f"organization {org_id} not found")
            verifier = ChainVerifier()
            async for row in _org_rows(uow, org_id):
                verifier.check(row)
            if not verifier.verdict().findings:
                return None
            found = verifier.all_findings
            event = await AuditRecorder(SystemClock()).record(
                uow,
                org_id=org_id,
                actor_type=ActorType.PLATFORM_ADMIN,
                actor_id=BOOTSTRAP_ACTOR,
                action=REANCHOR_ACTION,
                target_type="org",
                target_id=org_id,
                details={
                    "acknowledged_through": max(item.row_id for item in found),
                    "findings": len(found),
                    "note": note,
                    **(who or {}),
                },
            )
            await uow.commit()
    finally:
        await engine.dispose()
    return event.id


async def _audit_export_async(
    settings: Settings, org_id: str | None, write: Callable[[str], object]
) -> int:
    engine = create_engine(settings)
    exported = 0
    key = ChainPolicy.from_settings(settings).key
    signer = settings.audit_signer()
    try:
        async with UnitOfWork(create_session_factory(engine)) as uow:
            org_ids = [org_id] if org_id is not None else list(await uow.audit.org_ids())
            for current in org_ids:
                last: ChainedAuditEvent | None = None
                digest = ExportDigest()
                async for row in _org_rows(uow, current):
                    line = export_line(row)
                    write(line)
                    digest.add(row.event.id, line + "\n")
                    exported += 1
                    last = row
                if key is not None and last is not None and last.entry_hash is not None:
                    head = sign_head(
                        key, current, last.event.id, last.entry_hash, signer, None, digest.binding()
                    )
                    write(head.to_line())
    finally:
        await engine.dispose()
    return exported


async def _org_rows(uow: UnitOfWorkPort, org_id: str) -> AsyncIterator[ChainedAuditEvent]:
    """One org's audit rows in id (insertion) order, fetched a page at a time."""
    cursor: str | None = None
    while True:
        page = await uow.audit.list_chained(org_id, cursor=cursor, limit=AUDIT_PAGE_SIZE)
        for row in page:
            yield row
        if len(page) < AUDIT_PAGE_SIZE:
            return
        cursor = page[-1].event.id


def repaired_labels(labels: dict[str, str]) -> dict[str, str] | None:
    """``labels`` with lone surrogates and NUL replaced by U+FFFD; ``None`` when already clean.

    A repaired key that collides with another key gets more U+FFFD appended, so no pair is lost.
    A genuine (already clean) key always keeps its name, wherever it sits in the mapping.
    """
    genuine = {str(key) for key in labels if not UNREADABLE_CHARS.search(str(key))}
    fixed: dict[str, str] = {}
    dirty = False
    for key, value in labels.items():
        new_key = UNREADABLE_CHARS.sub(REPLACEMENT_CHAR, str(key))
        new_value = UNREADABLE_CHARS.sub(REPLACEMENT_CHAR, str(value))
        dirty = dirty or (new_key, new_value) != (key, value)
        if new_key != key:
            while new_key in fixed or new_key in genuine:
                new_key += REPLACEMENT_CHAR
        fixed[new_key] = new_value
    return fixed if dirty else None


async def _repair_labels_async(
    settings: Settings, org_id: str | None, *, dry_run: bool
) -> list[str]:
    """Ids of the sandbox rows whose labels were (or, on a dry run, would be) rewritten.

    Every state is covered (destroyed and standby rows too). Only ``labels`` and ``version`` are
    written; bumping ``version`` makes a writer holding the old labels conflict instead of
    restoring them. Nothing else is written, audit and outbox included.
    """
    engine = create_engine(settings)
    changed: list[str] = []
    try:
        async with create_session_factory(engine)() as session, session.begin():
            if org_id is not None and await SqlOrgRepository(session).get(org_id) is None:
                raise NotFound(f"organization {org_id} not found")
            async for sandbox_id, labels in _label_rows(session, org_id):
                fixed = repaired_labels(labels)
                if fixed is None:
                    continue
                changed.append(sandbox_id)
                if not dry_run:
                    await session.execute(
                        update(SandboxRow)
                        .where(SandboxRow.id == sandbox_id)
                        .values(labels=fixed, version=SandboxRow.version + 1)
                        .execution_options(synchronize_session=False)
                    )
    finally:
        await engine.dispose()
    return changed


async def _label_rows(
    session: AsyncSession, org_id: str | None
) -> AsyncIterator[tuple[str, dict[str, str]]]:
    """``(id, labels)`` of every sandbox row (of ``org_id`` when given), a page at a time."""
    cursor = ""
    while True:
        stmt = select(SandboxRow.id, SandboxRow.labels).where(SandboxRow.id > cursor)
        if org_id is not None:
            stmt = stmt.where(SandboxRow.org_id == org_id)
        page = (await session.execute(stmt.order_by(SandboxRow.id).limit(REPAIR_PAGE_SIZE))).all()
        for sandbox_id, labels in page:
            yield sandbox_id, dict(labels or {})
        if len(page) < REPAIR_PAGE_SIZE:
            return
        cursor = page[-1][0]


if __name__ == "__main__":
    main()
