"""Resolve the volume part of ``--mount`` (a ``vol_`` id or a volume name) to a volume id."""

from collections.abc import Sequence

import typer
from sandfort_sdk import Client, VolumeMount

from sandfort_cli.sanitise import MAX_ECHOED_VALUE_CHARS, caller_key, sanitise_text

VOLUME_ID_PREFIX = "vol_"
MOUNT_OPTION = "--mount"
LOOKUP_PAGE_SIZE = 100  # the largest page the server serves
READY_STATE = "ready"
AMBIGUOUS_AT = 2  # two matches already make a name ambiguous; no need to read further


def clean(text: str) -> str:
    """``text`` as a usage message may echo it: sanitised and cut to the echo cap."""
    return sanitise_text(text, api_key=caller_key(), limit=MAX_ECHOED_VALUE_CHARS)


def matching_ids(client: Client, name: str) -> list[str]:
    """The ids of the ready volumes called exactly ``name``, at most :data:`AMBIGUOUS_AT`.

    The server lists volumes without a name filter, so the pages are read and compared here, at
    the largest page size, and the reading stops at the second match. A volume that is being
    deleted neither matches nor makes the name ambiguous.
    """
    ids: list[str] = []
    for volume in client.volumes.iter(limit=LOOKUP_PAGE_SIZE):
        if volume.state != READY_STATE or volume.name != name:
            continue
        ids.append(volume.id)
        if len(ids) == AMBIGUOUS_AT:
            break
    return ids


def volume_id_for_name(client: Client, name: str, param_hint: str = MOUNT_OPTION) -> str:
    """The id of the one ready volume called exactly ``name``; a usage error for none or several.

    ``param_hint`` names the argument or option in the usage error.
    """
    ids = matching_ids(client, name)
    shown = clean(name)
    if not ids:
        raise typer.BadParameter(
            f"no volume named {shown} (volume create {shown}, or pass its vol_ id)",
            param_hint=param_hint,
        )
    if len(ids) > 1:
        listed = ", ".join(clean(volume_id) for volume_id in ids)
        raise typer.BadParameter(
            f"more than one volume is named {shown}: {listed}; pass the vol_ id",
            param_hint=param_hint,
        )
    return ids[0]


def volume_id_for_ref(client: Client, ref: str, param_hint: str = MOUNT_OPTION) -> str:
    """``ref`` itself when it starts with ``vol_`` (an id, kept as given), else the id of the
    volume of that name."""
    if ref.startswith(VOLUME_ID_PREFIX):
        return ref
    return volume_id_for_name(client, ref, param_hint)


def resolve_volume_refs(client: Client, mounts: Sequence[VolumeMount]) -> list[VolumeMount]:
    """``mounts`` with every volume name replaced by its id (one lookup per distinct name).

    A value that starts with ``vol_`` is always an id and is kept as given (a volume named
    ``vol_x`` cannot be mounted by name; a mistyped id reaches the server); the order is unchanged.
    """
    resolved: dict[str, str] = {}
    for mount in mounts:
        ref = mount.volume_id
        if not ref.startswith(VOLUME_ID_PREFIX) and ref not in resolved:
            resolved[ref] = volume_id_for_name(client, ref)
    return [
        VolumeMount(
            resolved.get(mount.volume_id, mount.volume_id), mount.mount_path, mount.read_only
        )
        for mount in mounts
    ]
