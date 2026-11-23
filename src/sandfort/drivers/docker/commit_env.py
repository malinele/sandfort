"""The ``Env`` a snapshot commit stores: the base image's, never the sandbox's values.

``docker commit`` keeps the container's whole ``Env`` (the user's env values and the
platform-injected variables such as the egress proxy URL with its signed token). The daemon
merges a given commit config with the container's config: for the same key the given ``Env``
wins, and a key the given ``Env`` lacks is appended from the container. So a commit can blank a
value but cannot drop a key. ``commit_env`` therefore returns every base image entry unchanged
(which restores a key the container overrode to its base value) plus ``KEY=`` (empty value) for
every key the container added; the stored image holds no value the sandbox set.
"""

from collections.abc import Iterable, Mapping
from typing import Any

ENV_SEPARATOR = "="


def env_key(entry: str) -> str:
    """The variable name of a ``KEY=VALUE`` entry; only the first ``=`` separates."""
    return entry.partition(ENV_SEPARATOR)[0]


def config_env(attrs: Mapping[str, Any]) -> list[str]:
    """``Config.Env`` of a container or image inspect payload (empty when unset)."""
    config = attrs.get("Config") or {}
    return [str(entry) for entry in config.get("Env") or []]


def commit_env(base_env: Iterable[str], container_env: Iterable[str]) -> list[str]:
    """Base entries unchanged, then ``KEY=`` once per key only the container has, in order."""
    result = [str(entry) for entry in base_env]
    known = {env_key(entry) for entry in result}
    for entry in container_env:
        key = env_key(str(entry))
        if key and key not in known:
            known.add(key)
            result.append(f"{key}{ENV_SEPARATOR}")
    return result


def base_image_id(container_attrs: Mapping[str, Any]) -> str:
    """The container's image: the ``Image`` id, else the ``Config.Image`` reference."""
    config = container_attrs.get("Config") or {}
    return str(container_attrs.get("Image") or config.get("Image") or "")
