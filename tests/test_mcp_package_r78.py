"""Packaging checks for the sandfort-mcp distribution (no Docker, no server)."""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
MCP_DIR = ROOT / "mcp_server"
sys.path.insert(0, str(MCP_DIR))

import sandfort_mcp  # noqa: E402

DOCUMENTED_URL_ENV = "SANDFORT_BASE_URL"
DOCUMENTED_KEY_ENV = "SANDFORT_API_KEY"
REGISTRY_NAME = "io.github.malinele/sandfort"
MAX_DESCRIPTION_CHARS = 100


def _server_json() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    return data


def _readme() -> str:
    return (MCP_DIR / "README.md").read_text(encoding="utf-8")


def test_main_is_callable() -> None:
    assert callable(sandfort_mcp.main)


def test_env_names_match_documented_names() -> None:
    assert sandfort_mcp.URL_ENV == DOCUMENTED_URL_ENV
    assert sandfort_mcp.KEY_ENV == DOCUMENTED_KEY_ENV


def test_server_json_identity_matches_readme() -> None:
    data = _server_json()
    readme = _readme()
    package = data["packages"][0]

    assert data["name"] == REGISTRY_NAME
    assert f"<!-- mcp-name: {REGISTRY_NAME} -->" in readme
    assert package["registryType"] == "pypi"
    assert package["identifier"] == "sandfort-mcp"
    assert f"pip install {package['identifier']}" in readme
    assert len(data["description"]) < MAX_DESCRIPTION_CHARS


def test_server_json_env_vars_match_readme_and_module() -> None:
    package = _server_json()["packages"][0]
    readme = _readme()
    env = {item["name"]: item for item in package["environmentVariables"]}

    assert set(env) == {sandfort_mcp.URL_ENV, sandfort_mcp.KEY_ENV}
    for name in env:
        assert f"`{name}`" in readme
    assert env[sandfort_mcp.URL_ENV]["isRequired"] is True
    assert env[sandfort_mcp.KEY_ENV]["isRequired"] is True
    assert env[sandfort_mcp.KEY_ENV]["isSecret"] is True


def test_pyproject_matches_server_json() -> None:
    text = (MCP_DIR / "pyproject.toml").read_text(encoding="utf-8")
    project = tomllib.loads(text)["project"]
    data = _server_json()
    package = data["packages"][0]

    assert project["name"] == package["identifier"]
    assert project["version"] == package["version"] == data["version"]
    assert project["scripts"] == {"sandfort-mcp": "sandfort_mcp:main"}
