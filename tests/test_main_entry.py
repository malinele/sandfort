"""``python -m sandfort.main`` must behave like a real entry point, not a silent no-op."""

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import sandfort.main as server_main
from sandfort.config import Settings

SRC_DIR = Path(__file__).resolve().parent.parent / "src"


def test_module_flag_invocation_prints_usage_and_exits_zero() -> None:
    env = dict(os.environ)
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(SRC_DIR) if not existing else f"{SRC_DIR}{os.pathsep}{existing}"

    result = subprocess.run(
        [sys.executable, "-m", "sandfort.main", "--help"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() != ""
    assert "usage:" in result.stdout.lower()


# --- forwarded headers: the ingress address is trusted for X-Forwarded-Proto/For ----------

TRUSTED_PROXIES = "10.0.0.7,10.0.0.8"


def _serve_env(monkeypatch: pytest.MonkeyPatch, *, role: str, proxy: bool) -> None:
    monkeypatch.setenv("SANDFORT_ROLE", role)
    monkeypatch.setenv("SANDFORT_PROXY_ENABLED", "true" if proxy else "false")
    monkeypatch.setenv("SANDFORT_FORWARDED_ALLOW_IPS", TRUSTED_PROXIES)


def test_config_builder_trusts_the_configured_forwarded_proxies() -> None:
    settings = Settings(forwarded_allow_ips=TRUSTED_PROXIES)

    config = server_main._config(object(), settings, 8000, access_log=False)

    assert config.proxy_headers is True
    assert config.forwarded_allow_ips == TRUSTED_PROXIES


def test_plain_uvicorn_run_path_receives_the_forwarded_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(server_main.uvicorn, "run", lambda app, **kwargs: calls.append(kwargs))
    monkeypatch.setattr(server_main, "create_app", lambda settings=None: object())
    _serve_env(monkeypatch, role="api", proxy=False)

    server_main.main([])

    assert len(calls) == 1
    assert calls[0]["proxy_headers"] is True
    assert calls[0]["forwarded_allow_ips"] == TRUSTED_PROXIES


def test_api_and_preview_proxy_servers_both_receive_the_forwarded_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    servers: list[Any] = []

    async def capture(*started: Any) -> None:
        servers.extend(started)

    monkeypatch.setattr(server_main, "_serve_together", capture)
    monkeypatch.setattr(server_main, "create_app", lambda settings=None: object())
    monkeypatch.setattr(server_main, "create_proxy_app", lambda settings, *, api_app: object())
    _serve_env(monkeypatch, role="all", proxy=True)

    server_main.main([])

    assert len(servers) == 2
    for server in servers:
        assert server.config.proxy_headers is True
        assert server.config.forwarded_allow_ips == TRUSTED_PROXIES
