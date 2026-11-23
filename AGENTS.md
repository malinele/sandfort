# sandfort

## What This Project Does
Self-hosted sandbox server for running AI-generated code: a REST API, a Python
SDK and a CLI over isolated Docker-backed sandboxes (exec, fs, git, PTY,
snapshots, volumes, quotas, audit). Pre-1.0 beta. The server is
source-available (FSL-1.1-Apache-2.0); the SDKs and CLI are Apache-2.0. See
`README.md` for scope, limits and a quickstart.

## Tech Stack
- Python 3.12, FastAPI + Pydantic v2, SQLAlchemy (SQLite for development,
  Postgres for production)
- docker-py behind a driver Protocol (`src/sandfort/drivers/base.py`)
- pytest (Docker-dependent tests are marked `@pytest.mark.docker`),
  `mypy --strict`, ruff, import-linter
- Typer CLI (`cli/`); TypeScript SDK (`sdk/typescript/`)

## Project Structure
- `docs/architecture.md` — the authoritative design: modules, REST API, data
  model, key decisions. When code and any other document disagree about the
  design, start there. Also in `docs/`: `operations.md` (runbook),
  `isolation-tiers.md`, `governance.md`, `roadmap.md`
- `src/sandfort/` — server package (`api/`, `services/`, `drivers/`, `db/`,
  `toolbox/`, `workers/`, `auth/`, `webhooks/`, `images/`, `domain/`)
- `sdk/python/` — Python SDK; `sdk/typescript/` — TypeScript SDK (a subset of
  the API); `cli/` — Typer CLI; `mcp_server/` — MCP server over stdio
- `tests/` — unit, chaos and load tests; `examples/` — runnable gate scripts
  (`quickstart.py`, `gate2.py` to `gate10.py`)
- `deploy/` — host setup, seccomp profile, Kubernetes kit;
  `openapi/sandfort.v1.json` — exported API spec

## Build / Test / Run Commands
Set up a checkout (Python 3.12 and, for driver tests and the dev server, a
local Docker daemon):

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

- `.venv/bin/python -m pytest -q` (unit; add `-m docker` for driver tests)
- Single test: `.venv/bin/python -m pytest tests/path/test_file.py::test_name -q`
- `.venv/bin/python -m mypy --strict src/sandfort`
- `.venv/bin/ruff check .`
- `PYTHONPATH=src .venv/bin/lint-imports` (layer contracts in `pyproject.toml [tool.importlinter]`)
- `.venv/bin/uvicorn --factory sandfort.main:create_app` (dev server; the
  application is built by the `create_app` factory, there is no module-level
  `app`. First set `SANDFORT_DATABASE_URL`, `SANDFORT_DRIVER` and
  `SANDFORT_API_KEY_PEPPER`, then run
  `.venv/bin/python -m sandfort.admin_cli migrate` and `bootstrap`; the full
  steps are in the `README.md` Quickstart)

## Coding Conventions
- Every file stays under 400 lines; prefer many small modules.
- Frozen interfaces (the driver protocols in `src/sandfort/drivers/base.py`)
  keep their shape: implementations fill in bodies and never change the
  protocols.
- No secrets in code or env defaults. The `SANDFORT_` env prefix never reaches
  a sandbox environment.
- Driver calls never run inside an open DB transaction (intent-then-act): record
  the intent, commit, then call the driver.
- Respect the layering contracts enforced by import-linter (`api` over
  `services`/`workers`/`toolbox`, over `auth`/`webhooks`/`images`, over
  `drivers`/`db`, over `domain`).
- After a non-obvious architectural change, update `docs/architecture.md`, and
  add a `CHANGELOG.md` entry for any user-visible change.

## How This Codebase Was Built
The codebase was built through guarded contract runs: narrow tasks for AI
coding agents, each with an explicit list of allowed files and verification
commands that a runner outside the agent executes, and each ending after one
small step. Contributors are welcome to work the same way: keep a change to one
narrow step, state which files it may touch, and let the verification commands
above decide whether it is done.

## Known Pitfalls
- Docker-dependent tests must stay skippable, so CI without Docker stays green:
  mark them `@pytest.mark.docker`.
- Verification commands must be side-effect-free: no `pip install -e` and no
  writes outside the working tree inside a check.
- `PYTHONPATH=src` is required for `lint-imports`; without it the contracts
  cannot resolve the package.
- Changing `SANDFORT_API_KEY_PEPPER` on an existing database makes every API key
  answer 401. Keep it stable for the life of a database.
- Per-sandbox disk limits need XFS project quotas on Linux; Docker Desktop on
  macOS does not enforce them. Blocking the cloud metadata IP is a host step
  (`deploy/host-setup.sh`), not something the server does by itself.
