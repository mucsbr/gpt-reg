# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

OpenAI Pool Orchestrator is a single-process Python application with:

- FastAPI backend
- Embedded static SPA (`openai_pool_orchestrator/static/`)
- A shared registration engine used by both Web mode and CLI mode
- Two account-pool integrations: CPA and Sub2Api
- Mail-provider abstraction for OTP-driven signup flows

The app listens on `http://localhost:18421` in Web mode.

## Common commands

### Install

```bash
pip install -r requirements.txt
pip install -e .
```

`pip install -e .` registers the `openai-pool` console entrypoint.

### Run the app

```bash
python run.py
python -m openai_pool_orchestrator
openai-pool
```

All three start the Web server on port `18421`.

### Run CLI registration flow

```bash
python run.py --cli --once
python run.py --cli --proxy http://127.0.0.1:7897 --once
python run.py --cli --proxy http://127.0.0.1:7897 --sleep-min 5 --sleep-max 30
```

`run.py` dispatches to CLI mode when `--cli` is present; otherwise it starts the Web server.

### Syntax check

```bash
python -m compileall openai_pool_orchestrator
```

### Docker

```bash
docker compose up -d
```

### Tests

There is currently no committed test suite or lint configuration in this repository.

If local pytest tests are added, use:

```bash
python -m pytest
python -m pytest tests/test_some_module.py
python -m pytest tests/test_some_module.py -k some_case
```

## High-level architecture

### Entry points

- `run.py` is the user-facing launcher. It switches between Web mode and CLI mode.
- `openai_pool_orchestrator/__main__.py` starts Uvicorn and serves `server.app`.
- `openai_pool_orchestrator/register.py:2028` provides the CLI entrypoint.

### Core runtime split

- `openai_pool_orchestrator/server.py` is the orchestration layer for Web mode.
- `openai_pool_orchestrator/register.py` is the end-to-end registration engine.
- `openai_pool_orchestrator/pool_maintainer.py` handles CPA and Sub2Api maintenance workflows.
- `openai_pool_orchestrator/mail_providers.py` abstracts mailbox creation and OTP polling.

The important relationship is that Web mode does not implement a separate registration pipeline: server workers ultimately drive the same registration logic exposed by `register.py`.

### Web mode flow

`server.py` owns three things that are easy to miss if you only read routes:

1. `TaskState` is the central runtime coordinator.
   - Tracks task lifecycle, worker snapshots, counters, upload backlogs, and stop/shutdown state.
   - Publishes structured SSE events for the frontend.
2. FastAPI routes expose control/config/token/pool APIs.
3. The server persists runtime configuration and counters under `data/`.

If a change affects task progress, worker state, counters, or live UI updates, inspect `TaskState` first rather than editing routes in isolation.

### Frontend model

The frontend is not a separate build system or framework app.

- `openai_pool_orchestrator/static/index.html` contains the page shell.
- `openai_pool_orchestrator/static/app.js` contains client-side state management and all API/SSE integration.
- `openai_pool_orchestrator/static/style.css` is the full styling layer.

`app.js` talks directly to REST endpoints and subscribes to `/api/logs` via `EventSource`. Changes to task snapshots, runtime snapshots, stats, or log event shapes usually require coordinated changes in both `server.py` and `static/app.js`.

### Registration engine

`register.py` contains the real signup/token acquisition flow in `run(...)`.

That function handles:

- proxy selection and proxy-pool fallback
- temporary mailbox acquisition
- OAuth/signup/OTP steps
- token result construction
- integration points used by CLI and server-side workers

When changing signup behavior, prefer modifying `run(...)` and its helpers rather than duplicating logic in `server.py`.

### Mail provider abstraction

`mail_providers.py` defines the extension seam for email backends:

- `MailProvider` is the abstract base class
- concrete providers implement mailbox creation and OTP polling
- `MultiMailRouter` selects among providers using routing/failover strategy

If you add or change a provider, verify both provider-specific logic and router behavior.

### Pool integrations

`pool_maintainer.py` has two separate integration surfaces:

- `PoolMaintainer` for CPA
- `Sub2ApiMaintainer` for Sub2Api

These are used for both manual maintenance operations and post-registration platform sync/upload work. Changes here often affect API handlers in `server.py` and token-processing behavior after registration succeeds.

## Persistence and configuration

Runtime data lives under `data/`:

- `data/sync_config.json` — live configuration persisted by the server
- `data/state.json` — success/failure counters
- `data/tokens/` — saved token JSON files

`openai_pool_orchestrator/__init__.py` creates these directories on import, so path setup is centralized there.

Configuration template lives at `config/sync_config.example.json`.

## Important repo-specific gotcha

There is a config-path mismatch in the current codebase:

- `server.py` reads/writes live config through `CONFIG_FILE`, which points to `data/sync_config.json`
- the CLI tail in `register.py:2046` still reads `config/sync_config.json`

If you touch configuration loading or CPA upload behavior, check both code paths and do not assume Web mode and CLI mode are reading the same file.

## Related guidance files

- `AGENTS.md` contains repository guidelines and command conventions.
- `openai_pool_orchestrator/CLAUDE.md` contains a deeper package-level breakdown of the main Python package.