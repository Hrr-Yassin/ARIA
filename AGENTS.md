# Repository Guidelines

## Project Structure & Module Organization
ARIA is a Python 3.11 penetration-testing research prototype with a FastAPI backend and browser interface. `api/` contains routes, authentication, and administrative commands; `agents/` contains specialist agents; `orchestrator/` handles workflow and execution policy. `memory/` owns persistence and evidence processing, `llm/` provides model adapters, and `security/` and `config/` hold security helpers and settings. Browser pages and assets live in `web/`. Database revisions live in `migrations/`; offline regressions in `tests/`; service integration tests in `integration/`. Consult `docs/` for security status, worker contracts, and lab setup. The external Kali worker implementation is not included.

## Build, Test, and Development Commands
Run commands from the repository root with the Python 3.11 virtual environment activated:

- `bash setup.sh`: create `.venv`, install hash-locked dependencies, and check consistency.
- `python -m alembic upgrade head`: migrate a new database; consult migration-adoption instructions before touching a populated legacy database.
- `python -m api.bootstrap_admin`: create an administrator interactively.
- `python -m uvicorn api.main:app --host 127.0.0.1 --port 7000 --workers 1`: serve the API and UI locally. One worker is required for process-local investigation state.
- `python -m unittest discover -s tests -t . -q`: run offline Python regressions.
- `node tests/frontend_contracts.cjs`: validate frontend contracts.

## Coding Style & Naming Conventions
Use four-space Python indentation, `snake_case` modules/functions, and `PascalCase` classes. Follow surrounding code and add type annotations to public interfaces. Keep asynchronous service paths asynchronous. No formatter or linter is configured; avoid unrelated formatting changes. Update `requirements.in` and regenerate the hash lock when changing dependencies.

## Testing Guidelines
Use `unittest`, existing `OfflineCase` helpers, and mocked providers/workers. Name files `test_*.py` and methods `test_*`. Cover authorization, isolation, cancellation, and failure paths when affected. Offline tests block network access. Run service integration checks only against disposable PostgreSQL/Redis using the configuration in `docs/p2-status.md`. No numeric coverage threshold is configured.

## Commit & Pull Request Guidelines
History uses descriptive, imperative subjects such as “Harden ARIA security”; follow that style. PRs should explain the problem, resulting behavior, validation commands/results, and configuration or migration impact. Link relevant issues and include screenshots for UI changes.

## Security & Configuration
Keep `.env`, credentials, and generated evidence untracked. Preserve shared execution authorization and session ownership checks. Use only isolated, authorized targets; read `docs/security-review.md` before changing execution boundaries.
