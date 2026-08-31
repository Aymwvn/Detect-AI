# Contributing to DetectAI

Thanks for considering contributing. DetectAI is early-stage and being built in phases (see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full roadmap), so the codebase and conventions below will keep evolving — this file will grow with it.

## Ground rules

- **Evidence-first, always.** Any change touching AI analysis, risk scoring, or MITRE mapping must keep claims traceable to real evidence (event IDs, alert fields). Don't add code paths that let a conclusion be shown without a citation.
- **SIEM-agnostic.** Core logic (dedup, correlation, risk scoring, API, dashboard) must never import or depend on a specific connector. If you're tempted to special-case one vendor outside `connectors/`, it belongs in a connector instead.
- **No secrets in code or logs.** Credentials go through `app/core/config.py` (env-driven `Settings`), never hardcoded, never logged. See [`SECURITY.md`](SECURITY.md).
- **Every PR should have tests.** Even a small one. This project deliberately favors runnable proof over untested code — see the existing `tests/` for the expected shape (small, focused, one behavior per test).

## Getting set up

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env
alembic upgrade head
pytest tests/ -v
```

## Adding a new SIEM connector

This is the most common contribution type once Phase 6+ lands. Every connector:

1. Lives in its own file under `backend/connectors/` (e.g. `connectors/your_siem.py`).
2. Subclasses `SIEMConnector` (`connectors/base.py`) and implements `authenticate()`, `fetch_alerts()`, `normalize_event()`.
3. Maps every field it can into `CommonAlertSchema` — leave fields `None` if the source doesn't provide them, never guess or fabricate a value.
4. Raises `NotSupportedError` for operations the source genuinely can't do (e.g. no single-alert lookup) — don't fake success.
5. Comes with tests using representative (anonymized/synthetic) sample payloads from that vendor.

A full step-by-step connector guide will land in `docs/CONNECTOR_GUIDE.md` alongside the first real connector (Phase 6).

## Commit style

Short, present-tense, one logical change per commit. If your change corresponds to one of the architecture doc's numbered phases, referencing it in the message is helpful but not required (e.g. `Phase 6: Elastic connector`).

## Reporting bugs / proposing features

Open an issue. For anything touching security-sensitive behavior (auth, prompt-injection handling, secret management), see [`SECURITY.md`](SECURITY.md) instead of a public issue.

## Code of Conduct

Be respectful, be constructive. A full `CODE_OF_CONDUCT.md` will be added as the contributor base grows.
