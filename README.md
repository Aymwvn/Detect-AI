# DetectAI

**Evidence-first, SIEM-agnostic AI security alert triage & investigation engine.**

DetectAI sits between raw security telemetry (SIEM, EDR, IDS, cloud alerts) and the human analyst. It ingests alerts from multiple sources, normalizes them into one common schema, deduplicates and correlates related events into incidents, maps them to MITRE ATT&CK, and produces structured, auditable AI-assisted analysis — without letting the AI hide its reasoning or make an unreviewable decision.

It is not an autonomous SOC, not a chatbot wrapper, and not tied to a single SIEM or LLM vendor. It's an investigation accelerant: the analyst stays in control, and every AI claim is traceable back to real evidence.

## Why

SOC analysts drown in alerts — duplicates, low-context detections, and inconsistent triage make investigation slow and error-prone. Most "AI SOC" tools either auto-close alerts with an untrustworthy black-box score, or wrap a chatbot around raw logs and hallucinate. DetectAI's approach: keep every AI conclusion evidence-backed and validated, run a fully functional rule-based pipeline even with no LLM configured, and never assign a MITRE technique or risk score without a cited reason.

## Status

Feature-complete for MVP scope. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design and phased build plan.

| Milestone | Status |
|---|---|
| M1 — Foundation (schema, API skeleton, database) | ✅ Done |
| M2 — Ingestion (4 connectors: Elastic, Splunk, Wazuh, generic webhook/REST) | ✅ Done |
| M3 — Correlation core (dedup, correlation, rule-based risk) | ✅ Done |
| M4 — AI layer (LLM abstraction, evidence-first analysis, MITRE mapping) | ✅ Done |
| M5 — Product (React dashboard, analyst feedback) | ✅ Done |
| M6 — Hardening & proof (auth/RBAC, synthetic scenarios, deployment) | ✅ Done |

## Architecture (high level)

```
SIEM/EDR/Cloud → Connector → Normalization → Dedup → Correlation
   → Rule-Based Risk Engine ─┬─ LLM Analysis (evidence-first, schema-validated)
                              └─ MITRE ATT&CK Mapping
   → Risk Scoring → PostgreSQL → FastAPI → React SOC Dashboard → Analyst Feedback
```

Full diagram and rationale in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). API reference in [`docs/API.md`](docs/API.md). Adding a new SIEM connector: [`docs/CONNECTOR_GUIDE.md`](docs/CONNECTOR_GUIDE.md).

## Tech stack

- **Backend**: FastAPI (Python), SQLAlchemy (async), PostgreSQL, Alembic, Redis, JWT auth (RBAC: viewer/analyst/admin)
- **AI**: provider-agnostic (`LLMProvider` abstraction) — OpenAI-compatible, Anthropic-compatible, or local Ollama; fully functional with AI disabled
- **Frontend**: React + Vite + TypeScript
- **Deployment**: Docker Compose

## Getting started (Docker — recommended)

```bash
cp .env.example .env
# edit .env — at minimum, set a real SECRET_KEY:
# python -c "import secrets; print(secrets.token_hex(32))"

docker compose up -d
# add --profile ollama to also start a local Ollama instance

# bootstrap the first admin user (public registration only grants "viewer")
docker compose exec backend python scripts/create_admin.py admin your-password
```

- Dashboard: http://localhost:8080
- API docs: http://localhost:8000/docs

**Honest note**: the Dockerfiles and compose file were written carefully but not build-verified in the environment that produced this repo (no Docker daemon available there). Test the build yourself before relying on it for anything important, and open an issue if something doesn't work as documented.

## Getting started (without Docker)

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env
# leave AI_PROVIDER=none to run without any LLM configured
# leave DATABASE_URL pointed at sqlite for a quick local run, or a real Postgres

alembic upgrade head
python scripts/create_admin.py admin your-password
uvicorn app.main:app --reload --port 8000
```

```bash
cd frontend
npm install
cp .env.example .env.local
npm run dev
```

Run tests:

```bash
cd backend && pytest tests/ -v            # 275+ tests
cd frontend && npm run build && npm run lint
```

Run the synthetic-scenario benchmark (architecture doc §24):

```bash
cd backend && python scripts/run_benchmark.py
```

See [`docs/sample_benchmark_output.txt`](docs/sample_benchmark_output.txt) for a sample run. Note: the AI-assisted figures in that benchmark use a scripted fake provider, not a real LLM (none was available to test against) — re-run with a real `AI_PROVIDER` configured for numbers that reflect actual model behavior.

## Project structure

```
detect-ai/
├── backend/         # FastAPI app, DB models, migrations, connectors, AI layer
│   ├── connectors/    # SIEM/EDR connector plugins (Elastic, Splunk, Wazuh, generic)
│   ├── datasets/       # Synthetic attack scenario generators
│   ├── scripts/         # Admin bootstrap, benchmark runner
│   └── tests/            # 275+ tests
├── frontend/         # React SOC dashboard
├── docs/               # Architecture, API reference, connector guide
├── docker-compose.yml   # Full stack deployment
└── .env.example
```

## License

MIT — see [`LICENSE`](LICENSE).
