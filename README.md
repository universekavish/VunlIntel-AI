# VulnIntel AI

VulnIntel AI is a vulnerability intelligence platform currently at **Phase 3**. It includes organization management, official-source ingestion, tenant-scoped asset inventory, CSV/SBOM imports, software normalization, and deterministic vulnerability matching. Risk scoring, AI investigation, and remediation remain future phases.
**Phase 4 now adds deterministic risk scoring and risk history.**
**Phase 5 now adds tenant-isolated RAG indexing and retrieval.**
**Phase 6 now adds the LangGraph investigation workflow and human approval.**
**Phase 7 now adds an optional MLflow/LoRA pipeline; fine-tuning is not required for application startup.**
**Phase 8 now adds the responsive React/TypeScript cybersecurity SaaS dashboard.**

## Implemented foundation

- Python 3.12+ FastAPI backend, SQLAlchemy session management, Pydantic contracts, Alembic migrations, structured JSON logging, and centralized API errors.
- React, TypeScript, Vite, and Recharts frontend scaffold and lint/type-check configuration.
- Docker Compose development stack: API, frontend, PostgreSQL, Redis, Qdrant, MLflow, Celery worker, and an automatic one-shot migration step.
- Architecture and module boundaries in [docs/architecture.md](docs/architecture.md).
- Argon2id password hashing, signed short-lived JWT access tokens, database-backed role checks, tenant isolation, and security audit events.
- Independent NVD, CISA KEV, FIRST EPSS, OSV, and MITRE CWE ingestion clients with retries, pagination, source payload traceability, validation, normalization, idempotent upserts, and run tracking.
- Environment template, migration/test Make targets, and VS Code development settings.
- Liveness and database readiness endpoints; Compose health checks for long-running services.

## Prerequisites

- Docker Engine with Docker Compose v2.
- `make` (optional; commands can also be run directly).
- Node.js 20.19+ and npm for frontend checks outside Docker.
- Python 3.12+ and `pip` for backend checks outside Docker.

## Start the development stack

```sh
cp .env.example .env
# Review .env. The sample DSNs follow the configured service passwords; use URL-safe
# passwords, or URL-encode special characters in DSNs.
docker compose config --quiet
docker compose up --build -d
docker compose ps
```

Or, with Make:

```sh
make setup
make config
make up
make ps
```

The local services bind published ports to `127.0.0.1`:

| Service | URL / endpoint |
|---|---|
| API liveness | http://127.0.0.1:8000/health/live |
| API readiness | http://127.0.0.1:8000/health/ready |
| API docs | http://127.0.0.1:8000/docs |
| Frontend scaffold | http://127.0.0.1:5173 |
| Qdrant | http://127.0.0.1:6333 |
| MLflow | http://127.0.0.1:5000 |
| PostgreSQL | `127.0.0.1:5432` |
| Redis | `127.0.0.1:6379` |

Wait until `docker compose ps` reports healthy services. Tail logs with `docker compose logs -f --tail=100`. Stop services with `docker compose down`; persisted development data remains in named volumes. To remove local service data intentionally, run `docker compose down --volumes`.

The one-shot `migrate` service applies `alembic upgrade head` before API and worker startup. Apply migrations manually after schema changes with `make migrate`.

## Identity API

All identity routes use `/api/v1`:

| Method | Path | Access |
|---|---|---|
| `POST` | `/auth/register` | Public; creates an organization and its initial owner |
| `POST` | `/auth/login` | Public; returns a short-lived access token |
| `GET` | `/auth/me` | Authenticated |
| `GET` | `/organizations/current` | Any active organization member |
| `GET` | `/organizations/current/members` | Owner or administrator |
| `POST` | `/organizations/current/members` | Owner or administrator |
| `PATCH` | `/organizations/current/members/{user_id}/role` | Owner |
| `DELETE` | `/organizations/current/members/{user_id}` | Owner or administrator; deactivates the account |

## Dashboard

The React dashboard provides authenticated views for:

- Security overview analytics
- Asset criticality and ingestion health
- Vulnerability matches and evidence
- Asset inventory CRUD
- AI evidence search
- LangGraph investigation details and approval
- Human remediation decisions
- Optional fine-tuned model runtime status

Dashboard statistics are derived from live API responses. The overview does not contain fabricated counts, chart values, or source results. Every API request includes loading and error handling, and empty data sets use explicit empty states.

Set `VITE_API_BASE_URL` for deployments that use an API origin other than `http://127.0.0.1:8000`.

See [IMPLEMENTATION_REPORT.md](IMPLEMENTATION_REPORT.md), [DEMO.md](DEMO.md), and [infra/deployment.md](infra/deployment.md) for final verification, demo, and deployment operations.

## Asset inventory API

| Method | Path | Access |
|---|---|---|
| `POST` | `/assets` | Analyst, administrator, or owner |
| `GET` | `/assets` | Active organization members |
| `GET` | `/assets/{asset_id}` | Active organization members |
| `PATCH` | `/assets/{asset_id}` | Analyst, administrator, or owner |
| `DELETE` | `/assets/{asset_id}` | Analyst, administrator, or owner |
| `POST` | `/assets/imports/csv` | Analyst, administrator, or owner |
| `POST` | `/assets/imports/sbom?format=cyclonedx\|spdx` | Analyst, administrator, or owner |
| `POST` | `/assets/{asset_id}/matches` | Analyst, administrator, or owner |
| `GET` | `/assets/{asset_id}/matches` | Active organization members |

## Deterministic risk API

```text
POST /api/v1/assets/{asset_id}/risk
GET  /api/v1/assets/{asset_id}/risk/history
```

Risk calculation is Python-only and never accepts LLM-derived inputs. The default formula normalizes each signal and applies:

| Factor | Weight |
|---|---:|
| CVSS | 25% |
| EPSS | 25% |
| CISA KEV | 20% |
| Asset criticality | 15% |
| Internet exposure | 10% |
| Ransomware indicator | 5% |

CVSS is divided by 10, EPSS is already a 0–1 probability normalized by 100, KEV/ransomware/exposure use 100 for present and 0 for absent, and asset criticality maps low=25, medium=50, high=75, critical=100.

The score is a weighted average of available signals: each available factor retains its original weight, then available weights are renormalized to 100. Missing factors remain explicit, receive no inferred value, reduce confidence to the available-weight percentage, and are listed in `missing_signals`. The resulting score is always in 0–100.

Default threshold boundaries are low `<=25`, medium `<=50`, high `<=75`, and critical `>75`. Request bodies may supply custom thresholds and weights. Custom weights must be non-negative percentages totaling 100; thresholds must satisfy `0 <= low < medium < high <= 100`.

A risk request may supply `cvss`, `epss`, `kev`, `internet_exposure`, and `ransomware` overrides directly or select a `vulnerability_id`. CVE context can supply CVSS and EPSS data, while CISA KEV presence is determined from the ingested KEV table. Asset criticality, internet exposure, and ransomware defaults come from the asset unless request overrides are present.

Every successful calculation is inserted into tenant-scoped `risk_history`. History retains the score, band, confidence, factor contributions, missing signals, explanations, thresholds, vulnerability ID, and calculation timestamp.

## RAG API

| Method | Path | Access |
|---|---|---|
| `POST` | `/rag/index` | Owner, administrator, or analyst |
| `POST` | `/rag/search` | Any active organization member |

The RAG pipeline prepares CVE, KEV, CWE, OSV, and vendor-advisory source text using LangChain `Document` and text splitters. Incremental indexing stores source identity, chunk index, SHA-256 content digest, and Qdrant point ID. Re-indexing unchanged chunks is skipped.

Qdrant collections are isolated by organization ID. Retrieval also applies an organization payload filter as a second boundary. Supported filters are source type, document type, and source ID. Search supports dense semantic retrieval, dense-plus-lexical hybrid ranking, and optional lexical reranking.

Every returned citation is revalidated against a persisted normalized source or vendor-advisory record. Cross-source and cross-tenant evidence is not returned.

Configure `RAG_EMBEDDING_PROVIDER` as `sentence_transformer` for the real Sentence Transformers implementation or `deterministic` for offline tests. `RAG_EMBEDDING_MODEL` and `RAG_EMBEDDING_DIMENSIONS` select and validate the model.

## Investigation workflow API

| Method | Path | Access |
|---|---|---|
| `POST` | `/investigations` | Analyst, administrator, or owner |
| `GET` | `/investigations` | Active organization members |
| `GET` | `/investigations/{investigation_id}` | Active organization members |
| `POST` | `/investigations/{investigation_id}/approve` | Analyst, administrator, or owner |

The workflow validates input and entities, retrieves normalized vulnerability and threat records, retries Qdrant retrieval up to three attempts, validates citations, calculates deterministic risk, generates structured evidence-grounded analysis, validates recommendations, and interrupts for explicit human approval.

Approved decisions cannot enable patch execution or shell commands. Recommendations are evidence-backed and `patch_allowed` remains false.

LangGraph checkpoints use PostgreSQL in production and an isolated in-memory checkpointer for SQLite/test execution. Investigations persist thread IDs, typed state, reports, approval decisions, and append-only audit events. Resume calls the same LangGraph thread and continue from the human approval interrupt.

CSV imports require `name` and `asset_type`. Optional software columns are `software_name`, `software_version`, `ecosystem`, `cpe`, and `purl`. CycloneDX and SPDX imports accept validated JSON uploads and reject unknown formats, malformed JSON, oversized files, missing components/packages, and script-bearing or external payload behavior. Asset and software records remain organization-scoped.

Roles are `owner`, `admin`, `analyst`, and `viewer`. The owner is created only during organization registration; member endpoints cannot create or promote an owner. Administrators may create analyst/viewer accounts and deactivate only analyst/viewer accounts. The API re-reads each user's active status and role from PostgreSQL on authenticated requests, so deactivation and role changes take effect immediately even for previously issued access tokens. Authentication failures use a generic response to avoid exposing account existence.

Passwords require 12–128 characters and are stored using Argon2id. Access tokens use HS256 with required issuer, audience, issued-at, expiration, and token-ID claims. Set `JWT_SECRET` to a unique random value of at least 32 bytes before deploying; the sample value is development-only. Users belong to exactly one organization in this phase. Membership queries filter by the authenticated database user's organization, and cross-tenant member IDs return not found.

Important identity events (organization registration, successful login, member creation, role changes, and deactivation) are persisted in the `audit_events` table in the same transaction as the action. Audit records are not exposed through an API in this phase.

## Vulnerability ingestion

| Source | Official access |
|---|---|
| NVD CVE | NVD CVE API 2.0, incrementally filtered by `lastModStartDate` |
| CISA KEV | Official JSON catalog download |
| FIRST EPSS | Official current CSV/GZIP daily dataset or API by CVE batch |
| OSV | Official OSV.dev query-batch and vulnerability-detail endpoints |
| MITRE CWE | Official current XML ZIP download |

Source payloads are stored unchanged in `source_records` with a SHA-256 content digest. Normalized tables are `cve_records`, `kev_records`, `epss_records`, `osv_records`, and `cwe_records`. `ingestion_runs` records mode, status, lifecycle timestamps, fetched/stored/skipped/error counts, source timestamp, and cursors or error summaries.

Owner users can inspect recent runs and trigger synchronization through `/api/v1/ingestion/runs` and `/api/v1/ingestion/sync/{source}?mode=initial|incremental`. OSV synchronization requires `cve_ids=CVE-2021-44228,...` because OSV does not expose a global CVE-only listing endpoint. The API performs bounded in-process requests; production scheduling should use Celery after that integration is completed in a later phase.

Configure optional NVD API key and source URLs through the environment. Source endpoints are real; test records are only fixture payloads used by the test suite. No fake vulnerability records are inserted as live intelligence.

Run fixture tests with:

```sh
make test-backend
```

Run the opt-in live-data smoke test only when network access is available:

```sh
cd backend
VULNINTEL_RUN_LIVE_INGESTION=1 python -m pytest -q -m live tests/integration/test_ingestion_live.py
```

## Verify the setup

```sh
# Validate Compose interpolation and schema against the installed Compose CLI.
docker compose config --quiet

# Start and check service health.
docker compose up --build -d
docker compose ps

# Check API and frontend responses.
curl --fail http://127.0.0.1:8000/health/live
curl --fail http://127.0.0.1:8000/health/ready
curl --fail http://127.0.0.1:5173/

# Run code checks (requires Python 3.12+ and Node.js 20+ locally).
make test
make lint
```

The test suite includes unit tests for hashing/token validation and integration tests that apply the Alembic migration to isolated SQLite databases, then exercise the HTTP authentication, RBAC, and tenant-isolation paths. The application is configured for PostgreSQL in Compose; run production-like database integration tests against PostgreSQL before deployment.

The backend and frontend are bind-mounted for development. Dependency installation happens in their images; rebuilding after changing dependency manifests is required. The frontend `node_modules` directory is held in a Compose-managed volume.

For checks without Docker, install dependencies first:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e "backend[dev]"
(cd frontend && npm ci)
```

## Repository layout

```text
backend/       FastAPI application layers, migrations, and unit/integration tests
frontend/      React/TypeScript application and frontend tests
ml/            Future training, evaluation, and dataset pipelines
docs/          Architecture and development documentation
infra/         Container definitions and database bootstrap
compose.yaml   Local multi-service development environment
```

## Development status

Phase 2 establishes official-source ingestion: independent HTTP clients, pagination/download handling, bounded retries and rate-limit backoff, source payload traceability, Pydantic/shape validation, normalization, SHA-256 deduplication, idempotent database upserts, and ingestion run tracking. The Celery app remains an execution shell with no registered business tasks. MLflow, asset inventory, risk scoring, AI investigation, ML training, and production deployment controls remain future work.

See [docs/architecture.md](docs/architecture.md) for the intended boundaries and phased implementation sequence.
