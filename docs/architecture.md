# VulnIntel AI architecture

## Phase 1 scope

This document defines the target boundaries for a modular monolith. Phase 0 established the layout and local services. Phase 1 implements application settings, structured logging, database sessions and migrations, versioned identity endpoints, password hashing, JWT access authentication, organization membership RBAC, tenant isolation, security audit events, and liveness/readiness probes. The remaining packages are architectural boundaries, not claims that their future features are implemented.

## System context

```text
Browser
  |
  v
React + TypeScript frontend ---- HTTP ----> FastAPI API
                                                |
                  +-----------------------------+------------------------+
                  |              |              |            |           |
             PostgreSQL       Redis          Qdrant       MLflow      Celery
                                                               ^          |
                                                               +-- worker-+
```

The API and worker share a Python application package but have separate process entry points. PostgreSQL is the system of record. Redis is the Celery broker and future cache. Qdrant is the vector store. MLflow is the experiment tracking service. The local Compose stack is for development and is not a production deployment specification.

## Backend boundaries

| Package | Responsibility |
|---|---|
| `app/api/` | HTTP routing, request/response orchestration, dependency wiring |
| `app/core/` | Settings, logging, errors, and cross-cutting primitives |
| `app/services/` | Business workflows and policy enforcement |
| `app/repositories/` | Persistence interfaces and SQLAlchemy implementations |
| `app/db/` | SQLAlchemy metadata, session setup, and database entities |
| `app/schemas/` | Pydantic API and service-boundary schemas |
| `app/ingestion/` | Source adapters, normalization, synchronization, and run tracking |
| `app/rag/` | Embedding, indexing, retrieval, evidence handling, and citations |
| `app/workflows/` | LangGraph investigation state, routing, and checkpoint integration |
| `app/llm/` | Provider interfaces and provider-specific clients/prompts |
| `app/ml/` | Training, evaluation, and MLflow integration |
| `app/workers/` | Celery app, task registration, and background execution |
| `alembic/` | Versioned database schema migrations |

HTTP handlers must not own business rules or SQL. Repositories must not contain prompts. Risk calculations must remain deterministic application code. External source content is untrusted input. AI-produced claims require validated evidence, and AI output must never set risk scores or execute commands.

### Phase 2 ingestion boundaries

`app/ingestion/` contains independent source clients and a source-neutral orchestration service. Source clients validate only the official protocol shape needed for that source: NVD CVE records, CISA KEV catalog entries, FIRST EPSS score rows, OSV vulnerability objects, and MITRE CWE weaknesses. HTTP calls use bounded exponential backoff and honor NVD and CISA-style `Retry-After`/transport/rate-limit behavior through the shared client.

NVD uses CVE API 2.0 pagination and `lastModStartDate`/`lastModEndDate` for incremental runs. CISA KEV and MITRE CWE use their official downloads. FIRST EPSS uses the official gzip daily dataset or API batch mode. OSV uses official `querybatch` and `/v1/vulns/{id}` calls because OSV.dev does not provide a global CVE-only listing endpoint; callers supply known identifiers. Source payloads remain in `source_records`, while normalized entities are persisted in source-specific tables. Repeating identical data does not create duplicate source or normalized primary keys.

Every run creates an `ingestion_runs` lifecycle row before fetching. The final status accounts for fetched, stored, skipped, and errored records. Source timestamps and pagination/download cursors are persisted when the source provides them. Network failures raise without presenting live or fixture data as successful intelligence.

### Phase 3 asset and matching boundaries

Assets, software products, installed asset software, and vulnerability matches are tenant-scoped database entities. Asset management is exposed through `/api/v1/assets`; CSV and SBOM imports use dedicated parsers and do not execute SBOM scripts or external package operations.

CSV imports require `name` and `asset_type`, accept bounded UTF-8 text, merge repeated external identifiers, and report row-level validation errors. CycloneDX imports read components and identifiers; SPDX imports read packages and `PACKAGE-MANAGER` or CPE external references. Inputs are limited to 5 MiB for CSV and 10 MiB for SBOM JSON.

Package identities are normalized by ecosystem. Package URLs are parsed for ecosystem, name, and version; CPE 2.3 strings provide vendor, product, and version constraints. Version comparisons use PEP 440 for PyPI, numeric prerelease-aware comparison for semver-style ecosystems, and bounded token comparison for other ecosystems.

OSV and NVD ranges are evaluated in application code. A product and range match is `confirmed`; exact package identity without a usable range is `potential`; no match after explicit affected evidence is `not_affected`; unresolved identity or ranges are `needs_review`. Every result stores its source, confidence, and structured evidence. Matching is repeatable and never uses an LLM to modify scores or outcomes.

### Phase 4 risk boundaries

The risk engine is a pure function under `app/services/risk.py`. It accepts typed signals and optional validated weights/thresholds and performs no database reads and no LLM calls. The application service under `app/services/risk_history.py` separately resolves source values and persists results.

The formula is a weighted average. Missing signals are excluded but never converted into a false zero; confidence equals the percentage of original weight that was available, and `missing_signals` is returned with the factor list. CVSS uses 0–10, EPSS uses 0–1, KEV uses boolean presence, criticality is low/medium/high/critical, and exposure/ransomware use booleans.

Default bands are low `<=25`, medium `<=50`, high `<=75`, and critical `>75`. Configuration can replace thresholds or weights, but custom weights must total 100. Every calculation appends one `risk_history` row for the organization and asset. History queries always include both tenant and asset filters.

### Phase 5 RAG boundaries

`app/rag/documents.py` converts normalized CVE, KEV, CWE, OSV, and vendor-advisory records into bounded LangChain `Document` chunks. Source identity, document type, chunk index, and a citation are retained as metadata. Original source data remains under the ingestion tables and source traceability records.

`app/rag/embeddings.py` supports a real Sentence Transformers provider and a deterministic offline provider for testing. `app/rag/vectorstore.py` manages one Qdrant collection per organization, creates keyword payload indexes for source/document/source-ID fields, and applies organization, source, and source-ID filters to every search.

Retrieval combines Qdrant cosine scores with deterministic lexical overlap for hybrid mode. Optional reranking gives lexical overlap additional weight. Identical evidence is deduplicated, and citations are resolved back to persisted normalized or vendor-advisory records before API output.

`rag_documents` stores the SQL-side chunk hash and Qdrant point identity. `rag_index_runs` records document/chunk counters and failures. The API cannot bypass tenant isolation through collection naming or metadata filters.

### Phase 6 investigation boundaries

`app/workflows/state.py` defines the typed graph state. `app/workflows/nodes.py` owns input/entity/vulnerability/threat/evidence/risk nodes. `app/workflows/llm_nodes.py` owns structured analysis, recommendation validation, and human interruption. `app/workflows/report.py` persists reports and audit events.

The graph executes these stages:

```text
input validation -> entity extraction -> vulnerability retrieval
-> threat retrieval -> bounded Qdrant retrieval -> evidence validation
-> deterministic risk assessment -> structured LLM analysis
-> recommendation validation -> human approval -> report persistence
```

Qdrant retrieval is retried at most three times. Empty or failed evidence routes to report persistence after the bounded retry budget. No evidence node permits unsupported factual claims to become recommendations.

The human approval node calls LangGraph `interrupt()`. Approval or rejection is supplied through `Command(resume=...)`; the graph resumes the saved checkpoint rather than starting from the first node. PostgreSQL `PostgresSaver` provides durable production checkpoints. Tests use `MemorySaver`.

Investigations and audit rows are organization-scoped. Cross-tenant lookups return not found. Starting investigations requires analyst/administrator/owner access; viewers may inspect persisted records but cannot initiate or approve.

### Phase 7 ML boundaries

The fine-tuning pipeline is independent of application startup. `ml/datasets/curate.py` validates and canonicalizes records, removes exact duplicates, and uses CVE/CWE/identifier families for leakage-resistant splits.

`ml/training/train_lora.py` lazily loads PyTorch, Transformers, PEFT, TRL, Datasets, and MLflow. GPU/MPS is required for training; CPU-only application execution is supported because fine-tuning libraries are optional extras. Training logs hyperparameters, training/validation losses, SHA-256 dataset versions, artifacts, and optional MLflow model versions.

`ml/evaluation/evaluate.py` compares base, prompt-engineered base, and LoRA variants through real test predictions. It reports exact match, JSON validity, unsupported claims, and recommendation validity. It never substitutes claimed or fabricated performance values.

`app/ml/inference.py` provides an optional, lazily loaded model service. Disabled mode performs no model download and returns a status only. Enabled inference supports CPU and accelerator execution and returns structured JSON only when the model emits parseable JSON.

### Identity data and authorization

`organizations` are tenant roots. Each `users` row references exactly one organization and has a globally unique normalized email, an Argon2id password hash, an active flag, and one of the `owner`, `admin`, `analyst`, or `viewer` roles. `audit_events` records registration, successful authentication, and membership mutations; each event is written in the same transaction as its action.

The initial owner is created atomically with organization registration. Member-management routes are scoped by the current user's organization ID loaded from the database, not by an organization ID supplied by the request. JWTs identify the user and include standard issuer/audience/expiry claims. Role claims are informational: each request resolves the user's current role and active state from PostgreSQL so role changes and deactivation invalidate existing authorization immediately. Member lookups always include both the requested user ID and the current organization ID. No user-facing endpoint can transfer or create the owner role.

The API uses synchronous SQLAlchemy sessions with one session per request. Services own transaction boundaries and policy decisions; repositories own persistence queries. Database schema changes are applied with Alembic and are not created implicitly by the API process.

## Frontend boundaries

`frontend/src/app/` owns application composition and routing. `components/` contains reusable presentation components. `features/` owns feature-specific UI and API interactions. `lib/` contains shared client utilities, and `types/` contains shared TypeScript contracts. UI features should call the API rather than connect directly to databases, queues, vector stores, or model providers.

## Dependency direction

```text
API -> services -> repository interfaces -> database adapters
                    |-> ingestion interfaces/adapters
                    |-> RAG interfaces/adapters
                    |-> workflow orchestration -> LLM provider interface
workers -> services/workflows
```

Use constructor/function dependency injection at boundaries. Keep provider implementations replaceable through typed interfaces and environment-based configuration. Avoid circular imports and avoid placing unrelated layers in a single module.

## Data flow (target)

1. Ingestion jobs fetch source records, validate them, retain source payloads and timestamps, deduplicate, then idempotently update normalized records.
2. Asset and SBOM imports pass file validation and normalization before persistence.
3. Vulnerability matching links normalized asset software to vulnerability records.
4. A deterministic risk service calculates factor contributions and explicit missing-data explanations.
5. An investigation workflow retrieves records and evidence, validates citations, and only then requests structured model analysis.
6. Recommendation validation and explicit human approval precede tracked remediation actions.
7. Background work is queued through Celery; important state transitions are audited.

These are intended flows, not implemented Phase 0 features.

## Local services and operational boundaries

`compose.yaml` starts PostgreSQL, Redis, Qdrant, MLflow, the API, Celery worker, and frontend. A one-shot migration container applies the current Alembic head before the API and worker start. All host-published ports bind to loopback. Compose health checks verify service availability; the API readiness probe checks PostgreSQL, and the worker's probe verifies that its Celery node responds. Development persistence uses named volumes. The MLflow development service uses SQLite and local artifacts; deployment environments must supply a supported durable backend and artifact store.

The `infra/` directory is reserved for environment-specific operational configuration; the local Compose stack remains at the repository root.

The Compose stack has no production secrets, ingress, authentication, backup policy, TLS, resource limits, or high availability. Use a managed secrets/configuration system and production-specific service configuration before deployment.

## Proposed implementation phases

0. Repository layout, architecture, development environment, and service health checks. *(Complete.)*
1. Configuration, structured logging, database engine/session, first migration, centralized errors, API versioning, health/readiness, organization/user identity, RBAC, audit records, and tenant isolation. *(Complete.)*
2. Source ingestion adapters and run tracking for NVD, CISA KEV, FIRST EPSS, OSV, and MITRE CWE. *(Complete.)*
3. Enterprise asset inventory, validated CSV/SBOM imports, software normalization, and vulnerability matching. *(Complete.)*
4. Deterministic, independently tested risk engine. *(Complete.)*
5. Qdrant knowledge indexing and evidence-grounded retrieval. *(Complete.)*
6. Stateful LangGraph investigation, human approval/resumption, and report persistence. *(Complete.)*
7. Remediation tracking and security analytics.
8. Optional LoRA training/evaluation pipeline and MLflow experiments. *(Complete.)*
9. Production hardening, PostgreSQL integration testing, observability, and deployment documentation.

Each phase must add tests and update API/database documentation for the behavior it introduces. Do not mark a feature complete until the application integration, validation, error handling, tests, and docs are in place.
