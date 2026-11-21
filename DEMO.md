# VulnIntel AI local demo

## Prerequisites

- Docker Engine and Docker Compose v2.
- Python 3.12 and Node.js 20.19+ for local checks outside Compose.

## Start

```sh
cp .env.example .env
docker compose config --quiet
docker compose up --build -d
docker compose ps
```

All host ports bind to loopback. Wait for the migration service and API readiness before using the dashboard.

```sh
curl --fail http://127.0.0.1:8000/health/live
curl --fail http://127.0.0.1:8000/health/ready
curl --fail http://127.0.0.1:5173/
```

Open `http://127.0.0.1:5173`.

## Demonstration flow

1. Register a new organization and owner account.
2. Open **Assets** and create a server or import a CycloneDX/SPDX JSON/SBOM.
3. Open **Vulnerabilities**, select the asset, and run deterministic matching.
4. Open **Ingestion** through the API or run an official-source synchronization endpoint for CISA/EPSS/NVD/CWE/OSV.
5. Open **AI Analyst** and search evidence.
6. Start an investigation.
7. Approve or reject the workflow in **Remediation**.
8. Open **Model Ops** to verify whether fine-tuned inference is explicitly enabled.

No fake dashboard statistics or live vulnerability data are invented by the demo.

## API examples

Register:

```sh
curl -X POST http://127.0.0.1:8000/api/v1/auth/register \
  -H 'content-type: application/json' \
  -d '{"organization_name":"Demo Org","display_name":"Demo Owner","email":"owner@demo.example","password":"Demo secure password 2026!"}'
```

Use the returned `access_token` as a bearer token for subsequent calls.

## Verification

```sh
make test
make test-e2e
make test-backend-live
make lint
docker compose ps
docker compose logs --tail=100
```

The live source smoke test requires network access and the opt-in environment variable:

```sh
cd backend
VULNINTEL_RUN_LIVE_INGESTION=1 python -m pytest -q -m live tests/integration/test_ingestion_live.py
```

## Stop

```sh
docker compose down
```

Use `docker compose down --volumes` only when intentionally removing all local PostgreSQL, Redis, Qdrant, MLflow, and frontend-volume data.
