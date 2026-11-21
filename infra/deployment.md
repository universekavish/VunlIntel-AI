# VulnIntel AI deployment and operations

## Supported deployment shape

VulnIntel AI is a modular monolith. The API and worker share the Python package; PostgreSQL is the system of record, Redis is the worker broker, Qdrant stores vector knowledge, and MLflow tracks optional experiments.

The repository Compose file is for development and demonstration. It is not a production security boundary.

## Production prerequisites

- Python 3.12 or container images built from the backend Dockerfile.
- Managed PostgreSQL with backups and a migration role distinct from the runtime role.
- TLS termination and an ingress controller or reverse proxy.
- Managed Redis or a private, authenticated Redis deployment.
- Managed or persistent Qdrant with backups and resource limits.
- A durable MLflow tracking server and artifact store.
- Secret-manager values for `JWT_SECRET`, database credentials, Redis credentials, API keys, and optional LLM credentials.
- DNS names for API and frontend origins.
- Central log collection that consumes structured JSON logs.

## Configuration

Start with `.env.example`, but replace every development credential. Required application settings include:

- `DATABASE_URL`
- `JWT_SECRET`
- `JWT_ISSUER`
- `JWT_AUDIENCE`
- `REDIS_URL`
- `QDRANT_URL`
- `MLFLOW_TRACKING_URI`
- `CORS_ORIGINS`
- `VULNINTEL_ML_ENABLED`

`JWT_SECRET` must contain at least 32 bytes and must never equal the repository's local-development secret outside development/test environments.

## Migration and startup

Run migrations before deploying API replicas:

```sh
cd backend
alembic upgrade head
```

The Compose `migrate` service enforces this order for local startup. Production orchestration should run migrations as a pre-deploy Job or release task and stop on migration failure.

API startup does not start fine-tuning or download a base model unless `VULNINTEL_ML_ENABLED=true`.

## Health checks

- `/health/live`: process liveness only.
- `/health/ready`: process readiness and database query.
- PostgreSQL: `pg_isready`.
- Redis: authenticated `PING`.
- Qdrant: `/readyz` or TCP readiness.
- MLflow: `/health`.
- API: `/health/ready`.
- Celery: worker node ping.
- Frontend: root HTTP response.

Add ingress/liveness probes only after confirming their environment-specific network behavior. Never use readiness checks as a reason to delete persistent data.

## Observability

Application logs are JSON records. Requests include `request_id`, method, path, status code, and duration. Do not log passwords, bearer tokens, LLM secrets, or uploaded source payload bodies. Retain request IDs in ingress and proxy logs for cross-service tracing.

Minimum production alerts:

- Readiness endpoint failures.
- Database migration failures.
- Ingestion run failures.
- Qdrant indexing failures.
- Investigation stuck in `waiting_approval`.
- 5xx and authentication failure rates.
- Disk and memory pressure on PostgreSQL/Qdrant.

## Security deployment requirements

- Bind local Compose ports to loopback only.
- Terminate TLS at ingress.
- Rotate JWT, database, Redis, Qdrant, and MLflow credentials.
- Restrict CORS to frontend origins.
- Apply rate limits at ingress for authentication and upload routes.
- Run containers as non-root where the selected base image permits.
- Enforce tenant checks in every service/repository that reads assets or investigations.
- Keep LLM output out of risk calculations and shell execution.
- Require explicit approval before remediation.

## Backup and recovery

Back up PostgreSQL with point-in-time recovery. Back up Qdrant storage separately if real-time vector recovery is required. Test migration rollback and restoration in a staging environment before production use.
