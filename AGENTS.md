# PROJECT: VulnIntel AI

## Project Objective

Build a production-oriented, AI-powered Cybersecurity Vulnerability Intelligence and Remediation Platform.

The platform must ingest real-world vulnerability data, maintain an enterprise asset inventory, identify vulnerable software versions, calculate contextual security risk, and provide evidence-backed AI investigation and remediation recommendations.

This must be a complete software application, not a chatbot demonstration.

## Mandatory Technology Stack

Backend:
- Python 3.12+
- FastAPI
- SQLAlchemy
- PostgreSQL
- Alembic
- Pydantic

AI:
- LangChain
- LangGraph
- Qdrant
- Configurable LLM provider
- Sentence Transformers

Fine-tuning:
- PyTorch
- Hugging Face Transformers
- PEFT
- LoRA / QLoRA
- TRL

Experiment Tracking:
- MLflow

Background Processing:
- Celery
- Redis

Frontend:
- React
- TypeScript
- Recharts

Infrastructure:
- Docker
- Docker Compose
- Pytest

## Architecture Requirements

Implement a modular monolith with clearly separated layers:

1. API layer
2. Business service layer
3. Repository layer
4. Database layer
5. Data ingestion layer
6. RAG layer
7. LangGraph orchestration layer
8. LLM provider layer
9. ML training and evaluation layer
10. Background worker layer

Do not mix database operations, LLM prompts, business rules and HTTP handlers in the same files.

Use dependency injection and typed interfaces.

## Data Sources

Implement ingestion from:

- NVD CVE API
- CISA KEV catalog
- FIRST EPSS daily dataset
- OSV API
- MITRE CWE

All ingestion pipelines must support:

- Initial backfill
- Incremental synchronization
- Pagination
- Retry with exponential backoff
- Idempotent upserts
- Schema validation
- Deduplication
- Error logging
- Source timestamps
- Ingestion run tracking

Persist original source data for traceability.

## Business Requirements

Implement:

1. Organization and user management.
2. Role-based access control.
3. Enterprise asset inventory.
4. CSV asset imports.
5. CycloneDX and SPDX SBOM import.
6. Software product and version normalization.
7. Vulnerability matching.
8. Risk scoring.
9. Vulnerability exploration.
10. AI investigation.
11. Evidence-backed recommendations.
12. Human approval.
13. Remediation tracking.
14. Security analytics.
15. ML model evaluation.

## Risk Engine

Implement a deterministic, independently tested risk calculation engine.

Initial weighting:

- CVSS: 25%
- EPSS: 25%
- KEV: 20%
- Asset criticality: 15%
- Internet exposure: 10%
- Ransomware indicator: 5%

Return a score from 0 to 100 with individual factor contributions and explanations.

Handle missing metrics explicitly. Do not silently treat missing information as zero.

Risk scores must never be generated or modified by the LLM.

## RAG Requirements

Use Qdrant to store searchable security knowledge.

Index:
- CVE descriptions
- Security advisories
- CWE documentation
- KEV descriptions
- OSV records
- Remediation documentation

Implement:
- Embedding generation
- Incremental indexing
- Hybrid retrieval
- Metadata filtering
- Optional reranking
- Evidence deduplication
- Citation validation

All factual AI claims must be supported by evidence records.

## LangGraph Requirements

Build a stateful investigation workflow.

Required nodes:
- Input validation
- Entity extraction
- Vulnerability retrieval
- Threat intelligence retrieval
- Qdrant retrieval
- Evidence validation
- Deterministic risk assessment
- LLM analysis
- Recommendation validation
- Human approval
- Report persistence

Support:
- Conditional routing
- Bounded retries
- Persistent checkpoints
- Human interruption and resumption
- Failure recovery
- Structured state
- Investigation audit trails

Do not create unnecessary autonomous agents.

## LoRA Requirements

Create an independent ML pipeline for:

- Vulnerability classification
- CWE classification
- Security information extraction
- Structured report generation

Use curated and deduplicated training examples.

Split data by vulnerability identity/family to avoid leakage.

Evaluate:
- Base model
- Prompt-engineered base model
- LoRA fine-tuned model

Track classification metrics, JSON validity, unsupported claims and recommendation validity.

LoRA must be optional for application execution.

## MLflow Requirements

Track:
- Dataset versions
- Model versions
- Hyperparameters
- Training loss
- Validation loss
- Classification metrics
- RAG evaluation
- Model comparison
- Artifacts
- Evaluation reports

## Security Requirements

- Enforce organization-level tenant isolation.
- Implement RBAC.
- Validate uploaded files.
- Protect against prompt injection.
- Treat external documents as untrusted.
- Never allow unrestricted SQL generation or execution.
- Never execute LLM-generated shell commands.
- Never automatically patch assets.
- Require explicit human approval.
- Keep audit logs for important actions.

## Engineering Standards

- Type hints throughout Python code.
- Pydantic schemas for API contracts.
- SQLAlchemy models and repositories.
- Alembic database migrations.
- Centralized exception handling.
- Structured logging.
- Configuration through environment variables.
- Unit and integration tests.
- Meaningful docstrings.
- No hardcoded credentials.
- No placeholder implementations in completed modules.
- No fake data presented as live intelligence.

## Development Rules

1. Implement the project in small, independently testable phases.
2. Before each phase, inspect existing code and architecture.
3. Never rewrite working modules unnecessarily.
4. Do not duplicate existing abstractions.
5. Do not create files without a clear architectural purpose.
6. Write tests alongside each feature.
7. Run relevant tests before marking a task complete.
8. Keep API contracts and database schemas synchronized.
9. Update documentation when architecture or APIs change.
10. Report incomplete functionality honestly.

## Definition of Done

A feature is complete only when:
- Its implementation exists.
- It integrates with the correct layers.
- Its validation is implemented.
- Tests pass.
- Error handling exists.
- Documentation is updated.
- It works with the actual application rather than isolated mock data.

Start by reviewing the architecture and implementing Phase 0. Do not attempt to generate the entire application in one operation.