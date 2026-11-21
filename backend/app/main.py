"""FastAPI application entry point."""

import logging
import time
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from app.api.health import router as health_router
from app.api.routes.assets import router as assets_router
from app.api.routes.auth import router as auth_router
from app.api.routes.ingestion import router as ingestion_router
from app.api.routes.investigations import router as investigations_router
from app.api.routes.ml import router as ml_router
from app.api.routes.organizations import router as organizations_router
from app.api.routes.rag import router as rag_router
from app.core.config import get_settings
from app.core.exceptions import (
    InvalidCredentialsError,
    PermissionDeniedError,
    ResourceConflictError,
    ResourceNotFoundError,
)
from app.core.logging_config import configure_logging

configure_logging()
settings = get_settings()

app = FastAPI(
    title="VulnIntel AI API",
    description="Vulnerability intelligence and remediation platform API.",
    version="0.1.0",
    docs_url="/docs" if settings.environment.casefold() == "development" else None,
    redoc_url=None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def observability_middleware(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid4())
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logging.getLogger("vulnintel.request").exception(
            "request failed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
            },
        )
        raise
    duration_ms = round((time.perf_counter() - started) * 1000, 3)
    logging.getLogger("vulnintel.request").info(
        "request completed",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
        },
    )
    response.headers["x-request-id"] = request_id
    return response


app.include_router(health_router)
app.include_router(auth_router, prefix="/api/v1")
app.include_router(organizations_router, prefix="/api/v1")
app.include_router(ingestion_router, prefix="/api/v1")
app.include_router(assets_router, prefix="/api/v1")
app.include_router(rag_router, prefix="/api/v1")
app.include_router(investigations_router, prefix="/api/v1")
app.include_router(ml_router, prefix="/api/v1")


@app.exception_handler(ResourceConflictError)
async def handle_resource_conflict(
    request: Request,
    exc: ResourceConflictError,
) -> JSONResponse:
    """Translate expected uniqueness conflicts to a stable response."""
    return JSONResponse(status_code=409, content={"detail": str(exc)})


@app.exception_handler(PermissionDeniedError)
async def handle_permission_denied(
    request: Request,
    exc: PermissionDeniedError,
) -> JSONResponse:
    """Translate service-layer authorization failures to forbidden responses."""
    return JSONResponse(status_code=403, content={"detail": str(exc)})


@app.exception_handler(ResourceNotFoundError)
async def handle_not_found(
    request: Request,
    exc: ResourceNotFoundError,
) -> JSONResponse:
    """Return a not-found response without disclosing cross-tenant resources."""
    return JSONResponse(status_code=404, content={"detail": str(exc)})


@app.exception_handler(InvalidCredentialsError)
async def handle_invalid_credentials(
    request: Request,
    exc: InvalidCredentialsError,
) -> JSONResponse:
    """Return one generic authentication error for invalid credentials."""
    return JSONResponse(
        status_code=401,
        content={"detail": "Invalid email or password"},
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.exception_handler(SQLAlchemyError)
async def handle_database_error(request: Request, exc: SQLAlchemyError) -> JSONResponse:
    """Log database failures without exposing driver details to clients."""
    logging.getLogger(__name__).error(
        "Database operation failed",
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
