"""Optional fine-tuned model status and inference routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import DatabaseSession, require_roles
from app.db.models import User
from app.ml.inference import (
    InferenceRequest,
    InferenceResponse,
    InferenceStatus,
    model_inference,
)
from app.schemas.roles import UserRole

router = APIRouter(prefix="/ml", tags=["ml"])
AnalystOrHigher = Annotated[
    User,
    Depends(require_roles(UserRole.OWNER, UserRole.ADMIN, UserRole.ANALYST)),
]


@router.get("/inference/status", response_model=InferenceStatus)
def inference_status(
    user: AnalystOrHigher,
) -> InferenceStatus:
    return model_inference.status()


@router.post("/inference/generate", response_model=InferenceResponse)
def inference_generate(
    payload: InferenceRequest,
    user: AnalystOrHigher,
    session: DatabaseSession,
) -> InferenceResponse:
    try:
        return model_inference.generate(payload)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
