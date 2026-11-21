"""CPU-safe optional model inference service."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from app.core.config import get_settings


class InferenceStatus(BaseModel):
    enabled: bool
    base_model: str | None = None
    adapter_path: str | None = None
    model_loaded: bool
    cpu_safe: bool = True


class InferenceRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=4000)
    max_new_tokens: int = Field(default=256, ge=1, le=1024)


class InferenceResponse(BaseModel):
    text: str
    structured_json: dict[str, Any] | None = None
    adapter_used: bool


class OptionalModelInference:
    """Load a fine-tuned model only when explicitly enabled.

    Application startup never imports Torch or Transformers. Disabled mode is a
    deliberate status response and does not fabricate a model result.
    """

    def __init__(self) -> None:
        self._model = None
        self._tokenizer = None
        self._adapter_used = False

    def status(self) -> InferenceStatus:
        settings = get_settings()
        return InferenceStatus(
            enabled=settings.vulnintel_ml_enabled,
            base_model=settings.vulnintel_ml_base_model,
            adapter_path=settings.vulnintel_ml_adapter_path,
            model_loaded=self._model is not None,
            cpu_safe=True,
        )

    def load(self) -> None:
        settings = get_settings()
        if not settings.vulnintel_ml_enabled:
            raise RuntimeError("Fine-tuned inference is disabled")
        if not settings.vulnintel_ml_base_model:
            raise RuntimeError("VULNINTEL_ML_BASE_MODEL is required")
        try:
            import torch
            from peft import PeftModel
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError(
                "ML inference dependencies are not installed. Install backend[ml]."
            ) from exc
        if torch.cuda.is_available():
            device_map = "auto"
            torch_dtype = "auto"
        else:
            device_map = None
            torch_dtype = torch.float32
        tokenizer = AutoTokenizer.from_pretrained(settings.vulnintel_ml_base_model)
        model = AutoModelForCausalLM.from_pretrained(
            settings.vulnintel_ml_base_model,
            device_map=device_map,
            torch_dtype=torch_dtype,
        )
        if settings.vulnintel_ml_adapter_path:
            model = PeftModel.from_pretrained(model, settings.vulnintel_ml_adapter_path)
            self._adapter_used = True
        if hasattr(model, "to") and not torch.cuda.is_available():
            model = model.to("cpu")
        self._model = model
        self._tokenizer = tokenizer

    def generate(self, request: InferenceRequest) -> InferenceResponse:
        if self._model is None:
            self.load()
        import torch

        inputs = self._tokenizer(request.prompt, return_tensors="pt")
        if torch.cuda.is_available():
            inputs = inputs.to(self._model.device)
        else:
            inputs = inputs.to("cpu")
        with torch.inference_mode():
            output = self._model.generate(
                **inputs,
                max_new_tokens=request.max_new_tokens,
                do_sample=False,
            )
        text = self._tokenizer.decode(
            output[0][inputs["input_ids"].shape[1] :],
            skip_special_tokens=True,
        )
        structured_json = None
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                structured_json = parsed
        except json.JSONDecodeError:
            pass
        return InferenceResponse(
            text=text,
            structured_json=structured_json,
            adapter_used=self._adapter_used,
        )


model_inference = OptionalModelInference()
