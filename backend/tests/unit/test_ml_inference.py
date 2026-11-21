"""Tests for optional CPU-safe inference behavior."""

from app.ml.inference import OptionalModelInference


def test_disabled_inference_never_loads_or_fabricates_model_output() -> None:
    inference = OptionalModelInference()
    status = inference.status()

    assert status.enabled is False
    assert status.model_loaded is False
    assert status.cpu_safe is True
