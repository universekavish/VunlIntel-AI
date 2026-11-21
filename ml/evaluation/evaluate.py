"""Evaluate base, prompt-engineered, and LoRA model variants."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", type=Path, required=True)
    parser.add_argument("--base-model", required=True)
    parser.add_argument("--lora-adapter", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mlflow-uri", default="http://localhost:5000")
    parser.add_argument("--experiment", default="vulnintel-model-comparison")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        import mlflow
        import torch
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as exc:
        raise RuntimeError(
            "Evaluation dependencies are not installed. Install backend[ml]."
        ) from exc

    if not torch.cuda.is_available() and not torch.backends.mps.is_available():
        raise RuntimeError(
            "Evaluation requires accelerator or CPU; use separate CPU-safe inference."
        )

    rows = [
        json.loads(line)
        for line in args.test.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    base = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        device_map="auto",
        torch_dtype="auto",
    )
    prompt_model = base
    lora_model = (
        PeftModel.from_pretrained(base, str(args.lora_adapter))
        if args.lora_adapter
        else None
    )

    def generate(model, prompt: str) -> str:
        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
        with torch.inference_mode():
            output = model.generate(**inputs, max_new_tokens=256, do_sample=False)
        return tokenizer.decode(
            output[0][inputs["input_ids"].shape[1] :], skip_special_tokens=True
        )

    mlflow.set_tracking_uri(args.mlflow_uri)
    mlflow.set_experiment(args.experiment)
    variants = {
        "base": base,
        "prompt_engineered": prompt_model,
        "lora": lora_model,
    }
    results = {}
    with mlflow.start_run(run_name="three-way-model-comparison") as run:
        for name, model in variants.items():
            if model is None:
                continue
            predictions: list[str] = []
            exact = 0
            valid_json = 0
            unsupported_claim_count = 0
            recommendation_valid_count = 0
            for row in rows:
                prompt = (
                    f"<task>{row['task']}</task>\n"
                    f"<evidence>{row['input']}</evidence>\n"
                    "<instruction>Use only evidence. Return structured JSON.</instruction>"
                    if name == "prompt_engineered"
                    else row["input"]
                )
                prediction = generate(model, prompt)
                predictions.append(prediction)
                expected = row["output"]
                expected_text = (
                    json.dumps(expected, sort_keys=True)
                    if isinstance(expected, dict)
                    else expected
                )
                if prediction.strip() == expected_text.strip():
                    exact += 1
                try:
                    parsed = json.loads(prediction)
                    valid_json += 1
                    unsupported = (
                        parsed.get("unsupported_claims", [])
                        if isinstance(parsed, dict)
                        else []
                    )
                    unsupported_claim_count += len(unsupported)
                    recommendations = (
                        parsed.get("recommendations", [])
                        if isinstance(parsed, dict)
                        else []
                    )
                    if isinstance(recommendations, list):
                        recommendation_valid_count += sum(
                            1
                            for recommendation in recommendations
                            if isinstance(recommendation, dict)
                            and recommendation.get("requires_human_approval") is True
                            and recommendation.get("patch_allowed") is False
                        )
                except json.JSONDecodeError:
                    pass
            metrics = {
                "exact_match": exact / len(rows) if rows else 0.0,
                "json_validity": valid_json / len(rows) if rows else 0.0,
                "unsupported_claim_count": float(unsupported_claim_count),
                "recommendation_validity": (
                    recommendation_valid_count / len(rows) if rows else 0.0
                ),
            }
            results[name] = {
                "metrics": metrics,
                "predictions": predictions,
            }
            mlflow.log_metrics(
                {f"{name}_{key}": value for key, value in metrics.items()}
            )
        mlflow.log_params(
            {
                "base_model": args.base_model,
                "lora_adapter": str(args.lora_adapter) if args.lora_adapter else None,
                "test_rows": len(rows),
            }
        )
        args.output.mkdir(parents=True, exist_ok=True)
        report = {
            "mlflow_run_id": run.info.run_id,
            "base_model": args.base_model,
            "lora_adapter": str(args.lora_adapter) if args.lora_adapter else None,
            "test_rows": len(rows),
            "results": results,
        }
        report_path = args.output / "comparison.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        mlflow.log_artifact(str(report_path), artifact_path="evaluation")
        print(
            json.dumps({"mlflow_run_id": run.info.run_id, "report": str(report_path)})
        )


if __name__ == "__main__":
    main()
