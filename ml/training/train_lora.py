"""LoRA/QLoRA training entry point for curated security datasets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", type=Path, required=True)
    parser.add_argument("--validation", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--experiment", default="vulnintel-finetuning")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--learning-rate", type=float, default=2e-4)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--gradient-accumulation", type=int, default=8)
    parser.add_argument("--lora-r", type=int, default=16)
    parser.add_argument("--lora-alpha", type=int, default=32)
    parser.add_argument("--lora-dropout", type=float, default=0.05)
    parser.add_argument("--qlora", action="store_true")
    parser.add_argument(
        "--mlflow-uri",
        default=os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5000"),
    )
    parser.add_argument("--register-model", default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        import mlflow
        import torch
        from datasets import load_dataset
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from trl import SFTConfig, SFTTrainer
    except ImportError as exc:
        raise RuntimeError(
            "Fine-tuning dependencies are not installed. Install backend[ml]."
        ) from exc

    if not torch.cuda.is_available() and not torch.backends.mps.is_available():
        raise RuntimeError(
            "LoRA/QLoRA training requires CUDA or Apple MPS; application execution is CPU-only."
        )

    train_file = str(args.train.resolve())
    validation_file = str(args.validation.resolve())
    dataset = load_dataset(
        "json",
        data_files={"train": train_file, "validation": validation_file},
    )

    quantization_config = None
    if args.qlora:
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
        )
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        quantization_config=quantization_config,
        device_map="auto",
        torch_dtype=torch.bfloat16,
    )
    if args.qlora:
        model = prepare_model_for_kbit_training(model)
    lora_config = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules="all-linear",
    )
    model = get_peft_model(model, lora_config)

    def formatting(row):
        output = row["output"]
        if isinstance(output, dict):
            output = json.dumps(output, sort_keys=True)
        return f"<instruction>\n{row['input']}\n</instruction>\n<response>\n{output}\n</response>"

    args.output.mkdir(parents=True, exist_ok=True)
    train_sha = hashlib.sha256(args.train.read_bytes()).hexdigest()
    validation_sha = hashlib.sha256(args.validation.read_bytes()).hexdigest()
    mlflow.set_tracking_uri(args.mlflow_uri)
    mlflow.set_experiment(args.experiment)
    with mlflow.start_run(run_name=f"lora-{Path(args.model).name}") as run:
        mlflow.log_params(
            {
                "base_model": args.model,
                "epochs": args.epochs,
                "learning_rate": args.learning_rate,
                "batch_size": args.batch_size,
                "gradient_accumulation": args.gradient_accumulation,
                "lora_r": args.lora_r,
                "lora_alpha": args.lora_alpha,
                "lora_dropout": args.lora_dropout,
                "qlora": args.qlora,
                "dataset_train_sha256": train_sha,
                "dataset_validation_sha256": validation_sha,
            }
        )
        mlflow.log_artifact(str(args.train), artifact_path="dataset")
        mlflow.log_artifact(str(args.validation), artifact_path="dataset")

        training_args = SFTConfig(
            output_dir=str(args.output),
            num_train_epochs=args.epochs,
            learning_rate=args.learning_rate,
            per_device_train_batch_size=args.batch_size,
            per_device_eval_batch_size=args.batch_size,
            gradient_accumulation_steps=args.gradient_accumulation,
            eval_strategy="epoch",
            save_strategy="epoch",
            report_to=[],
            logging_strategy="steps",
            logging_steps=10,
            remove_unused_columns=False,
        )
        trainer = SFTTrainer(
            model=model,
            args=training_args,
            train_dataset=dataset["train"],
            eval_dataset=dataset["validation"],
            processing_class=tokenizer,
            formatting_func=formatting,
        )
        result = trainer.train()
        metrics = trainer.evaluate()
        mlflow.log_metrics(
            {
                "training_loss": float(result.training_loss),
                **{
                    f"validation_{key}": float(value)
                    for key, value in metrics.items()
                    if isinstance(value, (int, float))
                },
            }
        )
        trainer.save_model(str(args.output))
        tokenizer.save_pretrained(str(args.output))
        mlflow.log_artifacts(str(args.output), artifact_path="model")
        if args.register_model:
            mlflow.register_model(
                model_uri=f"runs:/{run.info.run_id}/model",
                name=args.register_model,
            )
        mlflow.set_tag("run_id", run.info.run_id)
        mlflow.set_tag("model_version_status", "trained-not-registered")
        print(
            json.dumps({"mlflow_run_id": run.info.run_id, "output": str(args.output)})
        )


if __name__ == "__main__":
    main()
