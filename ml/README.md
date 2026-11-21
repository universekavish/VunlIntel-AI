# Machine learning workspace

Optional, isolated fine-tuning workspace for vulnerability/CWE classification, security information extraction, and structured report generation.

Nothing here is loaded by normal API startup. The application dependencies do not require PyTorch or Transformers; install `backend[ml]` only for training or enabled model inference.

## Dataset pipeline

Input JSONL examples must contain `id`, `task`, `identity`, `family`, `input`, `output`, `source_citations`, `license`, and `dedup_key`. Curate and split records by family:

```sh
python ml/datasets/curate.py raw.jsonl ml/datasets/prepared --seed 42
```

The pipeline removes exact normalized duplicates and partitions by CVE year, CWE family, or identifier prefix. It reports counts and duplicate removal in `manifest.json`. No live intelligence is invented.

## LoRA / QLoRA training

```sh
python ml/training/train_lora.py \
  --train ml/datasets/prepared/train.jsonl \
  --validation ml/datasets/prepared/validation.jsonl \
  --model <base-model-id-or-local-path> \
  --output ml/artifacts/lora \
  --qlora
```

Training requires CUDA or Apple MPS and logs hyperparameters, dataset SHA-256 versions, training/validation metrics, and artifacts to MLflow. Use `--register-model <name>` to create an MLflow model version from the logged run artifacts.

## Evaluation

Compare base, prompt-engineered-base, and LoRA variants:

```sh
python ml/evaluation/evaluate.py \
  --test ml/datasets/prepared/test.jsonl \
  --base-model <base-model-id-or-local-path> \
  --lora-adapter ml/artifacts/lora \
  --output ml/evaluation/results
```

The result report includes exact match, JSON validity, unsupported-claim count, and recommendation validity. The script records real run metrics only and does not generate example performance numbers.

`ml/evaluation/benchmark.json` contains explicitly labeled synthetic boundary fixtures for pipeline validation. It is not evidence of live model quality or a claim about real-world performance.

## CPU application mode

Set `VULNINTEL_ML_ENABLED=false` to use the application without loading PyTorch or Transformers. When enabled, set `VULNINTEL_ML_BASE_MODEL`; `VULNINTEL_ML_ADAPTER_PATH` is optional.
