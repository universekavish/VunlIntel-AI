"""Curate, validate, deduplicate, and split vulnerability examples."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Iterable
from pathlib import Path


def canonical_dedup_key(example: dict) -> str:
    """Return a stable family-aware key for exact and normalized duplicate removal."""
    output = json.dumps(example["output"], sort_keys=True, separators=(",", ":"))
    identity = str(example["identity"]).strip().casefold()
    task = str(example["task"]).strip().casefold()
    content = f"{task}|{identity}|{output}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def validate_example(example: dict) -> list[str]:
    errors: list[str] = []
    required = {
        "id",
        "task",
        "identity",
        "family",
        "input",
        "output",
        "source_citations",
        "license",
        "dedup_key",
    }
    missing = sorted(required - set(example))
    if missing:
        errors.append(f"missing fields: {', '.join(missing)}")
    if not isinstance(example.get("source_citations"), list):
        errors.append("source_citations must be a list")
    elif not example["source_citations"]:
        errors.append("source_citations must not be empty")
    if "dedup_key" not in example:
        return errors
    computed = canonical_dedup_key(example)
    if example["dedup_key"] != computed:
        errors.append("dedup_key does not match canonical content")
    return errors


def deduplicate(examples: Iterable[dict]) -> tuple[list[dict], int]:
    unique: dict[str, dict] = {}
    duplicates = 0
    for example in examples:
        dedup_key = canonical_dedup_key(example)
        if dedup_key in unique:
            duplicates += 1
            continue
        copied = dict(example)
        copied["dedup_key"] = dedup_key
        unique[dedup_key] = copied
    return list(unique.values()), duplicates


def cvv_family(identity: str) -> str:
    """Return a stable family key; CVE year is the first non-leaking family."""
    identity = identity.strip().upper()
    if identity.startswith("CVE-"):
        parts = identity.split("-")
        if len(parts) >= 3:
            return f"CVE-{parts[1]}"
    if identity.startswith("CWE-"):
        return "CWE-FAMILY"
    if identity:
        return identity.split("-", 1)[0].upper()
    return "UNIDENTIFIED"


def family_split(
    examples: Iterable[dict],
    *,
    seed: int = 42,
    train: float = 0.8,
    validation: float = 0.1,
    test: float = 0.1,
) -> dict[str, list[dict]]:
    """Split by CVE family/CWE-family so similar identities do not cross partitions."""
    if abs((train + validation + test) - 1.0) > 1e-9:
        raise ValueError("train, validation, and test proportions must sum to 1")
    groups: dict[str, list[dict]] = {}
    for example in examples:
        family = str(example.get("family") or cvv_family(str(example["identity"])))
        groups.setdefault(family, []).append(example)
    ordered = sorted(groups)
    import random

    rng = random.Random(seed)
    rng.shuffle(ordered)
    train_end = int(len(ordered) * train)
    validation_end = train_end + int(len(ordered) * validation)
    return {
        "train": [
            example for family in ordered[:train_end] for example in groups[family]
        ],
        "validation": [
            example
            for family in ordered[train_end:validation_end]
            for example in groups[family]
        ],
        "test": [
            example for family in ordered[validation_end:] for example in groups[family]
        ],
    }


def cli() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    examples = [
        json.loads(line)
        for line in args.input.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    for example in examples:
        example.setdefault("family", cvv_family(str(example["identity"])))
        errors = validate_example(example)
        if errors:
            raise ValueError(
                f"Invalid example {example.get('id')}: {'; '.join(errors)}"
            )
    examples, duplicate_count = deduplicate(examples)
    splits = family_split(examples, seed=args.seed)
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = {
        "seed": args.seed,
        "input_examples": len(examples) + duplicate_count,
        "unique_examples": len(examples),
        "duplicates_removed": duplicate_count,
        "family_partition": "CVE year / CWE family / identifier prefix",
        "splits": {name: {"count": len(rows)} for name, rows in splits.items()},
    }
    (args.output / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    for name, rows in splits.items():
        with (args.output / f"{name}.jsonl").open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")


if __name__ == "__main__":
    cli()
