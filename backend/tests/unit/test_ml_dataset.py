"""Tests for curated dataset deduplication and family-safe splitting."""

import importlib.util
import json
import sys
from pathlib import Path


def load_curation_module():
    module_path = Path(__file__).resolve().parents[3] / "ml" / "datasets" / "curate.py"
    spec = importlib.util.spec_from_file_location("vulnintel_curate", module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def example(identity: str, family: str, output: str) -> dict:
    module = load_curation_module()
    row = {
        "id": f"{identity}-example",
        "task": "vulnerability_classification",
        "identity": identity,
        "family": family,
        "input": "Evidence text",
        "output": output,
        "source_citations": [f"nvd:{identity}"],
        "license": "test-fixture",
    }
    row["dedup_key"] = module.canonical_dedup_key(row)
    return row


def test_family_split_never_places_same_family_across_partitions() -> None:
    module = load_curation_module()
    rows = [
        example("CVE-2024-0001", "CVE-2024", "confirmed"),
        example("CVE-2024-0002", "CVE-2024", "confirmed"),
        example("CVE-2025-0001", "CVE-2025", "potential"),
        example("CVE-2025-0002", "CVE-2025", "needs_review"),
        example("CVE-2026-0001", "CVE-2026", "not_affected"),
    ]

    splits = module.family_split(rows, seed=11)
    partitions = {
        family
        for name in ("train", "validation", "test")
        for row in splits[name]
        for family in [row["family"]]
    }
    assert partitions <= {"CVE-2024", "CVE-2025", "CVE-2026"}
    all_families = [row["family"] for name in splits for row in splits[name]]
    assert len(all_families) == len(rows)
    for name, rows_in_split in splits.items():
        for other_name, other_rows in splits.items():
            if name == other_name:
                continue
            assert not (
                {row["family"] for row in rows_in_split} & {row["family"] for row in other_rows}
            )


def test_deduplication_removes_exact_content_only() -> None:
    module = load_curation_module()
    first = example("CVE-2024-1000", "CVE-2024", "confirmed")
    duplicate = dict(first)
    changed = example("CVE-2024-1000", "CVE-2024", "potential")

    unique, duplicate_count = module.deduplicate([first, duplicate, changed])

    assert len(unique) == 2
    assert duplicate_count == 1


def test_invalid_dedup_key_is_rejected() -> None:
    module = load_curation_module()
    row = example("CVE-2024-1001", "CVE-2024", "confirmed")
    row["dedup_key"] = "wrong"

    errors = module.validate_example(row)

    assert any("dedup_key" in error for error in errors)


def test_schema_evaluation_dataset_is_valid_json() -> None:
    benchmark = Path(__file__).resolve().parents[3] / "ml" / "evaluation" / "benchmark.json"
    rows = json.loads(benchmark.read_text(encoding="utf-8"))
    assert len(rows) == 3
    assert all(row["benchmark"] == "synthetic-boundary-fixture" for row in rows)
