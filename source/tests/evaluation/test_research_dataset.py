"""Unit tests for dataset loading, schema adaptation, and validation."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from evaluation.dataset_loader import (
    PAYLOAD_TYPES,
    ResearchDataset,
    ResearchItem,
    discover_dataset_root,
    load_research_dataset,
)
from evaluation.validator import (
    EXPECTED_BASE,
    EXPECTED_CF_DIRECTIONAL_PAIRS,
    EXPECTED_CF_NEGATIVE_CONTROLS,
    EXPECTED_CF_PAIRS_TOTAL,
    EXPECTED_ROB,
    ValidationResult,
    validate_dataset,
    validate_dataset_root,
)


def test_discover_dataset_root():
    root = discover_dataset_root()
    assert root.name == "qrs_bench_ind"


def test_validate_missing_dataset_root(tmp_path):
    missing = tmp_path / "qrs_bench_ind"
    res = validate_dataset_root(missing)
    assert not res.ok
    assert any("not found" in e.lower() for e in res.errors)


def test_validate_file_instead_of_dir(tmp_path):
    fake_file = tmp_path / "not_a_dir"
    fake_file.write_text("hello", encoding="utf-8")
    res = validate_dataset_root(fake_file)
    assert not res.ok
    assert any("not a directory" in e.lower() for e in res.errors)


def _create_mock_dataset(root: Path, create_images: bool = True) -> Path:
    """Helper to build a small valid-structure mock dataset for testing."""
    base_dir = root / "base"
    base_dir.mkdir(parents=True, exist_ok=True)
    cf_dir = root / "counterfactual"
    cf_dir.mkdir(parents=True, exist_ok=True)
    rob_dir = root / "robustness"
    rob_dir.mkdir(parents=True, exist_ok=True)

    base_records = []
    for i, pt in enumerate(PAYLOAD_TYPES):
        img_name = f"base_{pt}_{i}.png"
        img_path = base_dir / img_name
        if create_images:
            img_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"fake_png_data")
        base_records.append({
            "id": f"BASE_{i:03d}",
            "image": img_name,
            "payload_type": pt,
            "family": f"family_{pt}",
            "expected_assessment": "needs_verification",
        })
    (base_dir / "dataset_manifest.json").write_text(json.dumps(base_records), encoding="utf-8")

    cf_records = []
    for i in range(5):
        img_a = f"cf_{i}_a.png"
        img_b = f"cf_{i}_b.png"
        if create_images:
            (cf_dir / img_a).write_bytes(b"\x89PNG\r\n\x1a\n")
            (cf_dir / img_b).write_bytes(b"\x89PNG\r\n\x1a\n")
        cf_records.append({
            "pair_id": f"CF_{i:03d}",
            "image_a": img_a,
            "image_b": img_b,
            "type": "url",
            "expected_direction": "b_more_concerning",
        })
    (cf_dir / "counterfactual_manifest.json").write_text(json.dumps(cf_records), encoding="utf-8")

    rob_records = []
    for i in range(5):
        img_rob = f"rob_{i}.png"
        if create_images:
            (rob_dir / img_rob).write_bytes(b"\x89PNG\r\n\x1a\n")
        rob_records.append({
            "variant_id": f"ROB_{i:03d}",
            "image": img_rob,
            "base_id": "BASE_000",
            "transform": "blur",
            "type": "url",
        })
    (rob_dir / "robustness_manifest.json").write_text(json.dumps(rob_records), encoding="utf-8")

    return root


def test_load_and_validate_mock_dataset(tmp_path):
    ds_root = _create_mock_dataset(tmp_path / "mock_ds", create_images=True)
    ds = load_research_dataset(ds_root)

    assert len(ds.base_items) == len(PAYLOAD_TYPES)
    assert len(ds.counterfactual_items) == 10  # 5 pairs * 2
    assert len(ds.counterfactual_pairs) == 5
    assert len(ds.counterfactual_negative_controls) == 0
    assert len(ds.robustness_items) == 5
    assert ds.total_images == len(PAYLOAD_TYPES) + 10 + 5

    res = validate_dataset(ds)
    assert len(res.missing_images) == 0
    assert res.counts["base"] == len(PAYLOAD_TYPES)
    assert res.counts["counterfactual_images"] == 10
    assert res.counts["robustness"] == 5


def test_validate_missing_images(tmp_path):
    ds_root = _create_mock_dataset(tmp_path / "missing_img_ds", create_images=False)
    ds = load_research_dataset(ds_root)
    res = validate_dataset(ds)
    assert not res.ok
    assert len(res.missing_images) > 0
    assert any("missing or unreadable" in e for e in res.errors)


def test_incomplete_counterfactual_pair_is_rejected(tmp_path):
    ds_root = _create_mock_dataset(tmp_path / "incomplete_pair_ds", create_images=True)
    ds = load_research_dataset(ds_root)
    ds.counterfactual_items = ds.counterfactual_items[:-1]
    res = validate_dataset(ds)
    assert not res.ok
    assert any("must have exactly one A image and one B image" in error for error in res.errors)
    assert any("Counterfactual image suite: expected exactly 400" in error for error in res.errors)


def test_v3_negative_controls_are_loaded_separately(tmp_path):
    root = _create_mock_dataset(tmp_path / "v3_ds", create_images=True)
    cf_dir = root / "counterfactual"
    neg = [{
        "pair_id": "NC_001",
        "payload_type": "url",
        "image_a": "cf_0_a.png",
        "image_b": "cf_0_b.png",
        "expected_direction": "no_change",
    }]
    metadata = cf_dir / "metadata"
    metadata.mkdir(parents=True)
    (metadata / "negative_controls.json").write_text(json.dumps(neg), encoding="utf-8")
    ds = load_research_dataset(root)
    assert len(ds.counterfactual_negative_controls) == 1
    assert len(ds.counterfactual_items) == 12
    assert {i.pair_id for i in ds.counterfactual_items if i.ground_truth.get("pair_class") == "negative_control"} == {"NC_001"}


def test_duplicate_ids_detected(tmp_path):
    base_dir = tmp_path / "dup_ds" / "base"
    base_dir.mkdir(parents=True, exist_ok=True)
    records = [
        {"id": "DUP_01", "image": "img1.png", "type": "url"},
        {"id": "DUP_01", "image": "img2.png", "type": "url"},
    ]
    (base_dir / "img1.png").write_bytes(b"data")
    (base_dir / "img2.png").write_bytes(b"data")
    (base_dir / "manifest.json").write_text(json.dumps(records), encoding="utf-8")

    ds = load_research_dataset(tmp_path / "dup_ds")
    res = validate_dataset(ds)
    assert not res.ok
    assert any("duplicate item IDs" in e for e in res.errors)
