"""Strict research dataset protocol, structural, and semantic validator (QRS-Bench-Ind)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import cv2
import numpy as np
from PIL import Image, UnidentifiedImageError

from qrshield_core.decoder.qr import detect_and_decode

from .dataset_loader import BENCHMARK_CATEGORIES, PAYLOAD_TYPES, ResearchDataset, discover_dataset_root, load_research_dataset

EXPECTED_BASE = 640
EXPECTED_CF_DIRECTIONAL_PAIRS = 160
EXPECTED_CF_NEGATIVE_CONTROLS = 40
EXPECTED_CF_PAIRS_TOTAL = 200
EXPECTED_CF_IMAGES = 400
EXPECTED_ROB = 240
EXPECTED_TOTAL = 1280
EXPECTED_PER_TYPE = 80
SUPPORTED_IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".bmp", ".webp"}
MAX_IMAGE_FILE_BYTES = 20 * 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000
MAX_IMAGE_SIDE = 8_000


@dataclass
class ValidationResult:
    ok: bool
    structural_valid: bool = False
    semantic_valid: bool = False
    errors: list[str] = field(default_factory=list)
    structural_errors: list[str] = field(default_factory=list)
    semantic_errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    per_payload: dict[str, int] = field(default_factory=dict)
    missing_images: list[str] = field(default_factory=list)
    invalid_images: list[str] = field(default_factory=list)
    missing_base_links: list[str] = field(default_factory=list)
    hash_mismatches: list[str] = field(default_factory=list)
    payload_mismatches: list[str] = field(default_factory=list)
    image_inventory_hash: str = ""
    dataset_root: str = ""

    @property
    def suite_valid(self) -> dict[str, bool]:
        base_ok = not any("base" in e.lower() or "image" in e.lower() or "payload" in e.lower() for e in self.errors)
        cf_ok = not any("counterfactual" in e.lower() for e in self.errors)
        rob_ok = not any("robustness" in e.lower() for e in self.errors)
        return {"base": base_ok, "counterfactual": cf_ok, "robustness": rob_ok, "all": base_ok and cf_ok and rob_ok}


def validate_dataset_root(root: Path | None = None, *, verify_payloads: bool = False) -> ValidationResult:
    if root is None:
        root = discover_dataset_root()
    result = ValidationResult(ok=False, dataset_root=str(root))
    if not root.exists():
        msg = f"Research dataset not found at '{root}'. Place the 'qrs_bench_ind' folder beside the project root."
        result.errors.append(msg)
        result.structural_errors.append(msg)
        return result
    if not root.is_dir():
        msg = f"'{root}' exists but is not a directory."
        result.errors.append(msg)
        result.structural_errors.append(msg)
        return result
    try:
        ds = load_research_dataset(root)
    except Exception as exc:
        msg = f"Dataset could not be loaded safely: {type(exc).__name__}: {exc}"
        result.errors.append(msg)
        result.structural_errors.append(msg)
        return result
    return validate_dataset(ds, verify_payloads=verify_payloads)


def _decode_payload_fast(image_path: Path, qr_bbox: list[int] | None = None) -> str | None:
    """Decode QR payload from image (using QR bbox crop first for speed when available)."""
    raw_bytes = image_path.read_bytes()
    arr = np.frombuffer(raw_bytes, dtype=np.uint8)
    bgr = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if bgr is None:
        return None
    if qr_bbox and len(qr_bbox) == 4:
        x0, y0, x1, y1 = [int(v) for v in qr_bbox]
        pad = 24
        h, w = bgr.shape[:2]
        crop = bgr[max(0, y0 - pad):min(h, y1 + pad), max(0, x0 - pad):min(w, x1 + pad)]
        if crop.size > 0:
            dec = detect_and_decode(crop)
            decoded = [c.payload for c in dec.codes if c.decoded and c.payload is not None]
            if decoded:
                return decoded[0]
    dec = detect_and_decode(bgr)
    decoded = [c.payload for c in dec.codes if c.decoded and c.payload is not None]
    return decoded[0] if decoded else None


def validate_dataset(ds: ResearchDataset, *, verify_payloads: bool = False) -> ValidationResult:
    """Validate structural and semantic integrity of the research dataset."""
    result = ValidationResult(ok=False, dataset_root=str(ds.root))
    structural_errors = result.structural_errors
    semantic_errors = result.semantic_errors
    root = Path(ds.root).resolve(strict=True)
    is_qrs_bench = (root / "annotations" / "consensus_ground_truth.jsonl").is_file()

    n_base = len(ds.base_items)
    n_cf = len(ds.counterfactual_items)
    n_cf_pairs = len(ds.counterfactual_pairs)
    n_cf_neg = len(ds.counterfactual_negative_controls)
    n_cf_total_pairs = n_cf_pairs + n_cf_neg
    n_rob = len(ds.robustness_items)
    n_total = n_base + n_cf + n_rob
    result.counts = {
        "base": n_base,
        "counterfactual_images": n_cf,
        "counterfactual_pairs": n_cf_pairs,
        "counterfactual_negative_control_pairs": n_cf_neg,
        "counterfactual_total_pairs": n_cf_total_pairs,
        "robustness": n_rob,
        "total": n_total,
    }

    expected_counts = (
        ("Base suite", n_base, EXPECTED_BASE),
        ("Counterfactual image suite", n_cf, EXPECTED_CF_IMAGES),
        ("Directional counterfactual pairs", n_cf_pairs, EXPECTED_CF_DIRECTIONAL_PAIRS),
        ("Negative-control pairs", n_cf_neg, EXPECTED_CF_NEGATIVE_CONTROLS),
        ("Total counterfactual pairs", n_cf_total_pairs, EXPECTED_CF_PAIRS_TOTAL),
        ("Robustness suite", n_rob, EXPECTED_ROB),
        ("Total benchmark", n_total, EXPECTED_TOTAL),
    )
    for label, actual, expected in expected_counts:
        if actual != expected:
            structural_errors.append(f"{label}: expected exactly {expected}, found {actual}.")

    expected_cats = BENCHMARK_CATEGORIES if is_qrs_bench else PAYLOAD_TYPES
    pt_counts = {pt: 0 for pt in expected_cats}
    for item in ds.base_items:
        if item.payload_type in pt_counts:
            pt_counts[item.payload_type] += 1
        elif item.payload_type != "unknown":
            pt_counts[item.payload_type] = pt_counts.get(item.payload_type, 0) + 1
    result.per_payload = pt_counts
    for pt in expected_cats:
        if pt_counts.get(pt, 0) != EXPECTED_PER_TYPE:
            structural_errors.append(f"Base payload type '{pt}': expected exactly {EXPECTED_PER_TYPE} images, found {pt_counts.get(pt, 0)}.")
    unknown_count = sum(1 for i in ds.base_items if i.payload_type == "unknown")
    if unknown_count:
        structural_errors.append(f"Base suite contains {unknown_count} image(s) with unknown payload type.")

    # Stable item IDs across suites.
    ids_by_suite = {
        "base": [i.item_id for i in ds.base_items],
        "counterfactual": [i.item_id for i in ds.counterfactual_items],
        "robustness": [i.item_id for i in ds.robustness_items],
    }
    for suite, ids in ids_by_suite.items():
        if any(not value for value in ids):
            structural_errors.append(f"{suite.capitalize()} suite contains an empty item ID.")
        if len(set(ids)) != len(ids):
            structural_errors.append(f"{suite.capitalize()} suite: duplicate item IDs detected.")

    directional_ids = [str(p.get("pair_id") or p.get("id") or "") for p in ds.counterfactual_pairs]
    negative_ids = [str(p.get("pair_id") or p.get("id") or "") for p in ds.counterfactual_negative_controls]
    if any(not p for p in directional_ids):
        structural_errors.append("Directional counterfactual manifest contains a pair without a pair_id.")
    if any(not p for p in negative_ids):
        structural_errors.append("Negative-control manifest contains a pair without a pair_id.")
    if len(set(directional_ids)) != len(directional_ids):
        structural_errors.append("Directional counterfactual manifest contains duplicate pair IDs.")
    if len(set(negative_ids)) != len(negative_ids):
        structural_errors.append("Negative-control manifest contains duplicate pair IDs.")
    if set(directional_ids) & set(negative_ids):
        structural_errors.append("Directional and negative-control manifests share pair IDs.")
    if any(p.get("expected_direction") not in {"b_more_concerning", "b_less_concerning"} for p in ds.counterfactual_pairs):
        semantic_errors.append("Directional counterfactual contains an invalid expected_direction.")
    if any(p.get("expected_direction") != "no_change" for p in ds.counterfactual_negative_controls):
        semantic_errors.append("Negative-control manifest must use expected_direction=no_change.")

    # Image inventory and integrity.
    missing: list[str] = []
    invalid: list[str] = []
    inventory = hashlib.sha256()
    hashes_by_item: dict[tuple[str, str], str] = {}
    hashes_by_relpath: dict[str, str] = {}
    for item in ds.all_items():
        path = Path(item.image_path)
        try:
            resolved = path.resolve(strict=False)
            rel_to_root = resolved.relative_to(root).as_posix()
        except (OSError, ValueError):
            structural_errors.append(f"{item.suite.capitalize()} item '{item.item_id}' has an image path outside the dataset root.")
            continue
        if not resolved.exists() or not resolved.is_file():
            missing.append(str(resolved))
            continue
        if resolved.suffix.lower() not in SUPPORTED_IMAGE_SUFFIXES:
            invalid.append(f"{resolved} (unsupported image extension)")
            continue
        try:
            if resolved.stat().st_size > MAX_IMAGE_FILE_BYTES:
                invalid.append(f"{resolved} (image exceeds {MAX_IMAGE_FILE_BYTES} byte limit)")
                continue
            with Image.open(resolved) as image:
                width, height = image.size
                if width <= 0 or height <= 0 or width * height > MAX_IMAGE_PIXELS or max(width, height) > MAX_IMAGE_SIDE:
                    invalid.append(f"{resolved} (image dimensions exceed validation limits)")
                    continue
                image.verify()
            digest = hashlib.sha256()
            with resolved.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
            image_hash = digest.hexdigest()
            inventory.update(item.suite.encode("utf-8"))
            inventory.update(b"\0")
            inventory.update(item.item_id.encode("utf-8"))
            inventory.update(b"\0")
            inventory.update(image_hash.encode("ascii"))
            inventory.update(b"\n")
            hashes_by_item[(item.suite, item.item_id)] = image_hash
            hashes_by_relpath[rel_to_root] = image_hash
        except (OSError, ValueError, UnidentifiedImageError) as exc:
            invalid.append(f"{resolved} ({type(exc).__name__})")

    result.missing_images = missing[:50]
    result.invalid_images = invalid[:50]
    if missing:
        structural_errors.append(f"{len(missing)} image file(s) are missing or unreadable. First {min(len(missing), 5)}: {missing[:5]}")
    if invalid:
        structural_errors.append(f"{len(invalid)} image file(s) are invalid or unreadable. First {min(len(invalid), 5)}: {invalid[:5]}")
    result.image_inventory_hash = inventory.hexdigest() if not missing and not invalid else ""

    # Pair completeness and A/B distinctness for both directional and control pairs.
    manifest_sets = [("directional", set(directional_ids)), ("negative_control", set(negative_ids))]
    item_groups: dict[str, list[Any]] = {}
    for item in ds.counterfactual_items:
        if not item.pair_id:
            structural_errors.append(f"Counterfactual item '{item.item_id}' has no pair ID.")
            continue
        item_groups.setdefault(str(item.pair_id), []).append(item)
    all_manifest_ids = set().union(*(s for _, s in manifest_sets)) if manifest_sets else set()
    for pid in sorted(all_manifest_ids):
        items = item_groups.get(pid, [])
        roles = sorted(getattr(i, "pair_role", None) for i in items)
        if len(items) != 2 or roles != ["a", "b"]:
            structural_errors.append(f"Counterfactual pair '{pid}' must have exactly one A image and one B image; found roles {roles}.")
            continue
        a = next(i for i in items if i.pair_role == "a")
        b = next(i for i in items if i.pair_role == "b")
        ha = hashes_by_item.get(("counterfactual", a.item_id))
        hb = hashes_by_item.get(("counterfactual", b.item_id))
        if ha and hb and ha == hb:
            semantic_errors.append(f"Counterfactual pair '{pid}' contains byte-identical A and B images.")
    if set(item_groups) != all_manifest_ids:
        structural_errors.append("Counterfactual manifest pair IDs do not match the pair IDs represented by images.")

    # Semantic check 1: Robustness lineage MUST resolve to an existing base scenario.
    base_ids = {i.item_id for i in ds.base_items}
    missing_links: list[str] = []
    for item in ds.robustness_items:
        bid = item.base_id or item.ground_truth.get("base_id") or item.ground_truth.get("original_scenario_id")
        if not bid:
            missing_links.append(item.item_id)
            semantic_errors.append(f"Robustness item '{item.item_id}' is missing base_id / original_scenario_id linkage.")
        elif str(bid) not in base_ids:
            missing_links.append(item.item_id)
            semantic_errors.append(f"Robustness item '{item.item_id}' references unknown base scenario '{bid}'.")
    result.missing_base_links = missing_links

    # Semantic check 2: Verify artifact_hashes.jsonl if present in dataset metadata.
    artifact_hashes_path = root / "metadata" / "artifact_hashes.jsonl"
    hash_mismatches: list[str] = []
    if artifact_hashes_path.is_file():
        for line in artifact_hashes_path.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                semantic_errors.append("Invalid JSON line in metadata/artifact_hashes.jsonl.")
                break
            rel_p = str(rec.get("path") or "").replace("\\", "/")
            expected_sha = str(rec.get("sha256") or "").lower()
            if not rel_p or not expected_sha:
                continue
            actual_sha = hashes_by_relpath.get(rel_p)
            if actual_sha is None:
                target_file = root / rel_p
                if target_file.is_file():
                    actual_sha = hashlib.sha256(target_file.read_bytes()).hexdigest()
            if actual_sha is None or actual_sha.lower() != expected_sha:
                hash_mismatches.append(rel_p)
    result.hash_mismatches = hash_mismatches[:50]
    if hash_mismatches:
        semantic_errors.append(
            f"{len(hash_mismatches)} artifact(s) failed SHA-256 verification against metadata/artifact_hashes.jsonl. "
            f"First {min(len(hash_mismatches), 5)}: {hash_mismatches[:5]}"
        )

    # Semantic check 3: Verify base ground-truth payload consistency and optional QR decode check.
    payload_mismatches: list[str] = []
    for item in ds.base_items:
        gt = item.ground_truth or {}
        if "qr_payload" in gt and not str(gt.get("qr_payload") or "").strip():
            payload_mismatches.append(f"{item.item_id}: empty qr_payload in manifest")
        if verify_payloads and "qr_payload" in gt and (("base", item.item_id) in hashes_by_item):
            expected_qr = str(gt.get("qr_payload") or "")
            decoded_qr = _decode_payload_fast(Path(item.image_path), gt.get("qr_bbox"))
            if decoded_qr is None:
                payload_mismatches.append(f"{item.item_id}: QR code could not be decoded during semantic verification")
            elif decoded_qr != expected_qr:
                payload_mismatches.append(f"{item.item_id}: decoded QR payload does not match manifest qr_payload")
    result.payload_mismatches = payload_mismatches[:50]
    if payload_mismatches:
        semantic_errors.append(
            f"{len(payload_mismatches)} base item(s) failed semantic payload verification. "
            f"First {min(len(payload_mismatches), 5)}: {payload_mismatches[:5]}"
        )

    result.structural_valid = len(structural_errors) == 0
    result.semantic_valid = len(semantic_errors) == 0
    result.errors = structural_errors + semantic_errors
    result.ok = result.structural_valid and result.semantic_valid
    return result
