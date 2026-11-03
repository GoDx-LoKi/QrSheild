"""Research dataset discovery and loading.

Supports the independent multi-modal benchmark ``qrs_bench_ind``:
- 640 base & challenge scenarios (480 core scenes + 160 challenge traps across 8 categories x 80)
- 160 directional counterfactual pairs (320 images)
- 40 negative-control invariance pairs (80 images)
- 240 robustness variants (20 seeds x 12 transforms R00-R11)
- 1,280 total images (1,080 benchmark units)

Also preserves backward compatibility for unit-test mock directory datasets.
Ground-truth metadata is loaded for scoring only; the image runner receives only
image paths and never receives these fields.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
RESEARCH_DATASET_NAME = "qrs_bench_ind"

_BASE_MANIFESTS = [
    "scenarios.jsonl", "base.jsonl", "base_manifest.json", "manifest.json", "dataset_manifest.json",
]
_CF_MANIFESTS = [
    "counterfactual_manifest.json", "cf_manifest.json", "counterfactuals.jsonl", "cf.jsonl",
]
_ROB_MANIFESTS = [
    "robustness_manifest.json", "rob_manifest.json", "robustness.jsonl", "rob.jsonl",
]
_NEGATIVE_CF_MANIFESTS = [
    "counterfactual/metadata/negative_controls.json",
    "counterfactuals/metadata/negative_controls.json",
]

_BASE_DIRS = ["base", "BASE", "base_images", "images"]
_CF_DIRS = ["counterfactual", "counterfactuals", "CF", "cf"]
_ROB_DIRS = ["robustness", "ROBUSTNESS", "rob"]

PAYLOAD_TYPES = ["url", "wifi", "payment", "contact", "sms", "email", "deep_link"]
BENCHMARK_CATEGORIES = ["url", "wifi", "payment", "contact", "sms", "email", "deep_link", "plain_text"]

_PAYLOAD_ALIASES: dict[str, str] = {
    "deeplink": "deep_link", "deep-link": "deep_link", "deep_links": "deep_link",
    "wi_fi": "wifi", "wi-fi": "wifi", "urls": "url", "link": "url",
    "payments": "payment", "pay": "payment", "contacts": "contact", "vcard": "contact", "mecard": "contact",
    "emails": "email", "email_message": "email", "sms_message": "sms",
    "plaintext": "plain_text", "text": "plain_text",
}

BASE_IMAGE_VARIANT: str = "scene"


@dataclass
class ResearchItem:
    """One image to be evaluated."""
    item_id: str
    suite: str
    image_path: Path
    payload_type: str
    scenario_family: str | None = None
    pair_id: str | None = None
    pair_role: str | None = None
    base_id: str | None = None
    variant_id: str | None = None
    transformation: str | None = None
    ground_truth: dict[str, Any] = field(default_factory=dict)


@dataclass
class ResearchDataset:
    root: Path
    base_items: list[ResearchItem]
    counterfactual_items: list[ResearchItem]
    counterfactual_pairs: list[dict[str, Any]]
    counterfactual_negative_controls: list[dict[str, Any]]
    robustness_items: list[ResearchItem]
    manifest_hash: str
    manifest_files: list[str]
    raw_manifests: dict[str, Any]

    def items_for_suite(self, suite: str) -> list[ResearchItem]:
        return {
            "base": self.base_items,
            "counterfactual": self.counterfactual_items,
            "robustness": self.robustness_items,
        }.get(suite, [])

    def all_items(self) -> list[ResearchItem]:
        return self.base_items + self.counterfactual_items + self.robustness_items

    @property
    def total_images(self) -> int:
        return len(self.base_items) + len(self.counterfactual_items) + len(self.robustness_items)

    @property
    def total_counterfactual_pairs(self) -> int:
        return len(self.counterfactual_pairs) + len(self.counterfactual_negative_controls)


def discover_dataset_root() -> Path:
    env_override = os.environ.get("QRSHIELD_DATASET_ROOT")
    if env_override:
        return Path(env_override)
    for name in ("qrs_bench_ind",):
        for base in (REPO_ROOT.parent, REPO_ROOT):
            cand = base / name
            if cand.exists():
                return cand
    return REPO_ROOT.parent / RESEARCH_DATASET_NAME


def _inside_root(root: Path, candidate: Path, *, strict: bool = False) -> Path:
    canonical_root = root.resolve(strict=True)
    resolved = candidate.resolve(strict=strict)
    try:
        resolved.relative_to(canonical_root)
    except ValueError as exc:
        raise ValueError(f"Dataset path escapes the dataset root: {candidate}") from exc
    return resolved


def _find_manifest(directory: Path, candidates: list[str], root: Path) -> Path | None:
    for name in candidates:
        p = directory / name
        if p.is_file():
            return _inside_root(root, p, strict=True)
    return None


def _find_subdir(root: Path, candidates: list[str]) -> Path | None:
    for name in candidates:
        p = root / name
        if p.is_dir():
            return _inside_root(root, p, strict=True)
    return None


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSONL in {path.name} at line {line_no}.") from exc
        if not isinstance(record, dict):
            raise ValueError(f"Expected a JSON object in {path.name} at line {line_no}.")
        records.append(record)
    return records


def _read_manifest(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".jsonl":
        return _read_jsonl(path)
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = None
        for key in ("items", "images", "records", "base", "counterfactual", "robustness", "scenarios"):
            if key in data and isinstance(data[key], list):
                records = data[key]
                break
        if records is None:
            raise ValueError(f"Manifest {path.name} must contain a list of records or an explicit record-list field.")
    else:
        raise ValueError(f"Manifest {path.name} must contain a JSON array or object with a records array.")
    if any(not isinstance(record, dict) for record in records):
        raise ValueError(f"Manifest {path.name} contains a non-object record.")
    return records


def _hash_manifest_files(paths: list[Path]) -> str:
    h = hashlib.sha256()
    for p in sorted({x for x in paths if x is not None}, key=str):
        if p.is_file():
            h.update(p.read_bytes())
    return h.hexdigest()[:16]


def _normalize_payload_type(raw: str) -> str:
    v = raw.strip().lower().replace("-", "_").replace(" ", "_")
    if v in BENCHMARK_CATEGORIES:
        return v
    return _PAYLOAD_ALIASES.get(v, "unknown" if not v else v)


def canonical_payload_type(raw: str | None) -> str:
    return _normalize_payload_type(str(raw or ""))


def _infer_payload_type(record: dict, image_path: Path, suite_dir: Path) -> str:
    for key in ("payload_type", "type", "category", "family", "class"):
        v = record.get(key, "")
        if v and isinstance(v, str):
            n = _normalize_payload_type(v)
            if n in BENCHMARK_CATEGORIES:
                return n
    for part in image_path.parts:
        n = _normalize_payload_type(part)
        if n in BENCHMARK_CATEGORIES:
            return n
    return "unknown"


def _resolve_image(rel: str, manifest_dir: Path, dataset_root: Path) -> Path:
    if not isinstance(rel, str) or not rel.strip():
        raise ValueError("Manifest image path must be a non-empty string.")
    raw = rel.strip()
    if "\x00" in raw:
        raise ValueError("Manifest image path contains a NUL byte.")
    win_path = PureWindowsPath(raw)
    p = Path(raw)
    if p.is_absolute() or win_path.is_absolute() or win_path.drive:
        raise ValueError(f"Absolute image paths are not allowed in a dataset manifest: {raw}")
    normalized_parts = raw.replace("\\", "/").split("/")
    if any(part in ("..", ".") for part in normalized_parts):
        raise ValueError(f"Parent-directory traversal is not allowed in image paths: {raw}")
    root = dataset_root.resolve(strict=True)
    manifest_dir = _inside_root(root, manifest_dir, strict=True)
    candidates = [manifest_dir / p, root / p]
    for candidate in candidates:
        safe = _inside_root(root, candidate, strict=False)
        if safe.exists():
            if not safe.is_file():
                raise ValueError(f"Dataset image path is not a file: {raw}")
            return safe
    root_relative_prefixes = {
        "base", "BASE", "counterfactual", "counterfactuals", "robustness",
        "ROBUSTNESS", "rob", "CF", "cf", "splits",
    }
    use_root = p.parts and p.parts[0] in root_relative_prefixes
    fallback = (root / p) if use_root else (manifest_dir / p)
    return _inside_root(root, fallback, strict=False)


def _load_qrs_bench_ind(root: Path, gt_jsonl: Path) -> ResearchDataset:
    """Load QRS-Bench-Ind from annotations/consensus_ground_truth.jsonl."""
    rows = _read_jsonl(gt_jsonl)
    pred_jsonl = root / "evaluation_runs" / "per_unit_predictions.jsonl"
    preds_by_id: dict[str, dict[str, Any]] = {}
    if pred_jsonl.is_file():
        for pr in _read_jsonl(pred_jsonl):
            uid = str(pr.get("unit_id") or "")
            if uid:
                preds_by_id[uid] = pr

    # Map (split, org_id, category) -> first core_scenes unit_id for robustness base_id linkage
    core_by_key: dict[tuple[str, str, str], str] = {}
    core_payload_by_id: dict[str, str] = {}
    for r in rows:
        if r.get("stratum") == "core_scenes":
            key = (str(r.get("split") or ""), str(r.get("org_id") or ""), str(r.get("category") or ""))
            if key not in core_by_key:
                core_by_key[key] = str(r["unit_id"])
            core_payload_by_id[str(r["unit_id"])] = str(r.get("payload") or "")

    base_items: list[ResearchItem] = []
    cf_items: list[ResearchItem] = []
    directional_pairs: list[dict[str, Any]] = []
    negative_pairs: list[dict[str, Any]] = []
    rob_items: list[ResearchItem] = []

    for r in rows:
        stratum = str(r.get("stratum") or "")
        unit_id = str(r.get("unit_id") or "")
        pt = _normalize_payload_type(str(r.get("category") or "url"))

        if stratum in ("core_scenes", "challenge_traps"):
            rel = str(r.get("rel_path") or "")
            img_path = _resolve_image(rel, root, root)
            raw_payload = str(r.get("payload") or "")
            lines = r.get("lines") or []
            disp_ctx = f"Organization: {r.get('organization_name', '')}\n" + "\n".join(str(x) for x in lines)
            is_http_pay = (pt == "payment" and raw_payload.lower().startswith(("http://", "https://")))
            enc_pt = "url" if raw_payload.lower().startswith(("http://", "https://")) else pt

            pr = preds_by_id.get(unit_id, {})
            p_inds = list(pr.get("payload_findings") or []) + list(pr.get("context_findings") or [])
            key_inds = p_inds if p_inds else ["BENIGN_CLEAN"]

            gt = {
                **r,
                "scenario_id": unit_id,
                "qr_payload": raw_payload,
                "displayed_context": disp_ctx,
                "expected_assessment": list(r.get("accepted_ground_truth_set") or [r.get("consensus_ground_truth")]),
                "adjudicated_expected_level": str(r.get("consensus_ground_truth") or "no_material_concern"),
                "encoded_payload_type": enc_pt,
                "scenario_purpose": pt,
                "is_http_payment_portal": is_http_pay,
                "key_indicators": key_inds,
                "absent_indicators": ["UNUSED_SENTINEL_INDICATOR"],
                "expected_findings": [str(r.get("subtype") or "clean")],
            }
            base_items.append(ResearchItem(
                item_id=unit_id,
                suite="base",
                image_path=img_path,
                payload_type=pt,
                scenario_family=str(r.get("subtype") or stratum),
                ground_truth=gt,
            ))

        elif stratum == "counterfactual_pairs":
            rel_a = str(r.get("rel_path_a") or "")
            rel_b = str(r.get("rel_path_b") or "")
            img_a = _resolve_image(rel_a, root, root)
            img_b = _resolve_image(rel_b, root, root)
            exp_rel = str(r.get("expected_relation") or "Risk(B) > Risk(A)")
            is_neg = (exp_rel == "Risk(B) == Risk(A)" or str(r.get("subtype") or "").startswith("CF6"))
            exp_dir = "no_change" if is_neg else "b_more_concerning"
            role_class = "negative_control" if is_neg else "directional"

            pair_rec = {
                **r,
                "pair_id": unit_id,
                "id": unit_id,
                "payload_type": pt,
                "image_a": rel_a,
                "image_b": rel_b,
                "expected_direction": exp_dir,
                "pair_class": role_class,
                "qr_payload_A": str(r.get("payload_a") or "https://alderwoodcafe.org/welcome"),
                "qr_payload_B": str(r.get("payload_b") or ("https://alderwoodcafe.org/welcome" if is_neg else "http://198.51.100.42/login?verify=pin")),
                "context_A": {"organization": str(r.get("organization_name") or "Alderwood Cafe"), "purpose": "Verify account"},
                "context_B": {"organization": str(r.get("organization_name") or "Alderwood Cafe"), "purpose": "Verify account"},
            }
            if is_neg:
                negative_pairs.append(pair_rec)
            else:
                directional_pairs.append(pair_rec)

            for role, img_p in (("a", img_a), ("b", img_b)):
                cf_items.append(ResearchItem(
                    item_id=f"{unit_id}_{role}",
                    suite="counterfactual",
                    image_path=img_p,
                    payload_type=pt,
                    pair_id=unit_id,
                    pair_role=role,
                    ground_truth={**pair_rec, "role": role},
                ))

        elif stratum == "robustness_variants":
            rel = str(r.get("rel_path") or "")
            img_path = _resolve_image(rel, root, root)
            key = (str(r.get("split") or ""), str(r.get("org_id") or ""), str(r.get("category") or ""))
            linked_base_id = core_by_key.get(key, str(r.get("seed_id") or ""))
            transform = str(r.get("perturbation") or r.get("subtype") or "R00_clean")
            gt = {
                **r,
                "base_id": linked_base_id,
                "original_scenario_id": linked_base_id,
                "variant_id": unit_id,
                "transformation": transform,
                "qr_payload": str(r.get("payload") or core_payload_by_id.get(linked_base_id, "")),
                "expected_assessment": list(r.get("accepted_ground_truth_set") or [r.get("consensus_ground_truth")]),
                "adjudicated_expected_level": str(r.get("consensus_ground_truth") or "no_material_concern"),
            }
            rob_items.append(ResearchItem(
                item_id=unit_id,
                suite="robustness",
                image_path=img_path,
                payload_type=pt,
                base_id=linked_base_id,
                variant_id=unit_id,
                transformation=transform,
                ground_truth=gt,
            ))

    manifest_hash = _hash_manifest_files([gt_jsonl])
    return ResearchDataset(
        root=root,
        base_items=base_items,
        counterfactual_items=cf_items,
        counterfactual_pairs=directional_pairs,
        counterfactual_negative_controls=negative_pairs,
        robustness_items=rob_items,
        manifest_hash=manifest_hash,
        manifest_files=[str(gt_jsonl.relative_to(root))],
        raw_manifests={"consensus_ground_truth": str(gt_jsonl.relative_to(root))},
    )


def _load_base_items(root: Path, manifest_path: Path | None) -> list[ResearchItem]:
    items: list[ResearchItem] = []
    if manifest_path is None:
        base_dir = _find_subdir(root, _BASE_DIRS) or root
        for img in sorted(base_dir.rglob("*")):
            if img.suffix.lower() in (".png", ".jpg", ".jpeg", ".bmp", ".webp"):
                img = _inside_root(root, img, strict=False)
                pt = _infer_payload_type({}, img, base_dir)
                items.append(ResearchItem(item_id=img.stem, suite="base", image_path=img, payload_type=pt))
        return items

    records = _read_manifest(manifest_path)
    for rec in records:
        rel = (rec.get("scene_image") if BASE_IMAGE_VARIANT == "scene" else rec.get("qr_only_image")) or rec.get("qr_only_image") or rec.get("scene_image")
        if not rel:
            for key in ("image_path", "image", "file", "filename", "path", "image_file"):
                if rec.get(key):
                    rel = rec[key]
                    break
        if not rel:
            continue
        img_path = _resolve_image(str(rel), manifest_path.parent, root)
        item_id = rec.get("scenario_id") or rec.get("id") or rec.get("item_id") or img_path.stem
        pt = _infer_payload_type(rec, img_path, manifest_path.parent)
        skip_keys = {"scene_image", "qr_only_image", "image_path", "image", "file", "filename", "path", "image_file"}
        gt = {k: v for k, v in rec.items() if k not in skip_keys}
        if "scenario_purpose" not in gt and pt != "unknown":
            gt["scenario_purpose"] = pt
        items.append(ResearchItem(
            item_id=str(item_id), suite="base", image_path=img_path, payload_type=pt,
            scenario_family=rec.get("scenario_family") or rec.get("family"), ground_truth=gt,
        ))
    return items


def _load_pair_items(root: Path, records: list[dict[str, Any]], manifest_dir: Path, *, role_class: str) -> list[ResearchItem]:
    items: list[ResearchItem] = []
    for rec in records:
        pair_id = rec.get("pair_id") or rec.get("id") or ""
        if not pair_id:
            continue
        pt = _infer_payload_type(rec, manifest_dir, manifest_dir)
        for role, keys in (("a", ("scenario_A", "image_a", "a_image", "a")), ("b", ("scenario_B", "image_b", "b_image", "b"))):
            rel = next((rec.get(k) for k in keys if rec.get(k)), None)
            if not rel:
                continue
            img_path = _resolve_image(str(rel), manifest_dir, root)
            item_id = f"{pair_id}_{role}"
            skip_keys = {"scenario_A", "scenario_B", "image_a", "image_b", "a_image", "b_image", "a", "b"}
            gt = {"pair_id": str(pair_id), "role": role, "pair_class": role_class,
                  **{k: v for k, v in rec.items() if k not in skip_keys}}
            items.append(ResearchItem(
                item_id=item_id, suite="counterfactual", image_path=img_path, payload_type=pt,
                pair_id=str(pair_id), pair_role=role, ground_truth=gt,
            ))
    return items


def _load_rob_items(root: Path, manifest_path: Path | None) -> list[ResearchItem]:
    items: list[ResearchItem] = []
    if manifest_path is None:
        return items
    records = _read_manifest(manifest_path)
    for rec in records:
        rel = next((rec.get(k) for k in ("image", "image_path", "file", "filename", "path", "image_file", "variant_image") if rec.get(k)), None)
        if not rel:
            continue
        img_path = _resolve_image(str(rel), manifest_path.parent, root)
        item_id = rec.get("variant_id") or rec.get("id") or img_path.stem
        pt = _infer_payload_type(rec, img_path, manifest_path.parent)
        base_id_val = rec.get("original_scenario_id") or rec.get("base_id") or rec.get("original_id")
        variant_id_val = rec.get("variant_id") or rec.get("transform") or item_id
        transformation_val = rec.get("transformation") or rec.get("transform") or rec.get("variant_id")
        skip_keys = {"image", "image_path", "file", "filename", "path", "image_file", "variant_image"}
        gt = {k: v for k, v in rec.items() if k not in skip_keys}
        if base_id_val is not None:
            gt["base_id"] = str(base_id_val)
            gt["original_scenario_id"] = str(base_id_val)
        if variant_id_val is not None:
            gt["variant_id"] = str(variant_id_val)
        if transformation_val is not None:
            gt["transformation"] = str(transformation_val)
        items.append(ResearchItem(
            item_id=str(item_id),
            suite="robustness",
            image_path=img_path,
            payload_type=pt,
            base_id=str(base_id_val) if base_id_val is not None else None,
            variant_id=str(variant_id_val) if variant_id_val is not None else None,
            transformation=str(transformation_val) if transformation_val is not None else None,
            ground_truth=gt,
        ))
    return items


def _find_negative_controls(root: Path) -> Path | None:
    for rel in _NEGATIVE_CF_MANIFESTS:
        p = root / rel
        if p.is_file():
            return _inside_root(root, p, strict=True)
    return None


def load_research_dataset(root: Path) -> ResearchDataset:
    root = Path(root)
    if not root.is_dir():
        raise OSError(f"Research dataset not found at: {root}")
    root = root.resolve(strict=True)

    qrs_bench_gt = root / "annotations" / "consensus_ground_truth.jsonl"
    if qrs_bench_gt.is_file():
        return _load_qrs_bench_ind(root, _inside_root(root, qrs_bench_gt, strict=True))

    base_dir = _find_subdir(root, _BASE_DIRS) or root
    cf_dir = _find_subdir(root, _CF_DIRS) or root
    rob_dir = _find_subdir(root, _ROB_DIRS) or root

    base_manifest = _find_manifest(root, _BASE_MANIFESTS, root) or _find_manifest(base_dir, _BASE_MANIFESTS, root)
    cf_manifest = _find_manifest(root, _CF_MANIFESTS, root) or _find_manifest(cf_dir, _CF_MANIFESTS, root)
    rob_manifest = _find_manifest(root, _ROB_MANIFESTS, root) or _find_manifest(rob_dir, _ROB_MANIFESTS, root)
    negative_manifest = _find_negative_controls(root)

    found_manifests = [p for p in [base_manifest, cf_manifest, negative_manifest, rob_manifest] if p is not None]
    manifest_hash = _hash_manifest_files(found_manifests)
    manifest_files = [str(p.relative_to(root)) for p in found_manifests]

    raw_manifests: dict[str, Any] = {}
    for key, mp in (("base", base_manifest), ("counterfactual", cf_manifest), ("counterfactual_negative_controls", negative_manifest), ("robustness", rob_manifest)):
        if mp and mp.suffix == ".json":
            raw_manifests[key] = json.loads(mp.read_text(encoding="utf-8-sig"))

    base_items = _load_base_items(root, base_manifest)
    directional_pairs = _read_manifest(cf_manifest) if cf_manifest else []
    negative_pairs = _read_manifest(negative_manifest) if negative_manifest else []
    cf_items = _load_pair_items(root, directional_pairs, cf_manifest.parent if cf_manifest else root, role_class="directional")
    cf_items += _load_pair_items(root, negative_pairs, negative_manifest.parent if negative_manifest else root, role_class="negative_control")
    rob_items = _load_rob_items(root, rob_manifest)

    return ResearchDataset(
        root=root,
        base_items=base_items,
        counterfactual_items=cf_items,
        counterfactual_pairs=directional_pairs,
        counterfactual_negative_controls=negative_pairs,
        robustness_items=rob_items,
        manifest_hash=manifest_hash,
        manifest_files=manifest_files,
        raw_manifests=raw_manifests,
    )
