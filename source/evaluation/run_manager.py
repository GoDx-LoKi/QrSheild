"""Research run directory management: incremental persistence, resumability, progress tracking.

Results are written to JSONL (one JSON line per completed item) so that
an interrupted run can be resumed without losing completed results.
"""
from __future__ import annotations

import json
import platform
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from qrshield_core import __version__
from qrshield_core.pipeline import QRShieldEngine

from .dataset_loader import ResearchDataset
from .image_runner import RESEARCH_CONFIG, ItemResult, portable_image_path


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def make_run_id(suite: str) -> str:
    return f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{suite[:16].lower().replace(' ', '_')}-{secrets.token_hex(3)}"


def run_dir(artifacts_dir: Path, run_id: str) -> Path:
    return artifacts_dir / "runs" / run_id


def suite_dir(artifacts_dir: Path, run_id: str, suite: str) -> Path:
    return run_dir(artifacts_dir, run_id) / suite


def results_jsonl_path(artifacts_dir: Path, run_id: str, suite: str) -> Path:
    return suite_dir(artifacts_dir, run_id, suite) / "results.jsonl"


def progress_json_path(artifacts_dir: Path, run_id: str) -> Path:
    return run_dir(artifacts_dir, run_id) / "progress.json"


def build_run_manifest(engine: QRShieldEngine, ds: ResearchDataset,
                       run_id: str, suite: str, item_count: int,
                       dataset_inventory_hash: str = "") -> dict[str, Any]:
    """Build a reproducibility manifest for the run."""
    ocr = engine.ocr_provider
    return {
        "run_id": run_id,
        "suite": suite,
        "started_utc": _utc_now(),
        "ended_utc": None,
        "dataset_root": ds.root.name,
        "dataset_manifest_hash": ds.manifest_hash,
        "dataset_manifest_files": ds.manifest_files,
        "dataset_image_inventory_hash": dataset_inventory_hash or None,
        "item_count": item_count,
        "dataset_scope": {
            "base_images": len(ds.base_items),
            "counterfactual_images": len(ds.counterfactual_items),
            "counterfactual_directional_pairs": len(ds.counterfactual_pairs),
            "counterfactual_negative_control_pairs": len(getattr(ds, "counterfactual_negative_controls", [])),
            "robustness_variants": len(ds.robustness_items),
        },
        "qrshield_version": __version__,
        "research_analysis_config": RESEARCH_CONFIG.to_dict(),
        "threat_intelligence": "disabled",
        "ocr": {
            "engine": getattr(ocr, "name", "none"),
            "version": getattr(ocr, "version", None),
            "config": getattr(ocr, "config", {}),
            "policy": "all_candidates_auto_accepted",
        },
        "python_version": sys.version.split()[0],
        "platform": platform.platform(terse=True),
        "engine_manifest": engine.manifest(config=RESEARCH_CONFIG),
    }


def load_completed_ids(jsonl_path: Path) -> set[str]:
    """Load item IDs that have already been completed from a JSONL results file."""
    if not jsonl_path.exists():
        return set()
    completed = set()
    for line in jsonl_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            item_id = rec.get("item_id")
            if item_id:
                completed.add(str(item_id))
        except json.JSONDecodeError:
            pass
    return completed


def append_result(jsonl_path: Path, result: ItemResult) -> None:
    """Atomically append one result to the JSONL file."""
    record = _item_result_to_dict(result)
    with jsonl_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        f.flush()


def _item_result_to_dict(r: ItemResult) -> dict[str, Any]:
    raw_asmt = (r.raw_result or {}).get("assessment", {}) if r.raw_result else {}
    d: dict[str, Any] = {
        "item_id": r.item_id,
        "suite": r.suite,
        "image_path": portable_image_path(r.image_path),
        "image_hash": r.image_hash,
        "failure_code": r.failure_code.value,
        "failure_stage": r.failure_stage,
        "failure_message": r.failure_message,
        "evaluable": r.evaluable,
        "base_id": r.base_id,
        "original_scenario_id": r.base_id,
        "variant_id": r.variant_id,
        "transformation": r.transformation,
        "pair_id": r.pair_id,
        "pair_role": r.pair_role,
        "qr_detected": r.qr_detected,
        "qr_count": r.qr_count,
        "qr_decoder": r.qr_decoder,
        "qr_decode_success": r.qr_decode_success,
        "qr_payload_redacted": r.qr_payload_redacted,
        "ocr_status": r.ocr_status,
        "ocr_engine": r.ocr_engine,
        "ocr_engine_version": r.ocr_engine_version,
        "ocr_duration_ms": r.ocr_duration_ms,
        "ocr_block_count": r.ocr_block_count,
        "context_candidate_count": r.context_candidate_count,
        "context_accepted_count": r.context_accepted_count,
        "payload_type": r.payload_type,
        "assessment_level": r.assessment_level,
        "assessment_label": r.assessment_label,
        "assessment_confidence": r.assessment_confidence,
        "action_sensitivity": r.action_sensitivity,
        "context_status": r.context_status or raw_asmt.get("context_status"),
        "context_incomplete": r.context_incomplete if r.context_incomplete is not None else raw_asmt.get("context_incomplete"),
        "timings_ms": r.timings_ms,
        "total_ms": r.total_ms,
    }
    if r.raw_result is not None:
        d["raw_result"] = r.raw_result
    return d


def load_results_jsonl(jsonl_path: Path) -> list[dict[str, Any]]:
    """Load all result records from a JSONL file, normalizing portable paths."""
    if not jsonl_path.exists():
        return []
    results = []
    for line in jsonl_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            if rec.get("image_path"):
                rec["image_path"] = portable_image_path(rec["image_path"])
            results.append(rec)
        except json.JSONDecodeError:
            pass
    return results


@dataclass
class RunProgress:
    run_id: str
    suite: str
    total: int
    completed: int
    failed: int
    started_utc: str
    status: str   # running | done | error
    current_item: str | None = None
    error_message: str | None = None

    @property
    def remaining(self) -> int:
        return max(0, self.total - self.completed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id, "suite": self.suite, "total": self.total,
            "completed": self.completed, "failed": self.failed,
            "remaining": self.remaining, "started_utc": self.started_utc,
            "status": self.status, "current_item": self.current_item,
            "error_message": self.error_message,
        }

    def save(self, artifacts_dir: Path) -> None:
        p = progress_json_path(artifacts_dir, self.run_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, artifacts_dir: Path, run_id: str) -> "RunProgress | None":
        p = progress_json_path(artifacts_dir, run_id)
        if not p.exists():
            return None
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
        except Exception:
            return None
