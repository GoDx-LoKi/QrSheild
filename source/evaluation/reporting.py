"""Research run artifact writers: JSONL, CSV, JSON summary.

The report_html module handles HTML generation.
This module handles structured data outputs.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .image_runner import portable_image_path


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    cols = list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def _flatten_result(r: dict[str, Any]) -> dict[str, Any]:
    """Flatten a result record for CSV output (drop raw_result blob)."""
    raw_asmt = (r.get("raw_result") or {}).get("assessment", {}) if r.get("raw_result") else {}
    return {
        "item_id": r.get("item_id"),
        "suite": r.get("suite"),
        "base_id": r.get("base_id") or r.get("original_scenario_id"),
        "variant_id": r.get("variant_id"),
        "transformation": r.get("transformation"),
        "pair_id": r.get("pair_id"),
        "pair_role": r.get("pair_role"),
        "image_path": portable_image_path(r.get("image_path") or ""),
        "image_hash": r.get("image_hash"),
        "failure_code": r.get("failure_code"),
        "evaluable": r.get("evaluable"),
        "qr_detected": r.get("qr_detected"),
        "qr_decode_success": r.get("qr_decode_success"),
        "qr_decoder": r.get("qr_decoder"),
        "ocr_status": r.get("ocr_status"),
        "ocr_engine": r.get("ocr_engine"),
        "ocr_block_count": r.get("ocr_block_count"),
        "context_accepted_count": r.get("context_accepted_count"),
        "context_status": r.get("context_status") or raw_asmt.get("context_status"),
        "context_incomplete": r.get("context_incomplete") if r.get("context_incomplete") is not None else raw_asmt.get("context_incomplete"),
        "payload_type": r.get("payload_type"),
        "assessment_level": r.get("assessment_level"),
        "assessment_label": r.get("assessment_label"),
        "assessment_confidence": r.get("assessment_confidence"),
        "action_sensitivity": r.get("action_sensitivity"),
        "total_ms": r.get("total_ms"),
    }


def write_suite_artifacts(
    suite_dir: Path,
    run_manifest: dict[str, Any],
    results: list[dict[str, Any]],
    metrics: dict[str, Any],
) -> None:
    """Write all artifacts for one suite: JSONL (already written incrementally), CSV, JSON summary."""
    suite_dir.mkdir(parents=True, exist_ok=True)
    _write_json(suite_dir / "run_manifest.json", run_manifest)
    _write_json(suite_dir / "summary.json", metrics)
    flat = [_flatten_result(r) for r in results]
    _write_csv(suite_dir / "results.csv", flat)

    # Write cross-tabulation CSVs for base suite (P1 #6)
    asmt = metrics.get("assessment") or {}
    cat_xtab = asmt.get("expected_category_vs_predicted_level")
    if isinstance(cat_xtab, dict) and cat_xtab:
        xtab_rows = [
            {"expected_category": cat, **counts, "total": sum(counts.values())}
            for cat, counts in cat_xtab.items()
        ]
        _write_csv(suite_dir / "expected_category_vs_predicted_level.csv", xtab_rows)
    adj_conf = asmt.get("adjudicated_confusion_matrix")
    if isinstance(adj_conf, dict) and adj_conf:
        conf_rows = [
            {"adjudicated_expected_level": lvl, **counts, "total": sum(counts.values())}
            for lvl, counts in adj_conf.items()
        ]
        _write_csv(suite_dir / "adjudicated_confusion_matrix.csv", conf_rows)


def write_overall_summary(
    overall_dir: Path,
    run_manifest: dict[str, Any],
    suite_metrics: dict[str, dict[str, Any]],
) -> None:
    """Write overall summary for an 'all' run."""
    overall_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "run_id": run_manifest.get("run_id"),
        "suite": "all",
        "dataset_root": run_manifest.get("dataset_root"),
        "dataset_manifest_hash": run_manifest.get("dataset_manifest_hash"),
        "threat_intelligence": "disabled",
        "suites": suite_metrics,
    }
    _write_json(overall_dir / "summary.json", summary)
    _write_json(overall_dir / "run_manifest.json", run_manifest)
