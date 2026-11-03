"""Run QRShield's reproducible benchmark or batch scenario evaluation from the command line.

Examples:
    python -m evaluation --mode validate-only
    python -m evaluation --mode validate-only --verify-payloads
    python -m evaluation --mode all --ocr-provider paddleocr
    python -m evaluation --mode robustness --ocr-provider tesseract
    python -m evaluation --batch-jsonl ../release/evidence/redteam_208_scenarios.jsonl

Research execution requires an explicit local OCR provider (PaddleOCR or Tesseract).
The CLI never silently switches to payload-only evaluation for image suites and disables synthetic references by default.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from qrshield_core.config import Settings
from qrshield_core.models import Confidence, Context, ContextAttribute
from qrshield_core.ocr.engine import create_ocr_provider
from qrshield_core.pipeline import AnalysisConfig, QRShieldEngine

from .dataset_loader import discover_dataset_root, load_research_dataset
from .image_runner import preflight_ocr
from .run_manager import RunProgress, build_run_manifest, make_run_id, run_dir
from .validator import validate_dataset

SUITES = ("base", "counterfactual", "robustness", "all")
OCR_PROVIDERS = ("paddleocr", "tesseract", "auto")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate or execute the QRShield benchmark.")
    parser.add_argument(
        "--mode", choices=(*SUITES, "validate-only"), default="all",
        help="Suite to run, or validate-only to check the dataset without starting OCR.",
    )
    parser.add_argument("--dataset", type=Path, default=None, help="Dataset root (default: auto-discovered project dataset).")
    parser.add_argument("--artifacts-dir", type=Path, default=None, help="Override the artifact output directory.")
    parser.add_argument(
        "--ocr-provider",
        choices=OCR_PROVIDERS,
        default=None,
        help="Local OCR provider to use for image evaluation (default: from OCR_PROVIDER env or 'paddleocr').",
    )
    parser.add_argument(
        "--verify-payloads",
        action="store_true",
        help="Decode QR symbols during validation to verify image payloads match manifest qr_payloads.",
    )
    parser.add_argument(
        "--batch-jsonl",
        type=Path,
        default=None,
        help="Evaluate a declarative JSONL file of {case_id, payload, ctx_attrs} scenarios and emit JSONL results to stdout.",
    )
    parser.add_argument(
        "--decode-images-dir",
        type=Path,
        default=None,
        help="Run QRShield multi-pass QR decoder on all PNG images under the directory and emit JSONL results to stdout.",
    )
    return parser


def _run_batch_jsonl(jsonl_path: Path) -> int:
    engine = QRShieldEngine(Settings(ocr_provider="mock", load_synthetic_reference=False, log_level="ERROR"))
    cfg = AnalysisConfig("payload_context_action", True, True, True, "off")
    lines = [ln for ln in jsonl_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    for ln in lines:
        item = json.loads(ln)
        ctx_attrs = item.get("ctx_attrs") or []
        ctx = Context(
            attributes=[
                ContextAttribute(
                    attribute=str(k),
                    value=str(v),
                    source="ocr",
                    confidence=Confidence.HIGH,
                    raw_value=str(v),
                )
                for k, v in ctx_attrs
            ]
        )
        res = engine.analyze_payload(str(item["payload"]), context=ctx, config=cfg).to_dict()
        out_row = {
            "case_id": item.get("case_id"),
            "kind": item.get("kind"),
            "category": item.get("category"),
            "predicted_level": res["assessment"]["level"],
            "primary_type": res.get("payload", {}).get("primary_type", ""),
            "action_sensitivity": res.get("action", {}).get("sensitivity_level", ""),
        }
        print(json.dumps(out_row, ensure_ascii=False))
    return 0


def _run_decode_images_dir(images_dir: Path) -> int:
    import cv2
    import numpy as np
    from qrshield_core.decoder.qr import detect_and_decode

    for img_path in sorted(images_dir.rglob("*.png")):
        raw_bytes = img_path.read_bytes()
        arr = cv2.imdecode(np.frombuffer(raw_bytes, np.uint8), cv2.IMREAD_COLOR)
        dec = detect_and_decode(arr)
        decoded_codes = dec.decoded_codes
        primary = decoded_codes[0] if decoded_codes else None
        print(json.dumps({
            "rel_from_dir": str(img_path.relative_to(images_dir)),
            "decoded": bool(primary and primary.decoded and primary.payload),
            "payload": (primary.payload or "") if primary else "",
            "decoder": primary.decoder if primary else "",
            "variant": primary.variant if primary else "",
            "count": dec.count,
        }, ensure_ascii=False))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.batch_jsonl is not None:
        return _run_batch_jsonl(args.batch_jsonl)
    if args.decode_images_dir is not None:
        return _run_decode_images_dir(args.decode_images_dir)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    dataset_root = args.dataset or discover_dataset_root()
    try:
        ds = load_research_dataset(dataset_root)
        validation = validate_dataset(ds, verify_payloads=bool(args.verify_payloads))
    except Exception as exc:
        print(f"Dataset validation could not complete safely: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    validation_summary = {
        "valid": validation.ok,
        "structural_valid": validation.structural_valid,
        "semantic_valid": validation.semantic_valid,
        "dataset_root": str(ds.root.name),
        "counts": validation.counts,
        "per_payload": validation.per_payload,
        "manifest_hash": ds.manifest_hash,
        "image_inventory_hash": validation.image_inventory_hash,
        "missing_base_links": validation.missing_base_links,
        "hash_mismatches": validation.hash_mismatches,
        "payload_mismatches": validation.payload_mismatches,
        "errors": validation.errors,
        "warnings": validation.warnings,
    }
    print(json.dumps(validation_summary, indent=2, ensure_ascii=False))
    if not validation.ok:
        print("The fixed benchmark protocol failed validation; no evaluation was started.", file=sys.stderr)
        return 2
    if args.mode == "validate-only":
        return 0

    settings = Settings.from_env()
    if args.artifacts_dir is not None:
        settings.artifacts_dir = args.artifacts_dir
    if args.ocr_provider is not None:
        settings.ocr_provider = args.ocr_provider
    settings.ensure_dirs()
    ocr_provider = create_ocr_provider(settings.ocr_provider) if settings.ocr_enabled else None
    engine = QRShieldEngine(settings, ocr_provider=ocr_provider)
    ocr_ok, ocr_reason = preflight_ocr(engine)
    if not ocr_ok:
        print(
            f"Evaluation not started: local OCR provider ({settings.ocr_provider}) is required for image/OCR evaluation. "
            + ocr_reason,
            file=sys.stderr,
        )
        return 3

    from app.routes.research import (
        _run_all_thread, _run_robustness_with_baseline_thread, _run_suite_thread,
    )

    run_id = make_run_id(args.mode)
    if args.mode == "all":
        items = ds.all_items()
        executed_suites = ["base", "counterfactual", "robustness"]
    elif args.mode == "robustness":
        items = ds.base_items + ds.robustness_items
        executed_suites = ["base", "robustness"]
    else:
        items = ds.items_for_suite(args.mode)
        executed_suites = [args.mode]

    manifest = build_run_manifest(engine, ds, run_id, args.mode, len(items), validation.image_inventory_hash)
    manifest["executed_suites"] = executed_suites
    output_dir = run_dir(settings.artifacts_dir, run_id)
    try:
        output_dir.mkdir(parents=True, exist_ok=False)
        (output_dir / "run_manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
        )
        RunProgress(
            run_id=run_id, suite=args.mode, total=len(items), completed=0, failed=0,
            started_utc=str(manifest.get("started_utc") or datetime.now(timezone.utc).isoformat(timespec="seconds")),
            status="running",
        ).save(settings.artifacts_dir)
    except OSError as exc:
        print(f"Could not prepare run output directory: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 4

    try:
        if args.mode == "all":
            _run_all_thread(engine, ds, run_id, settings.artifacts_dir, manifest)
        elif args.mode == "robustness":
            _run_robustness_with_baseline_thread(engine, ds, run_id, settings.artifacts_dir, manifest)
        else:
            _run_suite_thread(engine, ds, args.mode, items, run_id, settings.artifacts_dir, manifest)
    except Exception as exc:
        logging.getLogger("qrshield.evaluation.cli").exception("Research evaluation failed")
        progress = RunProgress.load(settings.artifacts_dir, run_id)
        if progress is not None:
            progress.status = "error"
            progress.error_message = "Evaluation failed unexpectedly; see application logs."
            progress.save(settings.artifacts_dir)
        print(f"Evaluation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 5

    progress = RunProgress.load(settings.artifacts_dir, run_id)
    print(json.dumps({
        "run_id": run_id,
        "run_directory": str(output_dir),
        "ocr_provider": getattr(engine.ocr_provider, "name", "none"),
        "status": progress.status if progress else "unknown",
        "completed": progress.completed if progress else None,
        "total": progress.total if progress else len(items),
        "failed": progress.failed if progress else None,
        "executed_suites": executed_suites,
    }, indent=2))
    return 0 if progress is not None and progress.status == "done" else 5


if __name__ == "__main__":
    raise SystemExit(main())
