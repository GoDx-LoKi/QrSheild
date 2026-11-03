"""Research Tests: GUI-driven evaluation of the external research dataset.

Replaces the old Evaluation Lab. Uses the SAME QRShieldEngine as normal Analyze.
Key invariants enforced here:
 - threat_intel_mode is always "off" (via RESEARCH_CONFIG in image_runner)
 - all OCR candidates are auto-accepted (auto_use_unconfirmed=True)
 - ground truth is never passed to inference
 - Local OCR provider is required; runs fail preflight if unavailable
"""
from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from evaluation.dataset_loader import discover_dataset_root, load_research_dataset
from evaluation.failures import FailureCode
from evaluation.image_runner import RESEARCH_CONFIG, portable_image_path, preflight_ocr, run_image
from evaluation.report_html import (
    generate_base_html, generate_counterfactual_html, generate_overall_html,
    generate_robustness_html, write_html_report,
)
from evaluation.reporting import write_overall_summary, write_suite_artifacts
from evaluation.run_manager import (
    RunProgress, append_result, build_run_manifest, load_completed_ids,
    load_results_jsonl, make_run_id, results_jsonl_path, run_dir, suite_dir,
)
from evaluation.scoring import score_base, score_counterfactual, score_robustness
from evaluation.validator import validate_dataset, validate_dataset_root

from .analyze import qs_, render

router = APIRouter()

VALID_SUITES = ("base", "counterfactual", "robustness", "all")
RUN_ARTIFACT_EXTENSIONS = {".json", ".jsonl", ".csv", ".html"}
RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[a-zA-Z0-9_]{1,16}-[0-9a-fA-F]{6}$")
logger = logging.getLogger("qrshield.research")

# One OCR research run at a time: OCR models and image processing are CPU/RAM intensive.
_active_runs: dict[str, threading.Thread] = {}
_active_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Helper: run a suite in a background thread
# ---------------------------------------------------------------------------
def _run_suite_thread(
    engine: Any,
    ds: Any,
    suite: str,
    items: list,
    run_id: str,
    artifacts_dir: Path,
    run_manifest: dict,
    *,
    finalize: bool = True,
) -> bool:
    """Execute one suite; optional finalization supports multi-stage runs."""
    s_dir = suite_dir(artifacts_dir, run_id, suite)
    s_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = results_jsonl_path(artifacts_dir, run_id, suite)

    # Resume support: skip already-completed items and preserve prior failure counts.
    existing_results = load_results_jsonl(jsonl_path)
    completed_ids = {str(record.get("item_id")) for record in existing_results if record.get("item_id")}
    remaining = [item for item in items if item.item_id not in completed_ids]
    failed = sum(1 for record in existing_results if not record.get("evaluable"))

    progress = RunProgress(
        run_id=run_id, suite=suite, total=len(items),
        completed=len(completed_ids), failed=failed,
        started_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        status="running",
    )
    progress.save(artifacts_dir)

    for item in remaining:
        progress.current_item = item.item_id
        progress.save(artifacts_dir)
        try:
            result = run_image(
                engine,
                item.item_id,
                suite,
                item.image_path,
                base_id=getattr(item, "base_id", None),
                variant_id=getattr(item, "variant_id", None),
                transformation=getattr(item, "transformation", None),
                pair_id=getattr(item, "pair_id", None),
                pair_role=getattr(item, "pair_role", None),
            )
        except Exception as exc:
            from evaluation.image_runner import ItemResult
            dummy = ItemResult(
                item_id=item.item_id,
                suite=suite,
                image_path=portable_image_path(item.image_path),
                image_hash="",
                failure_code=FailureCode.RUNTIME_ERROR,
                failure_stage="run_image",
                failure_message=f"{type(exc).__name__}: {exc}",
                base_id=getattr(item, "base_id", None),
                variant_id=getattr(item, "variant_id", None),
                transformation=getattr(item, "transformation", None),
                pair_id=getattr(item, "pair_id", None),
                pair_role=getattr(item, "pair_role", None),
            )
            from evaluation.run_manager import append_result as _append
            _append(jsonl_path, dummy)
            failed += 1
            progress.failed = failed
            progress.completed += 1
            progress.save(artifacts_dir)
            continue

        append_result(jsonl_path, result)
        if not result.evaluable:
            failed += 1
        progress.completed += 1
        progress.failed = failed
        progress.save(artifacts_dir)

    # --- Scoring phase (after all predictions frozen) ---
    all_results = load_results_jsonl(jsonl_path)
    gt_by_id: dict[str, dict[str, Any]] = {}
    for item in items:
        gt_entry = dict(item.ground_truth or {})
        if getattr(item, "base_id", None) and "base_id" not in gt_entry:
            gt_entry["base_id"] = item.base_id
            gt_entry["original_scenario_id"] = item.base_id
        if getattr(item, "variant_id", None) and "variant_id" not in gt_entry:
            gt_entry["variant_id"] = item.variant_id
        if getattr(item, "transformation", None) and "transformation" not in gt_entry:
            gt_entry["transformation"] = item.transformation
        gt_by_id[item.item_id] = gt_entry

    scoring_failed = False
    try:
        if suite == "base":
            metrics = score_base(all_results, gt_by_id)
            html_content = generate_base_html(run_manifest, all_results, metrics)
        elif suite == "counterfactual":
            gt_by_pair = {str(p.get("pair_id", "")): p for p in ds.counterfactual_pairs}
            gt_by_pair.update({str(p.get("pair_id", "")): p for p in ds.counterfactual_negative_controls})
            metrics = score_counterfactual(
                all_results,
                ds.counterfactual_pairs,
                gt_by_pair,
                negative_controls=ds.counterfactual_negative_controls,
            )
            html_content = generate_counterfactual_html(run_manifest, all_results, metrics)
        elif suite == "robustness":
            # Build base results index for comparison
            base_jsonl = results_jsonl_path(artifacts_dir, run_id, "base")
            base_results = {r["item_id"]: r for r in load_results_jsonl(base_jsonl)} if base_jsonl.exists() else {}
            metrics = score_robustness(all_results, base_results, gt_by_id)
            html_content = generate_robustness_html(run_manifest, all_results, metrics)
        else:
            metrics = {"suite": suite, "note": "Combined suite; see per-suite reports."}
            html_content = "<html><body>See per-suite reports.</body></html>"

        write_suite_artifacts(s_dir, run_manifest, all_results, metrics)
        write_html_report(s_dir / "report.html", html_content)
    except Exception:
        scoring_failed = True
        logger.exception("Scoring/report generation failed for run %s suite %s", run_id, suite)
        (s_dir / "scoring_error.txt").write_text(
            "Scoring or report generation failed. See application logs for details.\n",
            encoding="utf-8",
        )

    progress.status = "error" if scoring_failed else ("done" if finalize else "running")
    progress.error_message = "Scoring/report generation failed; see server logs." if scoring_failed else None
    progress.current_item = None
    progress.save(artifacts_dir)
    return not scoring_failed


def _finalize_multi_suite_progress(
    ds: Any, run_id: str, artifacts_dir: Path, *, suite: str, successful: bool, started_utc: str,
) -> None:
    """Mark a multi-stage run complete only after every stage and report is finished."""
    suite_names = ("base", "counterfactual", "robustness") if suite == "all" else ("base", "robustness")
    records = []
    for name in suite_names:
        records.extend(load_results_jsonl(results_jsonl_path(artifacts_dir, run_id, name)))
    total = len(ds.all_items()) if suite == "all" else len(ds.base_items) + len(ds.robustness_items)
    progress = RunProgress(
        run_id=run_id, suite=suite, total=total, completed=min(total, len(records)),
        failed=sum(1 for record in records if not record.get("evaluable")),
        started_utc=started_utc, status="done" if successful else "error",
        error_message=None if successful else "At least one evaluation or reporting stage failed; inspect suite reports and server logs.",
    )
    progress.save(artifacts_dir)


def _write_overall_report(run_id: str, artifacts_dir: Path, run_manifest: dict,
                          suite_metrics: dict[str, dict]) -> None:
    overall_dir = run_dir(artifacts_dir, run_id) / "overall"
    write_overall_summary(overall_dir, run_manifest, suite_metrics)
    write_html_report(overall_dir / "report.html", generate_overall_html(run_manifest, suite_metrics))


def _run_all_thread(engine: Any, ds: Any, run_id: str, artifacts_dir: Path, run_manifest: dict) -> None:
    """Run all suites sequentially; progress remains running until the final report is written."""
    suite_metrics: dict[str, dict] = {}
    successful = True
    for suite, items in [
        ("base", ds.base_items),
        ("counterfactual", ds.counterfactual_items),
        ("robustness", ds.robustness_items),
    ]:
        successful = _run_suite_thread(
            engine, ds, suite, items, run_id, artifacts_dir, run_manifest, finalize=False,
        ) and successful
        s_dir = suite_dir(artifacts_dir, run_id, suite)
        summary_p = s_dir / "summary.json"
        if summary_p.exists():
            try:
                suite_metrics[suite] = json.loads(summary_p.read_text(encoding="utf-8"))
            except Exception:
                successful = False
                logger.exception("Could not read summary for run %s suite %s", run_id, suite)

    try:
        _write_overall_report(run_id, artifacts_dir, run_manifest, suite_metrics)
    except Exception:
        successful = False
        logger.exception("Could not write overall report for research run %s", run_id)
    _finalize_multi_suite_progress(
        ds, run_id, artifacts_dir, suite="all", successful=successful,
        started_utc=str(run_manifest.get("started_utc") or datetime.now(timezone.utc).isoformat(timespec="seconds")),
    )


def _run_robustness_with_baseline_thread(
    engine: Any, ds: Any, run_id: str, artifacts_dir: Path, run_manifest: dict,
) -> None:
    """Run base predictions first so robustness retention is compared to a real baseline."""
    started = str(run_manifest.get("started_utc") or datetime.now(timezone.utc).isoformat(timespec="seconds"))
    base_ok = _run_suite_thread(
        engine, ds, "base", ds.base_items, run_id, artifacts_dir, run_manifest, finalize=False,
    )
    robustness_ok = _run_suite_thread(
        engine, ds, "robustness", ds.robustness_items, run_id, artifacts_dir, run_manifest, finalize=False,
    )
    metrics: dict[str, dict] = {}
    for name in ("base", "robustness"):
        summary_p = suite_dir(artifacts_dir, run_id, name) / "summary.json"
        if summary_p.exists():
            try:
                metrics[name] = json.loads(summary_p.read_text(encoding="utf-8"))
            except Exception:
                base_ok = False
                logger.exception("Could not read summary for run %s suite %s", run_id, name)
        else:
            base_ok = False
    try:
        _write_overall_report(run_id, artifacts_dir, run_manifest, metrics)
    except Exception:
        base_ok = False
        logger.exception("Could not write robustness baseline report for run %s", run_id)
    _finalize_multi_suite_progress(
        ds, run_id, artifacts_dir, suite="robustness", successful=base_ok and robustness_ok,
        started_utc=started,
    )


def _managed_run_thread(run_id: str, target, args: tuple, artifacts_dir: Path) -> None:
    """Isolate unexpected worker exceptions and always release the active-run slot."""
    try:
        target(*args)
    except Exception:
        logger.exception("Research run %s failed unexpectedly", run_id)
        progress = RunProgress.load(artifacts_dir, run_id)
        if progress is not None:
            progress.status = "error"
            progress.current_item = None
            progress.error_message = "Research run failed unexpectedly; see server logs for details."
            try:
                progress.save(artifacts_dir)
            except OSError:
                logger.exception("Could not persist error state for research run %s", run_id)
    finally:
        with _active_lock:
            if _active_runs.get(run_id) is threading.current_thread():
                _active_runs.pop(run_id, None)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@router.get("/research", response_class=HTMLResponse)
async def research_page(request: Request):
    qs = qs_(request)
    dataset_root = discover_dataset_root()
    validation = None
    ds = None
    if dataset_root.exists():
        try:
            ds = load_research_dataset(dataset_root)
            from evaluation.validator import validate_dataset
            validation = validate_dataset(ds)
        except Exception as exc:
            from evaluation.validator import ValidationResult
            validation = ValidationResult(ok=False, errors=[str(exc)], dataset_root=str(dataset_root))

    runs = qs.list_runs(limit=20)
    return render(request, "research.html", {
        "page": "research",
        "dataset_root": str(dataset_root),
        "dataset_exists": dataset_root.exists(),
        "ds": ds,
        "validation": validation,
        "runs": runs,
        "suites": VALID_SUITES,
        "ocr_policy": "Local OCR · automatic acceptance (all OCR candidates accepted)",
        "ti_policy": "Threat intelligence disabled · no external lookups · static analysis only",
    })


@router.post("/research/validate", response_class=HTMLResponse)
async def validate_dataset_route(request: Request):
    dataset_root = discover_dataset_root()
    from evaluation.validator import validate_dataset_root as _validate
    validation = _validate(dataset_root)
    ds = None
    if validation.ok or (not validation.errors):
        try:
            ds = load_research_dataset(dataset_root)
        except Exception:
            pass
    return render(request, "partials/research_status.html", {
        "dataset_root": str(dataset_root),
        "dataset_exists": dataset_root.exists(),
        "ds": ds,
        "validation": validation,
    })


@router.post("/research/run", response_class=HTMLResponse)
async def start_research_run(request: Request):
    qs = qs_(request)
    form = await request.form()
    suite = str(form.get("suite", ""))
    if suite not in VALID_SUITES:
        return render(request, "partials/error.html",
                      {"title": "Invalid suite", "message": f"Unknown test suite '{suite}'."})

    # Load and validate dataset
    dataset_root = discover_dataset_root()
    if not dataset_root.exists():
        return render(request, "partials/error.html", {
            "title": "Dataset not found",
            "message": f"Research dataset not found at '{dataset_root}'. "
                       f"Place 'qrs_bench_ind' beside the project root.",
        })

    try:
        ds = load_research_dataset(dataset_root)
    except Exception as exc:
        logger.warning("Research dataset load rejected: %s", type(exc).__name__)
        return render(request, "partials/error.html",
                      {"title": "Dataset load error", "message": "The research dataset could not be loaded safely. Check manifest paths and JSON structure."}, 400)

    validation = validate_dataset(ds)
    if not validation.ok:
        details = "; ".join(validation.errors[:6])
        if len(validation.errors) > 6:
            details += f"; and {len(validation.errors) - 6} additional validation error(s)"
        return render(request, "partials/error.html", {
            "title": "Dataset validation failed",
            "message": f"The fixed QRShield benchmark protocol must pass all checks before a run. {details}",
        }, 400)

    # Preflight: local OCR required
    engine = qs.engine
    ocr_ok, ocr_why = preflight_ocr(engine)
    if not ocr_ok:
        return render(request, "partials/error.html", {
            "title": "OCR engine unavailable",
            "message": f"A local OCR engine is required for research testing. {ocr_why}",
        })

    # Prepare the run metadata.
    run_id = make_run_id(suite)
    artifacts_dir = qs.settings.artifacts_dir
    r_dir = run_dir(artifacts_dir, run_id)
    if suite == "all":
        items = ds.all_items()
        execution_suites = ["base", "counterfactual", "robustness"]
        target = _run_all_thread
        target_args = (engine, ds, run_id, artifacts_dir, None)
    elif suite == "robustness":
        items = ds.base_items + ds.robustness_items
        execution_suites = ["base", "robustness"]
        target = _run_robustness_with_baseline_thread
        target_args = (engine, ds, run_id, artifacts_dir, None)
    else:
        items = ds.items_for_suite(suite)
        execution_suites = [suite]
        target = _run_suite_thread
        target_args = (engine, ds, suite, items, run_id, artifacts_dir, None)

    manifest = build_run_manifest(engine, ds, run_id, suite, len(items), validation.image_inventory_hash)
    manifest["executed_suites"] = execution_suites
    target_args = tuple(manifest if value is None else value for value in target_args)

    with _active_lock:
        stale = [rid for rid, active in _active_runs.items() if not active.is_alive()]
        for rid in stale:
            _active_runs.pop(rid, None)
        if _active_runs:
            return render(request, "partials/error.html", {
                "title": "Research run already active",
                "message": "Only one research run can execute at a time. Wait for the active run to finish, then retry.",
            }, 409)
        try:
            r_dir.mkdir(parents=True, exist_ok=False)
            (r_dir / "run_manifest.json").write_text(
                json.dumps(manifest, indent=2, default=str), encoding="utf-8"
            )
        except OSError:
            logger.exception("Unable to create research run directory %s", run_id)
            return render(request, "partials/error.html", {
                "title": "Research run could not be prepared",
                "message": "The run directory could not be created. Check artifact-directory permissions and available disk space.",
            }, 500)
        initial_progress = RunProgress(
            run_id=run_id, suite=suite, total=len(items), completed=0, failed=0,
            started_utc=str(manifest.get("started_utc") or datetime.now(timezone.utc).isoformat(timespec="seconds")),
            status="running",
        )
        initial_progress.save(artifacts_dir)
        t = threading.Thread(
            target=_managed_run_thread,
            args=(run_id, target, target_args, artifacts_dir),
            name=f"qrshield-research-{run_id}",
            daemon=True,
        )
        _active_runs[run_id] = t
        try:
            t.start()
        except Exception:
            _active_runs.pop(run_id, None)
            initial_progress.status = "error"
            initial_progress.error_message = "Research worker failed to start."
            initial_progress.save(artifacts_dir)
            logger.exception("Unable to start research worker %s", run_id)
            return render(request, "partials/error.html", {
                "title": "Research worker could not start",
                "message": "The research worker could not be started. Check server resources and logs.",
            }, 500)

    return render(request, "partials/research_progress.html", {
        "run_id": run_id,
        "suite": suite,
        "total": len(items),
        "status": "running",
        "completed": 0,
        "failed": 0,
    })


@router.get("/research/progress/{run_id}", response_class=HTMLResponse)
async def research_progress(request: Request, run_id: str):
    if not RUN_ID_RE.fullmatch(run_id):
        return JSONResponse({"error": "invalid_run_id"}, 400)
    qs = qs_(request)
    progress = RunProgress.load(qs.settings.artifacts_dir, run_id)
    if progress is None:
        return render(request, "partials/error.html",
                      {"title": "Run not found", "message": f"No run found for ID '{run_id}'."})

    if progress.status in ("done", "error"):
        r_dir = run_dir(qs.settings.artifacts_dir, run_id)
        artifact_links = []
        for p in sorted(r_dir.rglob("*")):
            if p.is_file() and p.suffix in RUN_ARTIFACT_EXTENSIONS:
                rel = p.relative_to(r_dir)
                artifact_links.append({"name": str(rel), "url": f"/research/runs/{run_id}/{rel.as_posix()}"})
        return render(request, "partials/research_results.html", {
            "progress": progress,
            "artifact_links": artifact_links,
        })

    return render(request, "partials/research_progress.html", {
        "run_id": run_id,
        "suite": progress.suite,
        "total": progress.total,
        "status": progress.status,
        "completed": progress.completed,
        "failed": progress.failed,
        "remaining": progress.remaining,
        "current_item": progress.current_item,
    })


@router.get("/research/runs/{run_id}/{path:path}")
async def run_artifact(request: Request, run_id: str, path: str):
    if not RUN_ID_RE.fullmatch(run_id):
        return JSONResponse({"error": "invalid_run_id"}, 400)
    if not path or "\\" in path or "\x00" in path:
        return JSONResponse({"error": "not_found"}, 404)
    relative = Path(path)
    windows = PureWindowsPath(path)
    if relative.is_absolute() or windows.is_absolute() or windows.drive or any(part in ("..", ".") for part in relative.parts):
        return JSONResponse({"error": "not_found"}, 404)

    qs = qs_(request)
    try:
        runs_root = (qs.settings.artifacts_dir / "runs").resolve(strict=True)
        candidate_run = (runs_root / run_id).resolve(strict=True)
        candidate_run.relative_to(runs_root)
        if not candidate_run.is_dir():
            raise FileNotFoundError
        artifact_path = (candidate_run / relative).resolve(strict=True)
        artifact_path.relative_to(candidate_run)
    except (OSError, ValueError, RuntimeError):
        return JSONResponse({"error": "not_found"}, 404)

    if not artifact_path.is_file():
        return JSONResponse({"error": "not_found"}, 404)
    ext = artifact_path.suffix.lower()
    if ext not in RUN_ARTIFACT_EXTENSIONS:
        return JSONResponse({"error": "not_found"}, 404)
    media_types = {".json": "application/json", ".jsonl": "application/x-ndjson",
                   ".csv": "text/csv", ".html": "text/html"}
    return FileResponse(artifact_path, media_type=media_types.get(ext, "application/octet-stream"),
                        filename=artifact_path.name, headers={"X-Content-Type-Options": "nosniff"})
