"""Unit tests for research run persistence, resume, and report generation."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from evaluation.failures import FailureCode
from evaluation.image_runner import ItemResult
from evaluation.report_html import (
    generate_base_html,
    generate_counterfactual_html,
    generate_overall_html,
    generate_robustness_html,
    write_html_report,
)
from evaluation.reporting import write_overall_summary, write_suite_artifacts
from evaluation.run_manager import (
    RunProgress,
    append_result,
    load_completed_ids,
    load_results_jsonl,
    make_run_id,
    results_jsonl_path,
    run_dir,
    suite_dir,
)


def test_make_run_id():
    rid = make_run_id("base")
    assert "-base-" in rid
    assert len(rid) > 20


def test_append_and_load_results_jsonl(tmp_path):
    s_dir = tmp_path / "run1" / "base"
    s_dir.mkdir(parents=True, exist_ok=True)
    j_path = s_dir / "results.jsonl"

    res1 = ItemResult(
        item_id="item_01",
        suite="base",
        image_path="path/1.png",
        image_hash="abc1",
        failure_code=FailureCode.SUCCESS,
        payload_type="url",
    )
    res2 = ItemResult(
        item_id="item_02",
        suite="base",
        image_path="path/2.png",
        image_hash="abc2",
        failure_code=FailureCode.QR_DETECT_ERROR,
    )

    append_result(j_path, res1)
    append_result(j_path, res2)

    loaded = load_results_jsonl(j_path)
    assert len(loaded) == 2
    assert loaded[0]["item_id"] == "item_01"
    assert loaded[1]["item_id"] == "item_02"

    completed = load_completed_ids(j_path)
    assert completed == {"item_01", "item_02"}


def test_run_progress_lifecycle(tmp_path):
    prog = RunProgress(
        run_id="run_123",
        suite="base",
        total=10,
        completed=4,
        failed=1,
        started_utc="2026-10-12T12:00:00Z",
        status="running",
    )
    prog.save(tmp_path)

    loaded = RunProgress.load(tmp_path, "run_123")
    assert loaded is not None
    assert loaded.total == 10
    assert loaded.completed == 4
    assert loaded.remaining == 6
    assert loaded.status == "running"


def test_suite_artifacts_and_html(tmp_path):
    s_dir = tmp_path / "base"
    s_dir.mkdir()
    records = [
        {"item_id": "BASE_01", "suite": "base", "evaluable": True, "payload_type": "url", "assessment_level": "high_concern"},
        {"item_id": "BASE_02", "suite": "base", "evaluable": False, "failure_code": "QR_DETECT_ERROR"},
    ]
    metrics = {
        "suite": "base",
        "pipeline": {"images_total": 2, "images_evaluable": 1, "images_failed": 1},
        "payload_type": {"agreement_rate": 1.0},
        "assessment": {"agreement_rate": 1.0},
    }

    manifest = {"run_id": "test_run", "dataset_root": "test_root"}
    write_suite_artifacts(s_dir, manifest, records, metrics)
    assert (s_dir / "results.csv").is_file()
    assert (s_dir / "summary.json").is_file()

    # Generate HTML
    html_content = generate_base_html(manifest, records, metrics)
    assert "<!doctype html>" in html_content.lower()
    assert "Base Test" in html_content
    # Offline check: no CDN link
    assert "cdn." not in html_content
    assert "http://" not in html_content.replace("http://www.w3.org", "")

    write_html_report(s_dir / "report.html", html_content)
    assert (s_dir / "report.html").is_file()
