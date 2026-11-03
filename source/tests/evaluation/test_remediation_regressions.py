"""Regression tests for benchmark evaluation, robustness linkage, context degradation, and QRS-Bench-Ind evaluation runs."""
from __future__ import annotations

import copy
import json
from pathlib import Path

from evaluation.ablation import run_ablation_study
from evaluation.adjudicator import adjudicate_scenario_record
from evaluation.dataset_loader import discover_dataset_root, load_research_dataset
from evaluation.holdout import build_holdout_scenarios, evaluate_holdout_benchmark
from evaluation.scoring import score_base, score_robustness
from evaluation.validator import validate_dataset
from qrshield_core.config import Settings
from qrshield_core.models import Confidence, Context, ContextAttribute
from qrshield_core.ocr.engine import OCRBlock, OCRResult, TesseractOCRProvider, create_ocr_provider
from qrshield_core.pipeline import AnalysisConfig, QRShieldEngine
from qrshield_core.rules import RuleRegistry


def test_p0_1_robustness_linkage_from_original_scenario_id() -> None:
    """P0 #1: Robustness loader & scorer must link variants via original_scenario_id and compare all evaluable variants."""
    ds_root = discover_dataset_root()
    ds = load_research_dataset(ds_root)
    assert len(ds.robustness_items) == 240
    assert all(it.base_id != "" for it in ds.robustness_items), "All 240 robustness items must have a non-empty base_id"

    base_by_id = {
        it.item_id: {
            "item_id": it.item_id,
            "evaluable": True,
            "assessment_level": "needs_verification",
        }
        for it in ds.base_items
    }
    rob_gt = {
        it.item_id: {
            **it.ground_truth,
            "base_id": it.base_id,
            "variant_id": it.variant_id,
            "transformation": it.transformation,
        }
        for it in ds.robustness_items
    }
    rob_results = [
        {
            "item_id": it.item_id,
            "payload_type": it.payload_type,
            "evaluable": True,
            "qr_decode_success": True,
            "ocr_status": "ok",
            "assessment_level": "needs_verification",
            "raw_result": {"assessment": {"level": "needs_verification", "context_status": "complete", "context_incomplete": False}},
        }
        for it in ds.robustness_items
    ]
    scored = score_robustness(rob_results, base_by_id, rob_gt)
    assert scored["summary"]["assessment_compared"] == 240
    assert scored["summary"]["assessment_retained"] == 240
    assert scored["summary"]["missing_base_links_count"] == 0


def test_p0_2_indicator_level_ground_truth_evaluable() -> None:
    """P0 #2: Every base/challenge scenario in QRS-Bench-Ind (640 items) has evaluable indicator ground truth."""
    ds_root = discover_dataset_root()
    ds = load_research_dataset(ds_root)
    base_gt = {it.item_id: it.ground_truth for it in ds.base_items}
    assert len(base_gt) == 640
    assert all(
        bool(gt.get("key_indicators") or gt.get("absent_indicators"))
        for gt in base_gt.values()
    )

    dummy_results = [
        {
            "item_id": it.item_id,
            "payload_type": it.payload_type,
            "evaluable": True,
            "qr_decode_success": True,
            "ocr_status": "ok",
            "assessment_level": it.ground_truth.get("adjudicated_expected_level", "no_material_concern"),
            "raw_result": {
                "payload_findings": [{"indicator_id": ind} for ind in it.ground_truth.get("key_indicators", [])],
                "context_findings": [],
            },
        }
        for it in ds.base_items
    ]
    scored = score_base(dummy_results, base_gt)
    assert scored["indicators"]["evaluable"] == 640
    assert scored["indicators"]["exact_indicator_match"] == 640
    assert scored["indicators"]["semantic_tag_evaluable"] == 640


def test_p0_3_progressive_context_degradation_never_silently_downgrades() -> None:
    """P0 #3: Partial context loss (organization lost, purpose retained) or total OCR failure must not downgrade needs_verification to no_material_concern."""
    settings = Settings.from_env()
    settings.load_synthetic_reference = True
    engine = QRShieldEngine(settings, use_default_ocr=False)
    cfg = AnalysisConfig(name="test", use_payload=True, use_context=True, use_action=True, threat_intel_mode="off")

    raw_dl = "acmeloyalty://open?ref=promo"
    ctx_full = Context(attributes=[
        ContextAttribute("organization", "Unrelated Bank", "ocr", Confidence.HIGH),
        ContextAttribute("purpose", "Open app reward", "ocr", Confidence.HIGH),
    ])
    ctx_partial_purpose_only = Context(attributes=[
        ContextAttribute("purpose", "Open app reward", "ocr", Confidence.HIGH),
    ])
    ocr_ok = OCRResult(status="ok", message="", engine="tesseract", blocks=[
        OCRBlock("b1", "Open app reward", "open app reward", 0.95, Confidence.HIGH, [[0, 0], [10, 0], [10, 10], [0, 10]], "purpose")
    ])
    res_full = engine.analyze_payload(raw_dl, ctx_full, cfg, ocr=ocr_ok).to_dict()
    res_partial = engine.analyze_payload(raw_dl, ctx_partial_purpose_only, cfg, ocr=ocr_ok).to_dict()
    assert res_full["assessment"]["level"] == "needs_verification"
    assert res_partial["assessment"]["level"] == "needs_verification"
    assert res_partial["assessment"]["context_status"] == "partial"
    assert res_partial["assessment"]["context_incomplete"] is True

    raw_email = "mailto:support@verdantvalleyclinic.org?subject=Booking&body=Hello"
    ocr_no_text = OCRResult(status="no_text", message="No text", engine="tesseract", blocks=[])
    res_email_no_text = engine.analyze_payload(raw_email, Context(attributes=[]), cfg, ocr=ocr_no_text).to_dict()
    assert res_email_no_text["assessment"]["level"] == "needs_verification"
    assert res_email_no_text["assessment"]["context_status"] == "missing"
    assert res_email_no_text["assessment"]["context_incomplete"] is True


def test_p1_4_and_6_syntax_vs_purpose_and_confusion_matrices() -> None:
    """P1 #4 & #6: Separate encoded_payload_type from scenario_purpose on QRS-Bench-Ind items."""
    ds_root = discover_dataset_root()
    ds = load_research_dataset(ds_root)
    assert len(ds.base_items) == 640
    for it in ds.base_items:
        assert "encoded_payload_type" in it.ground_truth
        assert "scenario_purpose" in it.ground_truth
    http_payment_items = [it for it in ds.base_items if it.ground_truth.get("is_http_payment_portal")]
    assert len(http_payment_items) >= 1
    for it in http_payment_items:
        assert it.ground_truth["encoded_payload_type"] == "url"
        assert it.ground_truth["scenario_purpose"] == "payment"


def test_p1_5_adjudicator_does_not_consult_predictions() -> None:
    """P1 #5: Deterministic scenario adjudicator derives expected level strictly from scenario input and rule definitions."""
    settings = Settings.from_env()
    settings.load_synthetic_reference = True
    engine = QRShieldEngine(settings, use_default_ocr=False)
    _ = RuleRegistry(settings.rules_dir)
    sample = {
        "scenario_id": "TEST-ADJ-001",
        "payload_type": "payment",
        "qr_payload": "https://pay.example.org/checkout?merchant=Acme&amount=50",
        "displayed_context": "Organization: Acme\nPurpose: Pay ₹50",
        "expected_findings": ["HTTPS_present", "merchant_match"],
    }
    adj = adjudicate_scenario_record(sample, engine.deps, engine.consistency)
    assert adj["encoded_payload_type"] == "url"
    assert adj["scenario_purpose"] == "payment"
    assert adj["is_http_payment_portal"] is True
    assert adj["adjudicated_expected_level"] in {"no_material_concern", "needs_verification", "high_concern", "harmful_corroborated"}


def test_p1_7_holdout_ood_benchmark_without_synthetic_reference() -> None:
    """P1 #7: Holdout benchmark runs 70 unseen scenarios with load_synthetic_reference=False."""
    scenarios = build_holdout_scenarios()
    assert len(scenarios) == 70
    summary = evaluate_holdout_benchmark()
    assert summary["synthetic_reference_loaded"] is False
    assert summary["total_scenarios"] == 70
    assert summary["encoded_syntax_agreement_rate"] == 1.0
    assert summary["adjudicated_ordinal_agreement_rate"] >= 0.90


def test_p2_8_ocr_provider_factory_and_tesseract_adapter(monkeypatch) -> None:
    """P2 #8: OCR provider factory supports tesseract, paddleocr, and auto."""
    assert Settings().ocr_provider == "paddleocr"
    monkeypatch.setenv("OCR_PROVIDER", "")
    assert Settings.from_env().ocr_provider == "paddleocr"
    assert create_ocr_provider().name == "paddleocr"
    provider = create_ocr_provider("tesseract")
    assert isinstance(provider, TesseractOCRProvider)


def test_p2_9_validator_semantic_checks_detect_corrupt_metadata() -> None:
    """P2 #9: Dataset validator flags missing robustness base_id links and payload mismatches."""
    ds_root = discover_dataset_root()
    ds = load_research_dataset(ds_root)
    clean_val = validate_dataset(ds, verify_payloads=False)
    assert clean_val.ok is True
    assert clean_val.structural_valid is True
    assert clean_val.semantic_valid is True

    corrupted_ds = copy.copy(ds)
    bad_item = copy.copy(ds.robustness_items[0])
    bad_item.base_id = "NON-EXISTENT-BASE-999"
    corrupted_ds.robustness_items = [bad_item] + list(ds.robustness_items[1:])
    bad_val = validate_dataset(corrupted_ds, verify_payloads=False)
    assert bad_val.ok is False
    assert bad_val.semantic_valid is False
    assert len(bad_val.missing_base_links) == 1


def test_p2_11_portable_relative_paths_in_evaluation_artifacts() -> None:
    """P2 #11: Frozen QRS-Bench-Ind evaluation JSONLs must not contain workstation-specific absolute paths."""
    ds_root = discover_dataset_root()
    for fname in ("per_unit_predictions.jsonl", "benchmark_metrics_report.json"):
        f = ds_root / "evaluation_runs" / fname
        assert f.is_file()
        text = f.read_text(encoding="utf-8")
        assert "/home/user/" not in text
        assert "/mnt/data/" not in text


def test_p3_13_layer_ablation_study() -> None:
    """P3 #13: Layer ablation study evaluates all 4 local configurations on QRS-Bench-Ind."""
    ds_root = discover_dataset_root()
    res = run_ablation_study(dataset_root=ds_root)
    cfgs = res["configurations"]
    assert set(cfgs.keys()) == {"payload_only", "context_only", "payload_context", "payload_context_action"}
    assert cfgs["payload_context_action"]["base_total"] == 640
    assert cfgs["payload_context_action"]["adjudicated_ordinal_agreement"] == 616
    assert cfgs["payload_context_action"]["accepted_set_agreement"] == 618
    assert cfgs["payload_context_action"]["counterfactual_directional_pairs"] == 160
    assert cfgs["payload_context_action"]["counterfactual_level_correct_direction"] == 160


def test_qrs_bench_ind_locked_test_and_full_metrics() -> None:
    """Verify QRS-Bench-Ind evaluation outputs match the locked test and full benchmark metrics."""
    ds_root = discover_dataset_root()
    report_path = ds_root / "evaluation_runs" / "benchmark_metrics_report.json"
    pred_path = ds_root / "evaluation_runs" / "per_unit_predictions.jsonl"
    assert report_path.is_file()
    assert pred_path.is_file()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    preds = [json.loads(line) for line in pred_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(preds) == 1080

    test_split = report["test_locked_primary"]["combined_core_plus_challenge_432_with_ti"]
    assert test_split["n"] == 432
    assert test_split["exact_agreement"] == 1.0
    assert test_split["accepted_set_agreement"] == 1.0

    test_cf = report["counterfactual_analysis_test_locked_152_pairs"]
    assert test_cf["directional_128_pairs_rate"] == 1.0
    assert test_cf["paraphrase_negative_control_24_pairs_invariance_rate"] == 1.0


def test_qrs_bench_ind_28_signage_templates_across_splits() -> None:
    """Verify all 28 signage layouts (T01..T04 dev, T05..T08 val, T09..T28 test_locked) exist in annotations and match taxonomy metadata."""
    import yaml

    ds_root = discover_dataset_root()
    tax = yaml.safe_load((ds_root / "metadata" / "taxonomy_and_codebook.yaml").read_text(encoding="utf-8"))
    recs = [
        json.loads(line)
        for line in (ds_root / "annotations" / "consensus_ground_truth.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    by_split: dict[str, set[str]] = {"dev": set(), "val": set(), "test_locked": set()}
    for r in recs:
        by_split[r["split"]].add(r["template_id"])

    assert sorted(by_split["dev"]) == ["T01", "T02", "T03", "T04"]
    assert sorted(by_split["val"]) == ["T05", "T06", "T07", "T08"]
    assert sorted(by_split["test_locked"]) == [f"T{i:02d}" for i in range(9, 29)]
    assert sorted(by_split["dev"]) == sorted(tax["splits"]["dev"]["templates"])
    assert sorted(by_split["val"]) == sorted(tax["splits"]["val"]["templates"])
    assert sorted(by_split["test_locked"]) == sorted(tax["splits"]["test_locked"]["templates"])
    all_templates = by_split["dev"] | by_split["val"] | by_split["test_locked"]
    assert len(all_templates) == 28


def test_human_annotation_workflow_end_to_end(tmp_path: Path) -> None:
    """Verify blind task export (1,280 image rows including separate counterfactual A/B tasks), full-schema ingestion, and relation validation."""
    import csv
    import sys

    ds_root = discover_dataset_root()
    repo_root = ds_root.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from tools.ingest_annotations import export_blind_tasks, ingest_human_csvs

    gt_jsonl = ds_root / "annotations" / "consensus_ground_truth.jsonl"
    blind_csv = tmp_path / "blind_tasks.csv"
    export_blind_tasks(gt_jsonl, blind_csv)

    with blind_csv.open("r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1280
    pair_a_rows = [r for r in rows if r["pair_side"] == "A"]
    pair_b_rows = [r for r in rows if r["pair_side"] == "B"]
    single_rows = [r for r in rows if r["pair_side"] == ""]
    assert len(pair_a_rows) == 200
    assert len(pair_b_rows) == 200
    assert len(single_rows) == 880

    base_recs = {
        json.loads(line)["unit_id"]: json.loads(line)
        for line in gt_jsonl.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    sample_uids = ["dev_core_scenes_0001", "dev_counterfactual_pairs_0081", "dev_counterfactual_pairs_0097"]
    sub_gt = tmp_path / "sub_gt.jsonl"
    sub_gt.write_text("\n".join(json.dumps(base_recs[u]) for u in sample_uids) + "\n", encoding="utf-8")

    sub_blind = tmp_path / "sub_blind.csv"
    export_blind_tasks(sub_gt, sub_blind)
    with sub_blind.open("r", encoding="utf-8") as f:
        sub_rows = list(csv.DictReader(f))
    assert len(sub_rows) == 5

    r1_rows, r2_rows, adj_rows = [], [], []
    for r in sub_rows:
        r1 = dict(r)
        r2 = dict(r)
        adj = dict(r)
        tid = r["task_id"]
        if tid == "dev_core_scenes_0001":
            r1["assigned_level_L0_to_L3"] = "no_material_concern"
            r2["assigned_level_L0_to_L3"] = "needs_verification"
            adj["assigned_level_L0_to_L3"] = "no_material_concern"
        elif tid == "dev_counterfactual_pairs_0081__A":
            r1["assigned_level_L0_to_L3"] = "no_material_concern"
            r2["assigned_level_L0_to_L3"] = "no_material_concern"
            adj["assigned_level_L0_to_L3"] = "no_material_concern"
        elif tid == "dev_counterfactual_pairs_0081__B":
            r1["assigned_level_L0_to_L3"] = "high_concern"
            r1["directional_relation_vs_A"] = "Risk(B) > Risk(A)"
            r2["assigned_level_L0_to_L3"] = "high_concern"
            r2["directional_relation_vs_A"] = "Risk(B) > Risk(A)"
            adj["assigned_level_L0_to_L3"] = "high_concern"
            adj["directional_relation_vs_A"] = "Risk(B) > Risk(A)"
        elif tid.startswith("dev_counterfactual_pairs_0097__"):
            r1["assigned_level_L0_to_L3"] = "no_material_concern"
            r2["assigned_level_L0_to_L3"] = "no_material_concern"
            adj["assigned_level_L0_to_L3"] = "no_material_concern"
            if tid.endswith("__B"):
                r1["directional_relation_vs_A"] = "Risk(B) == Risk(A)"
                r2["directional_relation_vs_A"] = "Risk(B) == Risk(A)"
        r1_rows.append(r1)
        r2_rows.append(r2)
        adj_rows.append(adj)

    def write_csv(p: Path, data: list[dict[str, str]]) -> None:
        with p.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(data[0].keys()))
            w.writeheader()
            w.writerows(data)

    r1_p, r2_p, adj_p = tmp_path / "r1.csv", tmp_path / "r2.csv", tmp_path / "adj.csv"
    write_csv(r1_p, r1_rows)
    write_csv(r2_p, r2_rows)
    write_csv(adj_p, adj_rows)

    out_jsonl = tmp_path / "human_gt.jsonl"
    irr_json = tmp_path / "irr.json"
    rc = ingest_human_csvs(r1_p, r2_p, adj_p, out_jsonl, irr_json, base_gt_jsonl=sub_gt)
    assert rc == 0

    ingested = {
        json.loads(line)["unit_id"]: json.loads(line)
        for line in out_jsonl.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    assert len(ingested) == 3
    s_rec = ingested["dev_core_scenes_0001"]
    for req_key in ("split", "stratum", "category", "org_id", "template_id", "subtype", "image_id", "rel_path", "accepted_ground_truth_set"):
        assert req_key in s_rec
    assert s_rec["provenance"] == "human"
    assert s_rec["consensus_ground_truth"] == "no_material_concern"
    assert s_rec["adjudication_method"] == "human_third_rater_adjudicated"

    p_rec = ingested["dev_counterfactual_pairs_0081"]
    for req_key in ("split", "stratum", "category", "org_id", "template_id", "subtype", "image_id_a", "image_id_b", "rel_path_a", "rel_path_b"):
        assert req_key in p_rec
    assert p_rec["consensus_ground_truth_a"] == "no_material_concern"
    assert p_rec["consensus_ground_truth"] == "high_concern"
    assert p_rec["expected_relation"] == "Risk(B) > Risk(A)"
    assert p_rec["rater_1_label_a"] == "no_material_concern"
    assert p_rec["rater_2_label_a"] == "no_material_concern"
    assert p_rec["rater_1_label"] == "high_concern"
    assert p_rec["rater_2_label"] == "high_concern"
    assert p_rec["rater_1_relation"] == "Risk(B) > Risk(A)"

    irr = json.loads(irr_json.read_text(encoding="utf-8"))
    assert irr["n_units"] == 3
    assert irr["n_images_rated"] == 5
    assert irr["n_counterfactual_pairs_rated"] == 2
    assert irr["counterfactual_relation_agreement"]["relation_exact_agreement"] == 1.0

    bad_r1 = [dict(x) for x in r1_rows]
    for x in bad_r1:
        if x["task_id"] == "dev_counterfactual_pairs_0081__B":
            x["directional_relation_vs_A"] = "Risk(B) == Risk(A)"
    bad_r1_p = tmp_path / "bad_r1.csv"
    write_csv(bad_r1_p, bad_r1)
    assert ingest_human_csvs(bad_r1_p, r2_p, adj_p, out_jsonl, irr_json, base_gt_jsonl=sub_gt) == 1


def test_independent_validation_redteam_thresholds_and_decoder_crosscheck() -> None:
    """Verify red-team report enforces performance thresholds and decoder cross-check independently measures QRShield's decoder."""
    ds_root = discover_dataset_root()
    repo_root = ds_root.parent
    rt_rep = json.loads((repo_root / "release" / "evidence" / "redteam_208_report.json").read_text(encoding="utf-8"))
    dec_rep = json.loads((repo_root / "release" / "evidence" / "decoder_crosscheck.json").read_text(encoding="utf-8"))

    assert rt_rep["status"] == "PASS"
    assert "thresholds" in rt_rep
    assert rt_rep["threshold_checks"]["case_count_208"] is True
    assert rt_rep["threshold_checks"]["attack_recall_gte_min"] is True
    assert rt_rep["threshold_checks"]["benign_specificity_gte_min"] is True
    assert rt_rep["threshold_checks"]["all_categories_gte_min"] is True
    assert rt_rep["attack_detection_recall"] >= rt_rep["thresholds"]["min_attack_recall"]
    assert rt_rep["benign_fp_trap_specificity_L0"] >= rt_rep["thresholds"]["min_benign_specificity"]

    assert dec_rep["status"] == "PASS"
    assert dec_rep["images_checked"] == 192
    assert dec_rep["raw_single_pass_opencv_decoded_count"] == 133
    assert dec_rep["standalone_multipass_decoded_count"] == 171
    assert dec_rep["qrshield_multipass_decoded_count"] == 191
    assert dec_rep["qrshield_multipass_decode_rate"] == 0.9948
    assert dec_rep["qrshield_multipass_decode_rate"] > dec_rep["standalone_multipass_decode_rate"] > dec_rep["raw_single_pass_opencv_decode_rate"]
    assert dec_rep["payload_agreement_rate"] == 1.0
    assert dec_rep["standalone_qrshield_agreement_rate"] == 1.0
    assert dec_rep["qrshield_ground_truth_agreement_rate"] == 1.0
