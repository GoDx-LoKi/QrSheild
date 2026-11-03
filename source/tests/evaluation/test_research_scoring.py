"""Unit tests for research scoring functions (Base, Counterfactual, Robustness)."""
from __future__ import annotations

import pytest
from evaluation.failures import FailureCode, is_evaluable
from evaluation.scoring import score_base, score_counterfactual, score_robustness


def test_failure_taxonomy_and_evaluability():
    assert is_evaluable(FailureCode.SUCCESS) is True
    assert is_evaluable(FailureCode.QR_DETECT_ERROR) is False
    assert is_evaluable(FailureCode.IMAGE_LOAD_ERROR) is False
    assert is_evaluable(FailureCode.SECURITY_ANALYSIS_ERROR) is False


def test_score_base_agreement():
    # 2 evaluable items, 1 failed
    results = [
        {
            "item_id": "BASE_001",
            "evaluable": True,
            "qr_decode_success": True,
            "ocr_status": "ok",
            "context_accepted_count": 2,
            "payload_type": "url",
            "assessment_level": "high_concern",
            "raw_result": {
                "payload_findings": [{"indicator_id": "URL-001"}],
                "context_findings": [],
                "action_findings": [],
            },
        },
        {
            "item_id": "BASE_002",
            "evaluable": True,
            "qr_decode_success": True,
            "ocr_status": "ok",
            "context_accepted_count": 1,
            "payload_type": "wifi",
            "assessment_level": "no_material_concern",
            "raw_result": {
                "payload_findings": [],
                "context_findings": [],
                "action_findings": [],
            },
        },
        {
            "item_id": "BASE_003",
            "evaluable": False,
            "failure_code": "QR_DETECT_ERROR",
            "qr_decode_success": False,
        },
    ]

    gt_by_id = {
        "BASE_001": {
            "payload_type": "url",
            "expected_assessment": "high_concern",
            "key_indicators": ["URL-001"],
        },
        "BASE_002": {
            "payload_type": "wifi",
            "expected_assessment": "needs_verification",  # disagree
        },
    }

    metrics = score_base(results, gt_by_id)
    assert metrics["pipeline"]["images_total"] == 3
    assert metrics["pipeline"]["images_evaluable"] == 2
    assert metrics["pipeline"]["images_failed"] == 1
    assert metrics["pipeline"]["qr_decode_success"] == 2

    # Payload agreement: 2 out of 2 = 1.0
    assert metrics["payload_type"]["agreement_rate"] == 1.0

    # Assessment agreement: 1 out of 2 = 0.5
    assert metrics["assessment"]["agreement"] == 1
    assert metrics["assessment"]["agreement_rate"] == 0.5

    # Failures breakdown
    assert metrics["failures"]["total"] == 1
    assert metrics["failures"]["by_code"]["QR_DETECT_ERROR"] == 1


def test_score_counterfactual():
    # Pair CF_01: image A is needs_verification, image B is high_concern
    results = [
        {
            "item_id": "CF_01_a",
            "evaluable": True,
            "assessment_level": "needs_verification",
        },
        {
            "item_id": "CF_01_b",
            "evaluable": True,
            "assessment_level": "high_concern",
        },
    ]

    pairs = [
        {"pair_id": "CF_01", "image_a": "a.png", "image_b": "b.png"}
    ]

    gt_by_pair = {
        "CF_01": {
            "expected_direction": "b_more_concerning",
            "type": "url",
        }
    }

    metrics = score_counterfactual(results, pairs, gt_by_pair)
    assert metrics["summary"]["total_pairs"] == 1
    assert metrics["summary"]["evaluable_pairs"] == 1
    assert metrics["summary"]["correct_direction"] == 1
    assert len(metrics["pairs"]) == 1


def test_score_counterfactual_negative_controls():
    results = [
        {"item_id": "NC_01_a", "evaluable": True, "assessment_level": "needs_verification", "raw_result": {"context_findings": [{"indicator_id": "identity_equivalence"}]}},
        {"item_id": "NC_01_b", "evaluable": True, "assessment_level": "needs_verification", "raw_result": {"context_findings": [{"indicator_id": "identity_equivalence"}]}},
        {"item_id": "NC_02_a", "evaluable": True, "assessment_level": "needs_verification", "raw_result": {}},
        {"item_id": "NC_02_b", "evaluable": True, "assessment_level": "high_concern", "raw_result": {}},
    ]
    controls = [
        {"pair_id": "NC_01", "payload_type": "payment", "image_a": "a", "image_b": "b", "expected_direction": "no_change"},
        {"pair_id": "NC_02", "payload_type": "url", "image_a": "a", "image_b": "b", "expected_direction": "no_change"},
    ]
    metrics = score_counterfactual(results, [], {}, negative_controls=controls)
    nc = metrics["negative_controls"]
    assert nc["total_pairs"] == 2
    assert nc["evaluable_pairs"] == 2
    assert nc["assessment_stable"] == 1
    assert nc["assessment_changed"] == 1
    assert nc["assessment_stability_rate"] == 0.5
    assert nc["finding_stable"] == 1


def test_score_robustness():
    # Base item BASE_01, variant ROB_01
    results = [
        {
            "item_id": "ROB_01",
            "evaluable": True,
            "assessment_level": "high_concern",
            "payload_type": "url",
            "qr_decode_success": True,
            "ocr_status": "ok",
        }
    ]

    base_results = {
        "BASE_01": {
            "evaluable": True,
            "assessment_level": "high_concern",
            "payload_type": "url",
            "qr_decode_success": True,
            "ocr_status": "ok",
        }
    }

    gt = {
        "ROB_01": {
            "base_id": "BASE_01",
            "variant_id": "blur",
            "type": "url",
        }
    }

    metrics = score_robustness(results, base_results, gt)
    assert metrics["summary"]["total_variants"] == 1
    assert metrics["summary"]["evaluable"] == 1
    assert metrics["summary"]["assessment_retained"] == 1
    assert metrics["summary"]["assessment_retention_rate"] == 1.0
    assert len(metrics["items"]) == 1
