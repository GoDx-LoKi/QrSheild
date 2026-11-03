"""Research evaluation scorers.

Scorers receive FROZEN predictions + ground truth separately.
Ground truth is NEVER mixed into inference — only used AFTER predictions are frozen.

All scorers return plain dicts of counts/rates; no invented numerical risk scores.
"""
from __future__ import annotations

import math
import random
import re
from collections import Counter, defaultdict
from typing import Any

from qrshield_core.models import LEVEL_ORDER, AssessmentLevel

from .adjudicator import SEMANTIC_TAG_TO_INDICATORS
from .failures import FailureCode

ALL_LEVELS = ("no_material_concern", "needs_verification", "high_concern", "harmful_corroborated")
ALL_GT_CATEGORIES = (
    "benign",
    "benign_with_identity_verification",
    "context_mismatch_requires_verification",
    "payload_risk_signal",
    "multi_indicator_risk_signal",
)


# Qualitative assessment level ordering for ordinal comparison
def _level_order(level: str | None) -> int:
    if level is None:
        return -1
    try:
        return LEVEL_ORDER[AssessmentLevel(level)]
    except (ValueError, KeyError):
        return -1


def _direction(level_a: str | None, level_b: str | None) -> str:
    """Directional comparison between two assessment levels."""
    oa, ob = _level_order(level_a), _level_order(level_b)
    if oa < 0 or ob < 0:
        return "not_evaluable"
    if ob > oa:
        return "b_more_concerning"
    if ob < oa:
        return "b_less_concerning"
    return "indistinguishable"


# Mapping from ScenarioForge research dataset ground truth labels to QRShield AssessmentLevels
# Explicitly framed as permissive multi-level accepted sets (P1 #6).
_GT_ASSESSMENT_MAP: dict[str, set[str]] = {
    "benign": {"no_material_concern", "needs_verification"},
    "benign_with_identity_verification": {"needs_verification"},
    "context_mismatch_requires_verification": {"needs_verification", "high_concern"},
    "payload_risk_signal": {"needs_verification", "high_concern"},
    "multi_indicator_risk_signal": {"high_concern", "harmful_corroborated"},
    "insufficient_context": {"needs_verification", "no_material_concern"},
    # Direct matches
    "no_material_concern": {"no_material_concern"},
    "needs_verification": {"needs_verification"},
    "high_concern": {"high_concern"},
    "harmful_corroborated": {"harmful_corroborated"},
}

# Primary 1-to-1 canonical ordinal mapping for ScenarioForge categories when adjudicated_expected_level is absent
_PRIMARY_CATEGORY_LEVEL: dict[str, str] = {
    "benign": "no_material_concern",
    "benign_with_identity_verification": "needs_verification",
    "context_mismatch_requires_verification": "needs_verification",
    "payload_risk_signal": "needs_verification",
    "multi_indicator_risk_signal": "high_concern",
    "insufficient_context": "needs_verification",
    "no_material_concern": "no_material_concern",
    "needs_verification": "needs_verification",
    "high_concern": "high_concern",
    "harmful_corroborated": "harmful_corroborated",
}


def _matches_expected_assessment(predicted_level: str | None, expected_raw: Any) -> bool:
    if not predicted_level or not expected_raw:
        return False
    candidates = [expected_raw] if isinstance(expected_raw, str) else list(expected_raw)
    for c in candidates:
        c_str = str(c).strip().lower()
        if predicted_level == c_str:
            return True
        allowed = _GT_ASSESSMENT_MAP.get(c_str, set())
        if predicted_level in allowed:
            return True
    return False


def _infer_encoded_payload_type(gt: dict[str, Any], fallback: str | None) -> str | None:
    explicit = gt.get("encoded_payload_type")
    if explicit:
        return str(explicit).strip().lower()
    raw_qr = str(gt.get("qr_payload") or "").strip()
    if raw_qr:
        low = raw_qr.lower()
        if low.startswith(("http://", "https://")):
            return "url"
        if low.startswith("upi://"):
            return "payment"
        if low.startswith("wifi:"):
            return "wifi"
        if low.startswith(("begin:vcard", "mecard:")):
            return "contact"
        if low.startswith(("smsto:", "sms:")):
            return "sms"
        if low.startswith(("mailto:", "matmsg:")):
            return "email"
        if "://" in low:
            return "deep_link"
    return str(fallback).strip().lower() if fallback else None


def _normalize_payload_template(raw_payload: str) -> str:
    """Collapse concrete IDs/numbers/tokens in a QR payload to measure structural template diversity (P2 #12)."""
    if not raw_payload:
        return ""
    s = re.sub(r"\b\d+\b", "<NUM>", raw_payload)
    s = re.sub(r"(?<==)[^;&?\s]+", "<VAL>", s)
    return s


def _wilson_ci(successes: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    """95% Wilson score confidence interval for a binomial proportion."""
    if total <= 0:
        return None
    p = successes / total
    denom = 1.0 + (z * z) / total
    center = (p + (z * z) / (2.0 * total)) / denom
    half = (z * math.sqrt((p * (1.0 - p) + (z * z) / (4.0 * total)) / total)) / denom
    return [round(max(0.0, center - half), 4), round(min(1.0, center + half), 4)]


def _cluster_bootstrap_ci(
    clusters: dict[str, list[int]],
    n_boot: int = 1000,
    seed: int = 20261028,
) -> list[float] | None:
    """Cluster-robust percentile bootstrap 95% CI resampling unique payload clusters (P2 #12)."""
    keys = sorted(clusters.keys())
    if not keys:
        return None
    if len(keys) == 1:
        vals = clusters[keys[0]]
        rate = round(sum(vals) / len(vals), 4) if vals else 0.0
        return [rate, rate]
    rng = random.Random(seed)
    k = len(keys)
    cluster_sums = [sum(clusters[c]) for c in keys]
    cluster_lens = [len(clusters[c]) for c in keys]
    rates: list[float] = []
    for _ in range(n_boot):
        num = 0
        den = 0
        for _ in range(k):
            idx = rng.randrange(k)
            num += cluster_sums[idx]
            den += cluster_lens[idx]
        if den > 0:
            rates.append(num / den)
    if not rates:
        return None
    rates.sort()
    lo = rates[max(0, int(0.025 * len(rates)))]
    hi = rates[min(len(rates) - 1, int(0.975 * len(rates)))]
    return [round(lo, 4), round(hi, 4)]


def _binary_metrics(tp: int, fp: int, tn: int, fn: int) -> dict[str, Any]:
    prec = round(tp / (tp + fp), 4) if (tp + fp) > 0 else None
    rec = round(tp / (tp + fn), 4) if (tp + fn) > 0 else None
    spec = round(tn / (tn + fp), 4) if (tn + fp) > 0 else None
    f1 = round(2 * tp / (2 * tp + fp + fn), 4) if (2 * tp + fp + fn) > 0 else None
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": prec,
        "recall": rec,
        "specificity": spec,
        "f1": f1,
    }


# --------------------------------------------------------------------------- Base
def score_base(
    results: list[dict[str, Any]],
    ground_truth_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Compute base suite metrics from frozen predictions + ground truth."""
    total = len(results)
    evaluable = [r for r in results if r.get("evaluable")]
    failures = [r for r in results if not r.get("evaluable")]

    # Pipeline stage counts
    qr_decoded = sum(1 for r in results if r.get("qr_decode_success"))
    ocr_ok = sum(1 for r in results if r.get("ocr_status") == "ok")
    context_available = sum(1 for r in results if (r.get("context_accepted_count") or 0) > 0)
    analysis_complete = len(evaluable)

    # Context completeness / abstention tracking (P0 #3)
    context_status_dist: Counter = Counter()
    context_incomplete_count = 0

    # Payload type classification (both scenario_purpose and encoded_payload_type, P1 #4)
    pt_predicted: Counter = Counter(r.get("payload_type") for r in evaluable)
    pt_expected: Counter = Counter()
    pt_encoded_expected: Counter = Counter()
    pt_agreement = 0
    pt_encoded_agreement = 0
    pt_purpose_aware_agreement = 0
    http_payment_portal_count = 0
    purpose_confusion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    encoded_confusion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    # Assessment agreement (both permissive accepted-set and strict adjudicated ordinal, P1 #6)
    assessment_agreement = 0
    legacy_unadjudicated_agreement = 0
    adjudicated_agreement = 0
    n_adjudicated_eval = 0
    assessment_by_type: dict[str, dict] = defaultdict(
        lambda: {
            "total": 0,
            "agreement": 0,
            "accepted_set_agreement": 0,
            "legacy_unadjudicated_accepted_set_agreement": 0,
            "adjudicated_ordinal_agreement": 0,
        }
    )
    level_distribution: Counter = Counter()
    expected_level_distribution: Counter = Counter()
    raw_expected_level_distribution: Counter = Counter()
    adjudicated_expected_distribution: Counter = Counter()

    category_vs_predicted: dict[str, dict[str, int]] = {
        cat: {lvl: 0 for lvl in ALL_LEVELS} for cat in ALL_GT_CATEGORIES
    }
    raw_category_vs_predicted: dict[str, dict[str, int]] = {
        cat: {lvl: 0 for lvl in ALL_LEVELS} for cat in ALL_GT_CATEGORIES
    }
    adjudicated_confusion: dict[str, dict[str, int]] = {
        lvl: {p_lvl: 0 for p_lvl in ALL_LEVELS} for lvl in ALL_LEVELS
    }

    # Binary threat metrics counters (P1 #6)
    warn_adj = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    high_adj = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    warn_cat = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

    # Indicator analysis (P0 #2)
    missing_indicators_count = 0
    unexpected_indicators_count = 0
    exact_indicator_match_count = 0
    indicator_evaluable = 0
    semantic_tag_evaluable = 0
    semantic_tag_satisfied_count = 0
    semantic_tag_contradiction_count = 0

    # Clustering & diversity tracking (P2 #12)
    payload_clusters_accepted: dict[str, list[int]] = defaultdict(list)
    payload_clusters_adjudicated: dict[str, list[int]] = defaultdict(list)
    unique_payloads: set[str] = set()
    unique_templates: set[str] = set()
    unique_orgs: set[str] = set()

    for r in evaluable:
        item_id = r["item_id"]
        gt = ground_truth_by_id.get(item_id, {})
        raw = r.get("raw_result") or {}
        raw_asmt = raw.get("assessment") or {}

        # Context completeness (P0 #3)
        c_status = r.get("context_status") or raw_asmt.get("context_status")
        if not c_status:
            c_status = "complete" if (r.get("ocr_status") == "ok" and (r.get("context_accepted_count") or 0) > 0) else "missing"
        c_incomp = r.get("context_incomplete")
        if c_incomp is None:
            c_incomp = raw_asmt.get("context_incomplete", c_status in ("missing", "partial"))
        context_status_dist[str(c_status)] += 1
        if c_incomp:
            context_incomplete_count += 1

        # Payload type agreement: scenario_purpose vs encoded_payload_type (P1 #4)
        expected_pt = gt.get("scenario_purpose", gt.get("payload_type", gt.get("type", gt.get("expected_payload_type"))))
        if expected_pt and str(expected_pt).lower() == "deeplink":
            expected_pt = "deep_link"
        encoded_pt = _infer_encoded_payload_type(gt, str(expected_pt) if expected_pt else None)
        predicted_pt = r.get("payload_type")
        is_http_pay = bool(gt.get("is_http_payment_portal")) or (encoded_pt == "url" and str(expected_pt).lower() == "payment")
        if is_http_pay:
            http_payment_portal_count += 1

        if expected_pt:
            exp_pt_str = str(expected_pt).lower()
            pred_pt_str = str(predicted_pt or "unknown").lower()
            pt_expected[exp_pt_str] += 1
            purpose_confusion[exp_pt_str][pred_pt_str] += 1
            if pred_pt_str == exp_pt_str:
                pt_agreement += 1
                pt_purpose_aware_agreement += 1
            elif is_http_pay and pred_pt_str == "url":
                pt_purpose_aware_agreement += 1

        if encoded_pt:
            enc_pt_str = str(encoded_pt).lower()
            pred_pt_str = str(predicted_pt or "unknown").lower()
            pt_encoded_expected[enc_pt_str] += 1
            encoded_confusion[enc_pt_str][pred_pt_str] += 1
            if pred_pt_str == enc_pt_str:
                pt_encoded_agreement += 1

        # Assessment level agreement (P1 #6)
        predicted_level = r.get("assessment_level")
        level_distribution[predicted_level] += 1
        expected_levels = gt.get("expected_assessment", gt.get("assessment_in", gt.get("expected_level", None)))
        raw_expected_levels = gt.get("raw_expected_assessment", expected_levels)
        primary_cat = None
        if expected_levels:
            if isinstance(expected_levels, str):
                expected_levels = [expected_levels]
            primary_cat = str(expected_levels[0]).strip().lower() if expected_levels else None
            expected_level_distribution[primary_cat] += 1
            if primary_cat in category_vs_predicted and predicted_level in ALL_LEVELS:
                category_vs_predicted[primary_cat][predicted_level] += 1
            elif primary_cat and predicted_level in ALL_LEVELS:
                category_vs_predicted.setdefault(primary_cat, {lvl: 0 for lvl in ALL_LEVELS})[predicted_level] += 1

        if raw_expected_levels:
            if isinstance(raw_expected_levels, str):
                raw_expected_levels = [raw_expected_levels]
            raw_cat = str(raw_expected_levels[0]).strip().lower() if raw_expected_levels else None
            raw_expected_level_distribution[raw_cat] += 1
            if raw_cat in raw_category_vs_predicted and predicted_level in ALL_LEVELS:
                raw_category_vs_predicted[raw_cat][predicted_level] += 1
            elif raw_cat and predicted_level in ALL_LEVELS:
                raw_category_vs_predicted.setdefault(raw_cat, {lvl: 0 for lvl in ALL_LEVELS})[predicted_level] += 1

        accepted_ok = _matches_expected_assessment(predicted_level, expected_levels)
        if expected_levels and accepted_ok:
            assessment_agreement += 1

        legacy_raw_ok = _matches_expected_assessment(predicted_level, raw_expected_levels)
        if raw_expected_levels and legacy_raw_ok:
            legacy_unadjudicated_agreement += 1

        # Adjudicated single-level ordinal comparison (P1 #5, P1 #6)
        adj_expected = gt.get("adjudicated_expected_level")
        if not adj_expected and primary_cat:
            adj_expected = _PRIMARY_CATEGORY_LEVEL.get(primary_cat)
        adj_ok = False
        if adj_expected:
            n_adjudicated_eval += 1
            adjudicated_expected_distribution[adj_expected] += 1
            if adj_expected in adjudicated_confusion and predicted_level in ALL_LEVELS:
                adjudicated_confusion[adj_expected][predicted_level] += 1
            adj_ok = (predicted_level == adj_expected)
            if adj_ok:
                adjudicated_agreement += 1

            # Binary threat metrics vs adjudicated ordinal level
            pred_warn = _level_order(predicted_level) >= _level_order("needs_verification")
            exp_warn = _level_order(adj_expected) >= _level_order("needs_verification")
            warn_adj["tp" if (pred_warn and exp_warn) else "fp" if (pred_warn and not exp_warn) else "tn" if (not pred_warn and not exp_warn) else "fn"] += 1

            pred_high = _level_order(predicted_level) >= _level_order("high_concern")
            exp_high = _level_order(adj_expected) >= _level_order("high_concern")
            high_adj["tp" if (pred_high and exp_high) else "fp" if (pred_high and not exp_high) else "tn" if (not pred_high and not exp_high) else "fn"] += 1

        if primary_cat:
            pred_warn = _level_order(predicted_level) >= _level_order("needs_verification")
            cat_warn = primary_cat != "benign"
            warn_cat["tp" if (pred_warn and cat_warn) else "fp" if (pred_warn and not cat_warn) else "tn" if (not pred_warn and not cat_warn) else "fn"] += 1

        # Per-payload-type breakdown
        pt_key = str(expected_pt or predicted_pt or "unknown").lower()
        assessment_by_type[pt_key]["total"] += 1
        if accepted_ok:
            assessment_by_type[pt_key]["agreement"] += 1
            assessment_by_type[pt_key]["accepted_set_agreement"] += 1
        if legacy_raw_ok:
            assessment_by_type[pt_key]["legacy_unadjudicated_accepted_set_agreement"] += 1
        if adj_ok:
            assessment_by_type[pt_key]["adjudicated_ordinal_agreement"] += 1

        # Clustering keys (P2 #12)
        raw_qr = str(gt.get("qr_payload") or r.get("qr_payload_redacted") or item_id)
        unique_payloads.add(raw_qr)
        unique_templates.add(_normalize_payload_template(raw_qr))
        org = (gt.get("observable_cues") or {}).get("context_organization") or gt.get("displayed_context")
        if org:
            unique_orgs.add(str(org).splitlines()[0].strip())
        if expected_levels:
            payload_clusters_accepted[raw_qr].append(1 if accepted_ok else 0)
        if adj_expected:
            payload_clusters_adjudicated[raw_qr].append(1 if adj_ok else 0)

        # Indicator analysis (P0 #2)
        found_ids: set[str] = set()
        for key in ("payload_findings", "context_findings", "action_findings"):
            for e in raw.get(key, []) or []:
                iid = e.get("indicator_id", "")
                if iid and not str(iid).startswith("ACT-"):
                    found_ids.add(str(iid))

        key_indicators = gt.get("key_indicators")
        absent_indicators = gt.get("absent_indicators")
        expected_findings = gt.get("expected_findings")

        if key_indicators is not None or absent_indicators is not None:
            indicator_evaluable += 1
            k_list = list(key_indicators or [])
            a_list = list(absent_indicators or [])
            missing = [i for i in k_list if i not in found_ids]
            unexpected = [i for i in a_list if i in found_ids]
            if missing:
                missing_indicators_count += 1
            if unexpected:
                unexpected_indicators_count += 1
            if not missing and not unexpected:
                exact_indicator_match_count += 1
        elif expected_findings is not None:
            # Fallback semantic-tag evaluation when explicit key_indicators are not populated (P0 #2)
            indicator_evaluable += 1
            req_groups = [SEMANTIC_TAG_TO_INDICATORS[t] for t in expected_findings if SEMANTIC_TAG_TO_INDICATORS.get(t)]
            missing_group = any(not (found_ids & grp) for grp in req_groups)
            if missing_group:
                missing_indicators_count += 1
            else:
                exact_indicator_match_count += 1

        if expected_findings is not None:
            semantic_tag_evaluable += 1
            req_groups = [SEMANTIC_TAG_TO_INDICATORS[t] for t in expected_findings if SEMANTIC_TAG_TO_INDICATORS.get(t)]
            if all(bool(found_ids & grp) for grp in req_groups):
                semantic_tag_satisfied_count += 1
            else:
                semantic_tag_contradiction_count += 1

    # Failure taxonomy distribution
    failure_codes: Counter = Counter(r.get("failure_code") for r in failures)

    n_eval = len(evaluable)
    n_pt_eval = sum(
        1 for r in evaluable
        if ground_truth_by_id.get(r["item_id"], {}).get(
            "scenario_purpose",
            ground_truth_by_id.get(r["item_id"], {}).get("payload_type", ground_truth_by_id.get(r["item_id"], {}).get("type")),
        ) is not None
    )
    n_encoded_eval = sum(
        1 for r in evaluable
        if _infer_encoded_payload_type(
            ground_truth_by_id.get(r["item_id"], {}),
            ground_truth_by_id.get(r["item_id"], {}).get("payload_type", ground_truth_by_id.get(r["item_id"], {}).get("type")),
        ) is not None
    )
    n_assessment_eval = sum(
        1 for r in evaluable
        if ground_truth_by_id.get(r["item_id"], {}).get("expected_assessment")
        or ground_truth_by_id.get(r["item_id"], {}).get("assessment_in")
        or ground_truth_by_id.get(r["item_id"], {}).get("expected_level")
    )

    # Effective sample size (ESS) accounting for payload clustering: N^2 / sum(n_c^2)
    cluster_sizes = [len(v) for v in payload_clusters_accepted.values()]
    ess = round((sum(cluster_sizes) ** 2) / sum(c * c for c in cluster_sizes), 2) if cluster_sizes else 0.0

    return {
        "suite": "base",
        "pipeline": {
            "images_total": total,
            "images_evaluable": n_eval,
            "images_failed": len(failures),
            "qr_decode_success": qr_decoded,
            "ocr_ok": ocr_ok,
            "context_available": context_available,
            "analysis_complete": analysis_complete,
            "context_incomplete_count": context_incomplete_count,
            "context_incomplete_rate": round(context_incomplete_count / n_eval, 4) if n_eval > 0 else None,
            "context_status_distribution": dict(context_status_dist),
        },
        "payload_type": {
            "evaluable_with_gt": n_pt_eval,
            "agreement": pt_agreement,
            "agreement_rate": round(pt_agreement / n_pt_eval, 4) if n_pt_eval > 0 else None,
            "predicted_distribution": dict(pt_predicted),
            "expected_distribution": dict(pt_expected),
            "encoded_syntax": {
                "evaluable_with_gt": n_encoded_eval,
                "agreement": pt_encoded_agreement,
                "agreement_rate": round(pt_encoded_agreement / n_encoded_eval, 4) if n_encoded_eval > 0 else None,
                "expected_distribution": dict(pt_encoded_expected),
                "confusion_matrix": {k: dict(v) for k, v in encoded_confusion.items()},
            },
            "scenario_purpose": {
                "evaluable_with_gt": n_pt_eval,
                "syntax_vs_purpose_agreement": pt_agreement,
                "syntax_vs_purpose_agreement_rate": round(pt_agreement / n_pt_eval, 4) if n_pt_eval > 0 else None,
                "purpose_aware_agreement": pt_purpose_aware_agreement,
                "purpose_aware_agreement_rate": round(pt_purpose_aware_agreement / n_pt_eval, 4) if n_pt_eval > 0 else None,
                "http_payment_portal_count": http_payment_portal_count,
                "confusion_matrix": {k: dict(v) for k, v in purpose_confusion.items()},
            },
        },
        "assessment": {
            "evaluable_with_gt": n_assessment_eval,
            "agreement": assessment_agreement,
            "agreement_rate": round(assessment_agreement / n_assessment_eval, 4) if n_assessment_eval > 0 else None,
            "accepted_set_agreement": assessment_agreement,
            "accepted_set_agreement_rate": round(assessment_agreement / n_assessment_eval, 4) if n_assessment_eval > 0 else None,
            "accepted_set_note": "Permissive multi-level set compatibility against reconciled scenario categories (raw unadjudicated ScenarioForge row-index labels preserved in raw_expected_assessment).",
            "legacy_unadjudicated_accepted_set_agreement": legacy_unadjudicated_agreement,
            "legacy_unadjudicated_accepted_set_agreement_rate": round(legacy_unadjudicated_agreement / n_assessment_eval, 4) if n_assessment_eval > 0 else None,
            "adjudicated_evaluable": n_adjudicated_eval,
            "adjudicated_ordinal_agreement": adjudicated_agreement,
            "adjudicated_ordinal_agreement_rate": round(adjudicated_agreement / n_adjudicated_eval, 4) if n_adjudicated_eval > 0 else None,
            "adjudicated_note": "Strict 1-to-1 ordinal match against deterministic rule-trace adjudication of scenario payload and context.",
            "level_distribution": dict(level_distribution),
            "expected_category_distribution": dict(expected_level_distribution),
            "raw_expected_category_distribution": dict(raw_expected_level_distribution),
            "adjudicated_expected_distribution": dict(adjudicated_expected_distribution),
            "expected_category_vs_predicted_level": category_vs_predicted,
            "raw_expected_category_vs_predicted_level": raw_category_vs_predicted,
            "adjudicated_confusion_matrix": adjudicated_confusion,
            "binary_threat_metrics": {
                "warning_positive_vs_adjudicated": _binary_metrics(**warn_adj),
                "high_concern_positive_vs_adjudicated": _binary_metrics(**high_adj),
                "warning_positive_vs_scenario_category": _binary_metrics(**warn_cat),
            },
            "per_payload_type": {k: v for k, v in assessment_by_type.items()},
        },
        "indicators": {
            "evaluable": indicator_evaluable,
            "exact_indicator_match": exact_indicator_match_count,
            "exact_indicator_match_rate": round(exact_indicator_match_count / indicator_evaluable, 4) if indicator_evaluable > 0 else None,
            "missing_key_indicators": missing_indicators_count,
            "unexpected_indicators": unexpected_indicators_count,
            "semantic_tag_evaluable": semantic_tag_evaluable,
            "semantic_tag_satisfied": semantic_tag_satisfied_count,
            "semantic_tag_contradictions": semantic_tag_contradiction_count,
        },
        "diversity_and_clustering": {
            "total_evaluable": n_eval,
            "unique_qr_payloads": len(unique_payloads),
            "unique_normalized_templates": len(unique_templates),
            "unique_organizations": len(unique_orgs),
            "effective_sample_size_ess": ess,
            "wilson_95_ci_accepted_set": _wilson_ci(assessment_agreement, n_assessment_eval),
            "cluster_bootstrap_95_ci_accepted_set": _cluster_bootstrap_ci(payload_clusters_accepted),
            "wilson_95_ci_adjudicated": _wilson_ci(adjudicated_agreement, n_adjudicated_eval),
            "cluster_bootstrap_95_ci_adjudicated": _cluster_bootstrap_ci(payload_clusters_adjudicated),
        },
        "failures": {
            "total": len(failures),
            "by_code": dict(failure_codes),
        },
    }


# --------------------------------------------------------------------------- Counterfactual
def _indicator_ids(result: dict[str, Any]) -> set[str]:
    raw = result.get("raw_result") or {}
    ids: set[str] = set()
    for key in ("payload_findings", "context_findings", "action_findings"):
        for entry in raw.get(key, []) or []:
            iid = entry.get("indicator_id")
            if iid:
                ids.add(str(iid))
    return ids


def score_counterfactual(
    results: list[dict[str, Any]],
    pairs: list[dict[str, Any]],
    ground_truth_by_pair_id: dict[str, dict[str, Any]],
    negative_controls: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Score v3 directional counterfactuals and isolated no-change controls.

    Separates rule/indicator activation sensitivity from final discrete ordinal
    level movement (P1 #6).
    """
    negative_controls = list(negative_controls or [])
    by_id = {r["item_id"]: r for r in results}
    directional_results: list[dict[str, Any]] = []
    direction_counts: Counter = Counter()
    by_payload_type: dict[str, Counter] = defaultdict(Counter)

    def evaluate_pair(pair_meta: dict[str, Any], *, role: str) -> tuple[dict[str, Any], str]:
        pair_id = str(pair_meta.get("pair_id", pair_meta.get("id", "")))
        gt = ground_truth_by_pair_id.get(pair_id, pair_meta)
        res_a = by_id.get(f"{pair_id}_a")
        res_b = by_id.get(f"{pair_id}_b")
        if res_a is None or res_b is None:
            return ({"pair_id": pair_id, "status": "not_evaluable", "reason": "missing result for one or both images"}, "not_evaluable_missing_result")
        if not res_a.get("evaluable") or not res_b.get("evaluable"):
            status = "not_evaluable_pipeline_failure"
            return ({"pair_id": pair_id, "status": status,
                     "failure_a": res_a.get("failure_code"), "failure_b": res_b.get("failure_code")}, status)
        level_a = res_a.get("assessment_level")
        level_b = res_b.get("assessment_level")
        observed = _direction(level_a, level_b)
        expected = gt.get("expected_direction", gt.get("expect", "b_more_concerning"))
        pt = gt.get("payload_type", gt.get("type", res_a.get("payload_type", "unknown")))
        if role == "directional":
            if observed == "not_evaluable":
                status = "not_evaluable"
            elif observed == expected:
                status = "correct_direction"
            elif observed == "indistinguishable":
                status = "unchanged_assessment"
            else:
                status = "opposite_direction"
        else:
            status = "assessment_stable" if observed == "indistinguishable" else (
                "not_evaluable" if observed == "not_evaluable" else "assessment_changed"
            )
        indicators_a = _indicator_ids(res_a)
        indicators_b = _indicator_ids(res_b)
        non_act_a = {i for i in indicators_a if not i.startswith("ACT-")}
        non_act_b = {i for i in indicators_b if not i.startswith("ACT-")}
        indicator_changed = non_act_a != non_act_b
        detail = {
            "pair_id": pair_id,
            "payload_type": pt,
            "changed_factor": gt.get("variable", gt.get("changed_factor", gt.get("factor"))),
            "expected_direction": expected,
            "level_a": level_a,
            "level_b": level_b,
            "observed_direction": observed,
            "status": status,
            "finding_stable": indicators_a == indicators_b,
            "indicator_changed": indicator_changed,
            "indicators_only_in_a": sorted(indicators_a - indicators_b),
            "indicators_only_in_b": sorted(indicators_b - indicators_a),
        }
        return detail, status

    for pair_meta in pairs:
        detail, status = evaluate_pair(pair_meta, role="directional")
        directional_results.append(detail)
        direction_counts[status] += 1
        pt = detail.get("payload_type", pair_meta.get("payload_type", "unknown"))
        by_payload_type[pt][status] += 1

    control_results: list[dict[str, Any]] = []
    control_counts: Counter = Counter()
    controls_by_payload: dict[str, Counter] = defaultdict(Counter)
    for pair_meta in negative_controls:
        detail, status = evaluate_pair(pair_meta, role="control")
        control_results.append(detail)
        control_counts[status] += 1
        pt = detail.get("payload_type", pair_meta.get("payload_type", "unknown"))
        controls_by_payload[pt][status] += 1

    def directional_evaluable(d: dict[str, Any]) -> bool:
        return d.get("status") in {"correct_direction", "unchanged_assessment", "opposite_direction"}

    eval_dir_items = [d for d in directional_results if directional_evaluable(d)]
    directional_evaluable_n = len(eval_dir_items)
    correct_dir_n = direction_counts.get("correct_direction", 0)
    unchanged_n = direction_counts.get("unchanged_assessment", 0)
    opposite_n = direction_counts.get("opposite_direction", 0)
    indicator_changed_n = sum(1 for d in eval_dir_items if d.get("indicator_changed"))
    sub_threshold_n = sum(1 for d in eval_dir_items if d.get("status") == "unchanged_assessment" and d.get("indicator_changed"))

    control_evaluable_n = sum(d.get("status") in {"assessment_stable", "assessment_changed"} for d in control_results)
    control_finding_stable = sum(1 for d in control_results if d.get("status") == "assessment_stable" and d.get("finding_stable"))
    control_finding_compared = sum(1 for d in control_results if d.get("status") in {"assessment_stable", "assessment_changed"})

    return {
        "suite": "counterfactual",
        "summary": {
            "total_pairs": len(pairs),
            "total_images": len(results),
            "evaluable_pairs": directional_evaluable_n,
            "correct_direction": correct_dir_n,
            "directional_movement_rate": round(correct_dir_n / directional_evaluable_n, 4) if directional_evaluable_n else None,
            "unchanged_assessment": unchanged_n,
            "indistinguishable": unchanged_n,
            "opposite_direction": opposite_n,
            "not_evaluable": len(pairs) - directional_evaluable_n,
            "indicator_changed_pairs": indicator_changed_n,
            "indicator_change_rate": round(indicator_changed_n / directional_evaluable_n, 4) if directional_evaluable_n else None,
            "sub_threshold_indicator_change_only": sub_threshold_n,
        },
        "directional": {
            "total_pairs": len(pairs),
            "evaluable_pairs": directional_evaluable_n,
            "correct_direction": correct_dir_n,
            "directional_movement_rate": round(correct_dir_n / directional_evaluable_n, 4) if directional_evaluable_n else None,
            "unchanged_assessment": unchanged_n,
            "opposite_direction": opposite_n,
            "not_evaluable": len(pairs) - directional_evaluable_n,
            "rule_activation_sensitivity": {
                "evaluable_pairs": directional_evaluable_n,
                "indicator_changed_pairs": indicator_changed_n,
                "indicator_change_rate": round(indicator_changed_n / directional_evaluable_n, 4) if directional_evaluable_n else None,
                "sub_threshold_indicator_change_only": sub_threshold_n,
            },
            "final_level_directional_sensitivity": {
                "evaluable_pairs": directional_evaluable_n,
                "correct_direction": correct_dir_n,
                "directional_movement_rate": round(correct_dir_n / directional_evaluable_n, 4) if directional_evaluable_n else None,
                "unchanged_assessment": unchanged_n,
                "opposite_direction": opposite_n,
            },
            "expected_balance": {
                "b_more_concerning": sum(1 for p in pairs if p.get("expected_direction") == "b_more_concerning"),
                "b_less_concerning": sum(1 for p in pairs if p.get("expected_direction") == "b_less_concerning"),
            },
        },
        "negative_controls": {
            "total_pairs": len(negative_controls),
            "total_images": len(negative_controls) * 2,
            "evaluable_pairs": control_evaluable_n,
            "assessment_stable": control_counts.get("assessment_stable", 0),
            "assessment_changed": control_counts.get("assessment_changed", 0),
            "not_evaluable": len(negative_controls) - control_evaluable_n,
            "assessment_stability_rate": round(control_counts.get("assessment_stable", 0) / control_evaluable_n, 4) if control_evaluable_n else None,
            "finding_stable": control_finding_stable,
            "finding_comparable": control_finding_compared,
            "finding_stability_rate": round(control_finding_stable / control_finding_compared, 4) if control_finding_compared else None,
        },
        "by_payload_type": {k: dict(v) for k, v in by_payload_type.items()},
        "negative_controls_by_payload_type": {k: dict(v) for k, v in controls_by_payload.items()},
        "pairs": directional_results,
        "negative_control_pairs": control_results,
    }


# --------------------------------------------------------------------------- Robustness
def score_robustness(
    results: list[dict[str, Any]],
    base_results_by_base_id: dict[str, dict[str, Any]],
    ground_truth_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Compute robustness suite metrics (P0 #1, P0 #3).

    Joins each variant to its base scenario via ``base_id`` or ``original_scenario_id``,
    flags any missing base links, and reports both conditional (evaluable / QR-decoded)
    and unconditional (all 140 variants) assessment retention.
    """
    total = len(results)
    evaluable = [r for r in results if r.get("evaluable")]

    qr_retained = 0
    ocr_retained = 0
    assessment_retained = 0
    assessment_changed = 0
    concern_lost = 0
    concern_introduced = 0

    all_decoded_compared = 0
    all_decoded_retained = 0
    ocr_failure_assessment_drops = 0
    context_incomplete_variants = 0
    missing_base_links: list[str] = []

    by_payload_type: dict[str, dict] = defaultdict(
        lambda: {"total": 0, "qr_ok": 0, "ocr_ok": 0, "assessment_compared": 0, "assessment_retained": 0}
    )
    by_variant: dict[str, dict] = defaultdict(
        lambda: {"total": 0, "qr_ok": 0, "ocr_ok": 0, "assessment_compared": 0, "assessment_retained": 0}
    )
    by_transformation: dict[str, dict] = defaultdict(
        lambda: {"total": 0, "qr_ok": 0, "ocr_ok": 0, "assessment_compared": 0, "assessment_retained": 0}
    )

    item_details = []
    for r in results:
        item_id = r["item_id"]
        gt = ground_truth_by_id.get(item_id, {})
        base_id = (
            gt.get("base_id")
            or gt.get("original_scenario_id")
            or gt.get("original_id")
            or r.get("base_id")
            or r.get("original_scenario_id")
        )
        variant_id = gt.get("variant_id") or r.get("variant_id") or item_id
        transformation = (
            gt.get("transformation")
            or gt.get("transform")
            or r.get("transformation")
            or variant_id
        )
        base = base_results_by_base_id.get(str(base_id)) if base_id else None
        if not base_id or (base_results_by_base_id and base is None):
            missing_base_links.append(str(item_id))

        pt = str(gt.get("payload_type", gt.get("type", r.get("payload_type", "unknown")))).lower()
        if pt == "deeplink":
            pt = "deep_link"

        qr_ok = bool(r.get("qr_decode_success"))
        ocr_ok = r.get("ocr_status") == "ok"
        raw_asmt = (r.get("raw_result") or {}).get("assessment", {}) if r.get("raw_result") else {}
        ctx_incomp = r.get("context_incomplete")
        if ctx_incomp is None:
            ctx_incomp = raw_asmt.get("context_incomplete", qr_ok and not ocr_ok)
        if qr_ok and ctx_incomp:
            context_incomplete_variants += 1

        assessment_ok = None
        decoded_assessment_ok = None
        direction = None
        base_level = base.get("assessment_level") if base else None
        variant_level = r.get("assessment_level")

        # All QR-decoded variants comparison (including OCR_NO_TEXT where QR decoded and raw_result exists)
        if base and base.get("evaluable") and qr_ok and variant_level:
            all_decoded_compared += 1
            decoded_assessment_ok = (base_level == variant_level)
            if decoded_assessment_ok:
                all_decoded_retained += 1
            elif not ocr_ok and _level_order(variant_level) < _level_order(base_level):
                ocr_failure_assessment_drops += 1

        # Conditional comparison on evaluable variants
        if base and r.get("evaluable") and base.get("evaluable"):
            assessment_ok = (base_level == variant_level)
            direction = _direction(base_level, variant_level) if base_level != variant_level else "retained"
            if assessment_ok:
                assessment_retained += 1
            else:
                assessment_changed += 1
                if _level_order(variant_level) < _level_order(base_level):
                    concern_lost += 1
                else:
                    concern_introduced += 1

        if qr_ok:
            qr_retained += 1
        if ocr_ok:
            ocr_retained += 1

        for bucket in (by_payload_type[pt], by_variant[str(variant_id)], by_transformation[str(transformation)]):
            bucket["total"] += 1
            if qr_ok:
                bucket["qr_ok"] += 1
            if ocr_ok:
                bucket["ocr_ok"] += 1
            if assessment_ok is not None:
                bucket["assessment_compared"] += 1
            if assessment_ok:
                bucket["assessment_retained"] += 1

        item_details.append({
            "item_id": item_id,
            "base_id": base_id,
            "original_scenario_id": base_id,
            "variant_id": variant_id,
            "transformation": transformation,
            "payload_type": pt,
            "qr_retained": qr_ok,
            "ocr_retained": ocr_ok,
            "base_level": base_level,
            "variant_level": variant_level,
            "assessment_retained": assessment_ok,
            "decoded_assessment_retained": decoded_assessment_ok,
            "context_incomplete": bool(ctx_incomp) if qr_ok else True,
            "direction": direction,
        })

    n_with_base = sum(1 for d in item_details if d["assessment_retained"] is not None)

    return {
        "suite": "robustness",
        "summary": {
            "total_variants": total,
            "evaluable": len(evaluable),
            "qr_retained": qr_retained,
            "qr_retention_rate": round(qr_retained / total, 4) if total > 0 else None,
            "ocr_retained": ocr_retained,
            "ocr_retention_rate": round(ocr_retained / total, 4) if total > 0 else None,
            "assessment_compared": n_with_base,
            "assessment_retained": assessment_retained,
            "assessment_retention_rate": round(assessment_retained / n_with_base, 4) if n_with_base > 0 else None,
            "all_decoded_compared": all_decoded_compared,
            "all_decoded_retained": all_decoded_retained,
            "all_decoded_retention_rate": round(all_decoded_retained / all_decoded_compared, 4) if all_decoded_compared > 0 else None,
            "unconditional_assessment_retained": all_decoded_retained,
            "unconditional_assessment_retention_rate": round(all_decoded_retained / total, 4) if total > 0 else None,
            "ocr_failure_assessment_drops": ocr_failure_assessment_drops,
            "context_incomplete_variants": context_incomplete_variants,
            "missing_base_links_count": len(missing_base_links),
            "missing_base_links": missing_base_links,
            "concern_lost": concern_lost,
            "concern_introduced": concern_introduced,
            "assessment_changed": assessment_changed,
        },
        "by_payload_type": {k: v for k, v in by_payload_type.items()},
        "by_transformation": {k: v for k, v in by_transformation.items()},
        "by_variant": {k: v for k, v in by_variant.items()},
        "items": item_details,
    }
