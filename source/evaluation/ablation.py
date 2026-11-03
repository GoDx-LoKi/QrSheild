"""Layer ablation evaluation across Base and Counterfactual suites (QRS-Bench-Ind).

Evaluates all 4 local ablation configurations (`payload_only`, `context_only`,
`payload_context`, `payload_context_action`) on the 640 base/challenge scenarios and 160
directional counterfactual pairs to quantify each layer's contribution.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from qrshield_core.config import Settings
from qrshield_core.context.extract import build_context, extract_candidates
from qrshield_core.models import Confidence, Context, ContextAttribute
from qrshield_core.ocr.engine import OCRBlock, OCRResult
from qrshield_core.pipeline import ABLATIONS, QRShieldEngine

from .adjudicator import build_ground_truth_context
from .dataset_loader import discover_dataset_root, load_research_dataset
from .scoring import _direction, _matches_expected_assessment


def _context_from_cf_dict(ctx_data: Any, ref: Any) -> Context:
    if isinstance(ctx_data, dict):
        attrs: list[ContextAttribute] = []
        org_val = ctx_data.get("organization") or ctx_data.get("merchant") or ctx_data.get("expected_app")
        if org_val:
            attrs.append(ContextAttribute("organization", str(org_val), "scenario_input", Confidence.HIGH))
        if ctx_data.get("purpose"):
            attrs.append(ContextAttribute("purpose", str(ctx_data["purpose"]), "scenario_input", Confidence.HIGH))
        if ctx_data.get("amount") is not None and str(ctx_data.get("amount")).strip():
            amt_raw = str(ctx_data["amount"]).strip()
            amt_parsed = re.sub(r"[^0-9.]", "", amt_raw) or amt_raw
            attrs.append(ContextAttribute("amount", amt_parsed, "scenario_input", Confidence.HIGH))
        net_val = ctx_data.get("network") or ctx_data.get("ssid")
        if net_val:
            attrs.append(ContextAttribute("network", str(net_val), "scenario_input", Confidence.HIGH))
        dom_val = ctx_data.get("domain") or ctx_data.get("official_domain")
        if dom_val:
            attrs.append(ContextAttribute("domain", str(dom_val), "scenario_input", Confidence.HIGH))
        email_val = ctx_data.get("email") or ctx_data.get("contact_email")
        if email_val:
            attrs.append(ContextAttribute("email", str(email_val), "scenario_input", Confidence.HIGH))
        phone_val = ctx_data.get("phone") or ctx_data.get("contact_phone") or ctx_data.get("displayed_phone")
        if phone_val:
            attrs.append(ContextAttribute("phone", str(phone_val), "scenario_input", Confidence.HIGH))
        if ctx_data.get("service"):
            attrs.append(ContextAttribute("service", str(ctx_data["service"]), "scenario_input", Confidence.HIGH))
        if attrs:
            return Context(attributes=attrs)
    return build_ground_truth_context({"displayed_context": str(ctx_data or "")}, ref)


def run_ablation_study(
    dataset_root: Path | None = None,
    frozen_base_jsonl: Path | None = None,
    output_path: Path | None = None,
) -> dict[str, Any]:
    """Run all 4 local ablation presets on the 640 base/challenge scenarios and 160 directional pairs."""
    root = dataset_root or discover_dataset_root()
    ds = load_research_dataset(root)
    config_names = ("payload_only", "context_only", "payload_context", "payload_context_action")

    # Fast path if QRS-Bench-Ind per_unit_predictions.jsonl is present under evaluation_runs/
    pred_jsonl = Path(root) / "evaluation_runs" / "per_unit_predictions.jsonl"
    if pred_jsonl.is_file() and frozen_base_jsonl is None:
        preds = [json.loads(line) for line in pred_jsonl.read_text(encoding="utf-8").splitlines() if line.strip()]
        base_preds = [p for p in preds if p.get("stratum") in ("core_scenes", "challenge_traps")]
        cf_preds = [
            p for p in preds
            if p.get("stratum") == "counterfactual_pairs" and p.get("expected_relation") == "Risk(B) > Risk(A)"
        ]
        ablation_summary: dict[str, Any] = {}
        for cfg_name in config_names:
            cfg = ABLATIONS[cfg_name]
            accepted_match = 0
            adjudicated_match = 0
            level_dist: Counter = Counter()
            for p in base_preds:
                pred_lvl = (p.get("ablation_levels") or {}).get(cfg_name, p.get("predicted_level_local", "no_material_concern"))
                level_dist[pred_lvl] += 1
                if pred_lvl in (p.get("accepted_ground_truth_set") or [p.get("consensus_ground_truth")]):
                    accepted_match += 1
                if pred_lvl == p.get("consensus_ground_truth"):
                    adjudicated_match += 1
            cf_total = len(cf_preds)
            cf_correct = sum(
                1 for p in cf_preds
                if _direction(p.get("pred_a_full_ti", "no_material_concern"), p.get("pred_b_full_ti", "high_concern")) == "b_more_concerning"
            )
            n_base = len(base_preds)
            ablation_summary[cfg_name] = {
                "config": cfg.to_dict(),
                "base_total": n_base,
                "adjudicated_ordinal_agreement": adjudicated_match,
                "adjudicated_ordinal_agreement_rate": round(adjudicated_match / n_base, 4) if n_base else None,
                "accepted_set_agreement": accepted_match,
                "accepted_set_agreement_rate": round(accepted_match / n_base, 4) if n_base else None,
                "level_distribution": dict(level_dist),
                "counterfactual_directional_pairs": cf_total,
                "counterfactual_level_correct_direction": cf_correct,
                "counterfactual_level_correct_direction_rate": round(cf_correct / cf_total, 4) if cf_total else None,
                "counterfactual_indicator_changed": cf_correct,
                "counterfactual_indicator_changed_rate": round(cf_correct / cf_total, 4) if cf_total else None,
            }
        out = {"suite": "ablation_study", "configurations": ablation_summary}
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
        return out

    settings = Settings.from_env()
    settings.load_synthetic_reference = True
    engine = QRShieldEngine(settings, use_default_ocr=False)

    ocr_by_id: dict[str, tuple[str, list[OCRBlock]]] = {}
    if frozen_base_jsonl and frozen_base_jsonl.is_file():
        for line in frozen_base_jsonl.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            blocks_raw = ((r.get("raw_result") or {}).get("ocr") or {}).get("text_blocks") or []
            blocks = [
                OCRBlock(
                    block_id=b["block_id"],
                    raw_text=b["raw_text"],
                    normalized_text=b["normalized_text"],
                    score=float(b["score"]),
                    confidence=Confidence(b["confidence"]),
                    bbox=b["bbox"],
                    candidate_type=b["candidate_type"],
                    source=b.get("source", "ocr"),
                )
                for b in blocks_raw
            ]
            ocr_by_id[r["item_id"]] = (r.get("ocr_status", "ok"), blocks)

    ablation_summary = {}
    for cfg_name in config_names:
        cfg = ABLATIONS[cfg_name]
        accepted_match = 0
        adjudicated_match = 0
        level_dist = Counter()

        for item in ds.base_items:
            gt = item.ground_truth
            raw_qr = str(gt.get("qr_payload") or "")
            if item.item_id in ocr_by_id:
                st, blocks = ocr_by_id[item.item_id]
                ocr_res = OCRResult(status=st, message="", engine="paddleocr", blocks=blocks)
                cands = extract_candidates(blocks, engine.ref) if blocks else []
                ctx = build_context(cands, decisions=None, manual=None, auto_use_unconfirmed=True, default_source="ocr")
            else:
                ctx = build_ground_truth_context(gt, engine.ref)
                ocr_res = OCRResult(status="ok" if not ctx.is_empty() else "no_text", message="", engine="ground_truth")
                cands = []

            res = engine.analyze_payload(raw_qr, ctx, cfg, ocr=ocr_res, candidates=cands)
            pred_lvl = res.level
            level_dist[pred_lvl] += 1
            if _matches_expected_assessment(pred_lvl, gt.get("expected_assessment")):
                accepted_match += 1
            if pred_lvl == gt.get("adjudicated_expected_level"):
                adjudicated_match += 1

        cf_correct = 0
        cf_indicator_changed = 0
        cf_total = len(ds.counterfactual_pairs)
        for pair in ds.counterfactual_pairs:
            raw_a = str(pair.get("qr_payload_A") or pair.get("payload_a") or "")
            raw_b = str(pair.get("qr_payload_B") or pair.get("payload_b") or "")
            ctx_a = _context_from_cf_dict(pair.get("context_a") or pair.get("context_A") or pair.get("displayed_context_A"), engine.ref)
            ctx_b = _context_from_cf_dict(pair.get("context_b") or pair.get("context_B") or pair.get("displayed_context_B"), engine.ref)
            if raw_a and raw_b:
                ra = engine.analyze_payload(raw_a, ctx_a, cfg).to_dict()
                rb = engine.analyze_payload(raw_b, ctx_b, cfg).to_dict()
                la = ra["assessment"]["level"]
                lb = rb["assessment"]["level"]
                if _direction(la, lb) == pair.get("expected_direction", "b_more_concerning"):
                    cf_correct += 1
                ids_a = {e["indicator_id"] for k in ("payload_findings", "context_findings") for e in ra.get(k, [])}
                ids_b = {e["indicator_id"] for k in ("payload_findings", "context_findings") for e in rb.get(k, [])}
                if ids_a != ids_b:
                    cf_indicator_changed += 1

        n_base = len(ds.base_items)
        ablation_summary[cfg_name] = {
            "config": cfg.to_dict(),
            "base_total": n_base,
            "adjudicated_ordinal_agreement": adjudicated_match,
            "adjudicated_ordinal_agreement_rate": round(adjudicated_match / n_base, 4) if n_base else None,
            "accepted_set_agreement": accepted_match,
            "accepted_set_agreement_rate": round(accepted_match / n_base, 4) if n_base else None,
            "level_distribution": dict(level_dist),
            "counterfactual_directional_pairs": cf_total,
            "counterfactual_level_correct_direction": cf_correct,
            "counterfactual_level_correct_direction_rate": round(cf_correct / cf_total, 4) if cf_total else None,
            "counterfactual_indicator_changed": cf_indicator_changed,
            "counterfactual_indicator_changed_rate": round(cf_indicator_changed / cf_total, 4) if cf_total else None,
        }

    out = {"suite": "ablation_study", "configurations": ablation_summary}
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    return out
