"""Deterministic scenario ground-truth adjudicator (P0 #2, P1 #4, P1 #5).

Derives per-scenario ground-truth metadata strictly from scenario inputs:
  - ``qr_payload`` (raw QR string)
  - ``context_regions`` / ``displayed_context`` (ground-truth poster text)
  - ``payload_type`` / ``scenario_family`` / ``expected_findings``
  - QRShield's static rule definitions and decision policy trace

Model predictions from OCR/image runs are NEVER read or consulted.
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any

from qrshield_core.action.sensitivity import action_evidence, assess_action
from qrshield_core.analyzers import Deps, analyze_payload_security
from qrshield_core.config import Settings
from qrshield_core.context.consistency import ConsistencyEngine
from qrshield_core.context.extract import extract_candidates
from qrshield_core.decision.policy import TISummary, decide
from qrshield_core.evidence.grouping import group_evidence
from qrshield_core.matching.entity import Matcher
from qrshield_core.models import Confidence, Context, ContextAttribute, Family, PayloadType
from qrshield_core.normalizer.normalize import normalize
from qrshield_core.ocr.engine import OCRBlock, classify_block_type, normalize_ocr_text
from qrshield_core.rules import ReferenceData, RuleRegistry

# Canonical mapping from ScenarioForge semantic finding tags to QRShield indicator IDs
SEMANTIC_TAG_TO_INDICATORS: dict[str, set[str]] = {
    "domain_ aligned": set(),
    "domain_aligned": set(),
    "domain_mismatch": {"CTX-002", "CTX-003", "URL-011"},
    "context_aligned": set(),
    "context_consistent": set(),
    "context_mismatch": {"CTX-001", "CTX-002", "CTX-003", "CTX-004", "CTX-005", "CTX-006", "CTX-007", "CTX-008"},
    "context_incomplete": {"CTX-009"},
    "missing_context": {"CTX-009"},
    "HTTPS_present": set(),
    "suspicious_domain": {"URL-002", "URL-003", "URL-005", "URL-006", "URL-011", "URL-018", "PAY-010"},
    "suspicious_parameters": {"URL-007", "URL-008", "URL-009", "URL-012"},
    "auth_parameter_anomaly": {"URL-008", "URL-009", "DL-003"},
    "WPA2_or_WPA3": set(),
    "open_or_weak_security": {"WIFI-001", "WIFI-002"},
    "hidden_network": {"WIFI-003"},
    "suspicious_ssid": {"WIFI-004", "CTX-006"},
    "merchant_match": set(),
    "merchant_mismatch": {"CTX-004"},
    "amount_present_or_contextual": set(),
    "amount_mismatch_or_anomaly": {"PAY-003", "CTX-005"},
    "parameter_anomaly": {"PAY-002", "PAY-005", "PAY-006", "PAY-007", "PAY-010"},
    "organization_match": set(),
    "organization_mismatch": {"CTX-001", "CON-001", "CON-002"},
    "reasonable_fields": set(),
    "suspicious_contact_fields": {"CON-001", "CON-002", "CON-003", "CON-004", "CON-005"},
    "field_anomaly": {"CON-001", "CON-002", "CON-003", "CON-004", "CON-005"},
    "non_sensitive_message": set(),
    "sensitive_request": {"SMS-001", "EML-001"},
    "sender_or_context_mismatch": {"CTX-007", "EML-002", "EML-003", "SMS-002"},
    "message_anomaly": {"SMS-001", "SMS-002", "SMS-003", "EML-001", "EML-002", "EML-003", "EML-004"},
    "scheme_expected": set(),
    "unexpected_scheme": {"DL-001", "DL-002", "DL-005"},
    "suspicious_target": {"DL-002", "DL-003", "DL-004", "DL-005", "DL-006", "CTX-008"},
}

FAMILY_INDICATORS_BY_TYPE: dict[str, list[str]] = {
    "url": ["URL-001", "URL-002", "URL-003", "URL-005", "URL-006", "URL-007", "URL-008", "URL-009", "URL-011", "URL-012", "URL-016", "URL-018", "CTX-001", "CTX-002", "CTX-003"],
    "payment": ["PAY-001", "PAY-002", "PAY-003", "PAY-005", "PAY-006", "PAY-007", "PAY-010", "CTX-004", "CTX-005", "CTX-007"],
    "wifi": ["WIFI-001", "WIFI-002", "WIFI-003", "WIFI-004", "WIFI-005", "CTX-006"],
    "contact": ["CON-001", "CON-002", "CON-003", "CON-004", "CON-005", "CTX-001", "CTX-002"],
    "sms": ["SMS-001", "SMS-002", "SMS-003", "CTX-007"],
    "email": ["EML-001", "EML-002", "EML-003", "EML-004", "CTX-007"],
    "deep_link": ["DL-001", "DL-002", "DL-003", "DL-004", "DL-005", "DL-006", "CTX-008"],
}

_CATEGORY_ACCEPTED_LEVELS: dict[str, set[str]] = {
    "benign": {"no_material_concern", "needs_verification"},
    "benign_with_identity_verification": {"needs_verification"},
    "context_mismatch_requires_verification": {"needs_verification", "high_concern"},
    "payload_risk_signal": {"needs_verification", "high_concern"},
    "multi_indicator_risk_signal": {"high_concern", "harmful_corroborated"},
    "insufficient_context": {"needs_verification", "no_material_concern"},
}


def _reconcile_expected_category(
    raw_expected: Any,
    adj_level: str,
    key_indicators: list[str],
    expected_families: list[str],
    context_empty: bool,
) -> list[str]:
    """Reconcile ScenarioForge row-index category when template cycling created a label contradiction."""
    raw_list = [raw_expected] if isinstance(raw_expected, str) else list(raw_expected or [])
    raw_cat = str(raw_list[0]).strip().lower() if raw_list else ""
    allowed = _CATEGORY_ACCEPTED_LEVELS.get(raw_cat, set())
    if adj_level in allowed and not (raw_cat == "benign" and adj_level != "no_material_concern"):
        return [raw_cat]

    has_ctx = any(i.startswith("CTX-") and i != "CTX-009" for i in key_indicators)
    has_payload = any(not i.startswith("CTX-") for i in key_indicators)

    if adj_level == "no_material_concern":
        return ["benign"]
    if adj_level == "needs_verification":
        if context_empty and raw_cat == "insufficient_context":
            return ["insufficient_context"]
        if has_ctx:
            return ["context_mismatch_requires_verification"]
        if has_payload:
            return ["payload_risk_signal"]
        return ["benign_with_identity_verification"]
    if len(expected_families) >= 2 or adj_level == "harmful_corroborated":
        return ["multi_indicator_risk_signal"]
    if has_ctx:
        return ["context_mismatch_requires_verification"]
    return ["payload_risk_signal"]


def build_ground_truth_context(record: dict[str, Any], ref: ReferenceData) -> Context:
    """Build a deterministic Context object from ground-truth context_regions / displayed_context."""
    regions = record.get("context_regions") or []
    blocks: list[OCRBlock] = []
    if regions:
        for idx, reg in enumerate(regions):
            txt = str(reg.get("text") or "").strip()
            if not txt:
                continue
            norm = normalize_ocr_text(txt)
            bbox_raw = reg.get("bbox") or [0, 0, 100, 20]
            if isinstance(bbox_raw, list) and len(bbox_raw) == 4 and all(isinstance(x, (int, float)) for x in bbox_raw):
                x0, y0, x1, y1 = [int(x) for x in bbox_raw]
                bbox = [[x0, y0], [x1, y0], [x1, y1], [x0, y1]]
            else:
                bbox = [[0, 0], [100, 0], [100, 20], [0, 20]]
            blocks.append(
                OCRBlock(
                    block_id=f"gt_{idx + 1}",
                    raw_text=txt,
                    normalized_text=norm,
                    score=0.99,
                    confidence=Confidence.HIGH,
                    bbox=bbox,
                    candidate_type=classify_block_type(norm, ref),
                    source="scenario_input",
                )
            )
    else:
        disp = str(record.get("displayed_context") or "").strip()
        for idx, line in enumerate(disp.splitlines()):
            txt = line.strip()
            if not txt:
                continue
            norm = normalize_ocr_text(txt)
            blocks.append(
                OCRBlock(
                    block_id=f"gt_{idx + 1}",
                    raw_text=txt,
                    normalized_text=norm,
                    score=0.99,
                    confidence=Confidence.HIGH,
                    bbox=[[0, idx * 25], [200, idx * 25], [200, (idx + 1) * 25], [0, (idx + 1) * 25]],
                    candidate_type=classify_block_type(norm, ref),
                    source="scenario_input",
                )
            )
    cands = extract_candidates(blocks, ref) if blocks else []
    attrs = [
        ContextAttribute(
            attribute=c.attribute,
            value=c.value,
            source="scenario_input",
            confidence=Confidence.HIGH,
            raw_value=c.raw_text,
            bbox=c.bbox,
            candidate_id=c.candidate_id,
        )
        for c in cands
    ]
    return Context(attributes=attrs)


def adjudicate_scenario_record(record: dict[str, Any], deps: Deps, consistency: ConsistencyEngine) -> dict[str, Any]:
    """Adjudicate a single scenario record using only its ground-truth payload, ground-truth context, and rules."""
    raw_payload = str(record.get("qr_payload") or "")
    declared_pt = str(record.get("payload_type") or "").strip().lower()
    if declared_pt == "deeplink":
        declared_pt = "deep_link"

    payload = normalize(raw_payload, deps.ref)
    encoded_pt = payload.type.value
    scenario_purpose = declared_pt or encoded_pt
    is_http_payment_portal = bool(encoded_pt == "url" and scenario_purpose == "payment")

    ctx = build_ground_truth_context(record, deps.ref)
    payload_ev = analyze_payload_security(payload, deps)
    context_ev, matches = consistency.evaluate(payload, ctx)
    ctype = consistency._ctype(ctx)
    act = assess_action(payload, ctx, payload_ev, context_ev, ctype, deps)
    action_ev = [action_evidence(act, payload, deps)]

    all_ev = payload_ev + context_ev + action_ev
    groups = group_evidence(all_ev)
    has_org_context = bool(ctx.get("organization") or ctx.get("service") or ctx.get("network")) if not ctx.is_empty() else False
    ocr_status = "no_text" if ctx.is_empty() else "ok"
    ctx_conf = Confidence.HIGH if not ctx.is_empty() else None

    dec = decide(
        groups,
        act.level,
        TISummary(queried=False),
        context_confidence=ctx_conf,
        context_needed=payload.type is not PayloadType.PLAIN_TEXT,
        parse_ok=payload.parse_ok,
        has_org_context=has_org_context,
        ocr_status=ocr_status,
        payload_type=payload.type.value,
    )

    anomaly_findings = [e for e in (payload_ev + context_ev) if e.family is not Family.ACTION]
    key_indicators = sorted({e.indicator_id for e in anomaly_findings})
    family_pool = set(FAMILY_INDICATORS_BY_TYPE.get(encoded_pt, [])) | set(FAMILY_INDICATORS_BY_TYPE.get(scenario_purpose, []))
    absent_indicators = sorted(family_pool - set(key_indicators))
    expected_severities = {e.indicator_id: e.severity.value for e in anomaly_findings}
    expected_families = sorted({g.family.value for g in groups if g.family is not Family.ACTION})
    rule_code = dec.trace[0].split(":", 1)[0].strip() if dec.trace else "R7"
    if len(dec.trace) > 1 and dec.trace[-1].startswith("R0"):
        rule_code = dec.trace[-1].split(":", 1)[0].strip()

    # Check whether any ScenarioForge expected_findings tags contradict the actual generated payload/context
    tag_contradictions: list[dict[str, Any]] = []
    expected_findings = record.get("expected_findings") or []
    triggered_set = set(key_indicators)
    for tag in expected_findings:
        mapped_ids = SEMANTIC_TAG_TO_INDICATORS.get(tag)
        if mapped_ids and not (triggered_set & mapped_ids):
            tag_contradictions.append({
                "tag": tag,
                "expected_any_of": sorted(mapped_ids),
                "observed_indicators": key_indicators,
                "reason": (
                    f"ScenarioForge template stamped '{tag}', but the generated qr_payload and displayed_context "
                    f"do not contain any corresponding anomaly ({', '.join(sorted(mapped_ids))})."
                ),
            })

    raw_expected = record.get("raw_expected_assessment") or record.get("expected_assessment")
    if isinstance(raw_expected, str):
        raw_expected = [raw_expected]
    elif isinstance(raw_expected, list):
        raw_expected = list(raw_expected)
    else:
        raw_expected = []

    reconciled_expected = _reconcile_expected_category(
        raw_expected,
        dec.level.value,
        key_indicators,
        expected_families,
        ctx.is_empty(),
    )

    observable_cues = {
        "encoded_payload_type": encoded_pt,
        "scenario_purpose": scenario_purpose,
        "is_http_payment_portal": is_http_payment_portal,
        "normalized_action": payload.action,
        "context_organization": ctx.get("organization").value if ctx.get("organization") else None,
        "context_purpose": ctx.get("purpose").value if ctx.get("purpose") else None,
        "context_amount": ctx.get("amount").value if ctx.get("amount") else None,
        "context_network": ctx.get("network").value if ctx.get("network") else None,
        "context_empty": ctx.is_empty(),
    }

    result: dict[str, Any] = {
        "encoded_payload_type": encoded_pt,
        "scenario_purpose": scenario_purpose,
        "is_http_payment_portal": is_http_payment_portal,
        "observable_cues": observable_cues,
        "key_indicators": key_indicators,
        "absent_indicators": absent_indicators,
        "expected_severities": expected_severities,
        "expected_evidence_families": expected_families,
        "expected_action_sensitivity": act.level.value,
        "policy_rule_trace": rule_code,
        "adjudicated_expected_level": dec.level.value,
        "tag_contradictions": tag_contradictions,
    }
    if raw_expected:
        result["raw_expected_assessment"] = raw_expected
        result["expected_assessment"] = reconciled_expected
    return result


def _refresh_sha256sums(dataset_root: Path) -> None:
    """Refresh metadata/artifact_hashes.jsonl and SHA256SUMS.txt for all tracked files in dataset_root."""
    ah_path = dataset_root / "metadata" / "artifact_hashes.jsonl"
    if ah_path.is_file():
        updated_lines: list[str] = []
        for line in ah_path.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            rel_p = str(rec.get("path") or "").replace("\\", "/")
            target = dataset_root / rel_p
            if target.is_file():
                rec["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
            updated_lines.append(json.dumps(rec, sort_keys=True))
        ah_path.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")

    sums_path = dataset_root / "SHA256SUMS.txt"
    if not sums_path.exists():
        return
    entries: list[str] = []
    for p in sorted(dataset_root.rglob("*")):
        if not p.is_file() or p.name == "SHA256SUMS.txt":
            continue
        rel = p.relative_to(dataset_root).as_posix()
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        entries.append(f"{digest}  {rel}")
    sums_path.write_text("\n".join(entries) + "\n", encoding="utf-8")


def enrich_dataset_scenarios(dataset_root: Path, reports_dir: Path | None = None) -> dict[str, Any]:
    """Enrich scenarios.jsonl, scenarios.csv, and metadata/ground_truth.jsonl with deterministic adjudication."""
    settings = Settings.from_env()
    settings.load_synthetic_reference = True
    settings.load_synthetic_reference = True
    reg = RuleRegistry(settings.rules_dir)
    ref = ReferenceData.load(settings.rules_dir, True)
    matcher = Matcher(ref)
    deps = Deps(reg, ref, matcher)
    consistency = ConsistencyEngine(deps)

    jsonl_path = dataset_root / "scenarios.jsonl"
    if not jsonl_path.exists():
        jsonl_path = dataset_root / "metadata" / "scenarios.jsonl"
    csv_path = dataset_root / "scenarios.csv"
    if not csv_path.exists():
        csv_path = dataset_root / "metadata" / "scenarios.csv"
    gt_jsonl_path = dataset_root / "metadata" / "ground_truth.jsonl"
    adjudication_json_path = dataset_root / "metadata" / "scenario_adjudication.json"

    records = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    enriched_records: list[dict[str, Any]] = []
    adjudicated_by_id: dict[str, dict[str, Any]] = {}
    csv_rows: list[dict[str, Any]] = []
    contradiction_count = 0
    http_payment_count = 0
    reconciled_category_count = 0

    for rec in records:
        adj = adjudicate_scenario_record(rec, deps, consistency)
        updated = dict(rec)
        updated.update(adj)
        if isinstance(updated.get("ground_truth_labels"), dict) and adj.get("expected_assessment"):
            gt_labels = dict(updated["ground_truth_labels"])
            if "raw_assessment" not in gt_labels and "assessment" in gt_labels:
                gt_labels["raw_assessment"] = gt_labels["assessment"]
            gt_labels["assessment"] = adj["expected_assessment"]
            updated["ground_truth_labels"] = gt_labels
        enriched_records.append(updated)
        sid = str(updated.get("scenario_id") or "")
        adjudicated_by_id[sid] = adj
        if adj["tag_contradictions"]:
            contradiction_count += 1
        if adj["is_http_payment_portal"]:
            http_payment_count += 1
        if adj.get("raw_expected_assessment") != adj.get("expected_assessment"):
            reconciled_category_count += 1
        csv_rows.append({
            "scenario_id": sid,
            "scenario_family": updated.get("scenario_family"),
            "encoded_payload_type": adj["encoded_payload_type"],
            "scenario_purpose": adj["scenario_purpose"],
            "is_http_payment_portal": adj["is_http_payment_portal"],
            "raw_expected_assessment_category": (adj.get("raw_expected_assessment") or [None])[0],
            "expected_assessment_category": (updated.get("expected_assessment") or [None])[0]
            if isinstance(updated.get("expected_assessment"), list)
            else updated.get("expected_assessment"),
            "adjudicated_expected_level": adj["adjudicated_expected_level"],
            "policy_rule_trace": adj["policy_rule_trace"],
            "expected_action_sensitivity": adj["expected_action_sensitivity"],
            "key_indicators": ";".join(adj["key_indicators"]),
            "expected_evidence_families": ";".join(adj["expected_evidence_families"]),
            "tag_contradictions": ";".join(c["tag"] for c in adj["tag_contradictions"]),
        })

    jsonl_path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in enriched_records) + "\n",
        encoding="utf-8",
    )

    if csv_path.exists():
        cols = list(dict.fromkeys(k for r in enriched_records for k in r))
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for r in enriched_records:
                flat = {
                    k: (json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v)
                    for k, v in r.items()
                }
                w.writerow(flat)

    if gt_jsonl_path.exists():
        gt_rows = [json.loads(line) for line in gt_jsonl_path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
        updated_gt = []
        for g in gt_rows:
            sid = str(g.get("scenario_id") or "")
            if sid in adjudicated_by_id:
                g = {**g, **adjudicated_by_id[sid]}
            updated_gt.append(g)
        gt_jsonl_path.write_text(
            "\n".join(json.dumps(g, ensure_ascii=False) for g in updated_gt) + "\n",
            encoding="utf-8",
        )

    summary = {
        "total_scenarios": len(enriched_records),
        "http_payment_portal_scenarios": http_payment_count,
        "scenarios_with_template_tag_contradictions": contradiction_count,
        "scenarios_with_reconciled_assessment_category": reconciled_category_count,
        "adjudicated_level_distribution": {
            lvl: sum(1 for r in enriched_records if r["adjudicated_expected_level"] == lvl)
            for lvl in ("no_material_concern", "needs_verification", "high_concern", "harmful_corroborated")
        },
        "policy_rule_distribution": {
            rule: sum(1 for r in enriched_records if r["policy_rule_trace"] == rule)
            for rule in sorted({r["policy_rule_trace"] for r in enriched_records})
        },
    }
    adjudication_json_path.parent.mkdir(parents=True, exist_ok=True)
    adjudication_json_path.write_text(json.dumps({"summary": summary, "scenarios": csv_rows}, indent=2), encoding="utf-8")

    if reports_dir is not None:
        reports_dir.mkdir(parents=True, exist_ok=True)
        out_csv = reports_dir / "scenario_adjudication_700.csv"
        with out_csv.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(csv_rows[0].keys()))
            w.writeheader()
            w.writerows(csv_rows)

    _refresh_sha256sums(dataset_root)
    return summary
