#!/usr/bin/env python3
"""Human annotation task exporter, full-schema ingestion pipeline, and IRR calculator (AC-5 / F-01).

Capabilities:
  1. Export blind annotation CSV tasks (1,280 image rows across all 1,080 units, including separate
     blind rows for both Image A and Image B of every counterfactual pair):
     python3 tools/ingest_annotations.py --export-blind-tasks \
       qrs_bench_ind/annotations/consensus_ground_truth.jsonl \
       annotations_kit/blind_tasks_v1_0.csv

  2. Ingest two completed human rater CSVs (and optional third-rater adjudication CSV), merge into
     the full benchmark ground-truth schema so the output JSONL is directly consumable by the
     benchmark evaluator, collect separate human labels for both images (A and B) in every
     counterfactual pair, and process/validate the counterfactual directional relation field:
     python3 tools/ingest_annotations.py --ingest \
       --base-gt qrs_bench_ind/annotations/consensus_ground_truth.jsonl \
       --rater1 rater1.csv --rater2 rater2.csv [--adjudicator adj.csv] \
       --out qrs_bench_ind/annotations/human_consensus_ground_truth.jsonl \
       --report release/evidence/human_irr_report.json
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASE_GT = ROOT / "qrs_bench_ind" / "annotations" / "consensus_ground_truth.jsonl"

LEVELS = ["no_material_concern", "needs_verification", "high_concern", "harmful_corroborated"]
LEVEL_IDX = {lvl: i for i, lvl in enumerate(LEVELS)}

VALID_RELATIONS = {
    "Risk(B) > Risk(A)",
    "Risk(B) == Risk(A)",
    "Risk(B) < Risk(A)",
}


def derive_relation(level_a: str, level_b: str) -> str:
    """Derive the ordinal risk relation between Image A and Image B."""
    ia, ib = LEVEL_IDX[level_a], LEVEL_IDX[level_b]
    if ib > ia:
        return "Risk(B) > Risk(A)"
    if ib == ia:
        return "Risk(B) == Risk(A)"
    return "Risk(B) < Risk(A)"


def cohen_kappa(y1: list[str], y2: list[str], categories: list[str] | None = None) -> tuple[float, float]:
    cats = categories or LEVELS
    cat_idx = {c: i for i, c in enumerate(cats)}
    n = len(y1)
    k = len(cats)
    if n == 0:
        return 0.0, 0.0
    mat = np.zeros((k, k), dtype=np.float64)
    for a, b in zip(y1, y2):
        mat[cat_idx[a], cat_idx[b]] += 1.0
    mat /= n
    r = mat.sum(axis=1)
    c = mat.sum(axis=0)
    pe = float(np.sum(r * c))
    po = float(np.trace(mat))
    unw = 1.0 if abs(1.0 - pe) < 1e-12 else (po - pe) / (1.0 - pe)

    w = np.zeros((k, k), dtype=np.float64)
    denom = max(1, (k - 1) ** 2)
    for i in range(k):
        for j in range(k):
            w[i, j] = ((i - j) ** 2) / denom
    po_w = float(np.sum(w * mat))
    pe_w = float(np.sum(w * np.outer(r, c)))
    qw = 1.0 if abs(pe_w) < 1e-12 else 1.0 - (po_w / pe_w)
    return round(unw, 4), round(qw, 4)


def bootstrap_kappa_ci(y1: list[str], y2: list[str], n_boot: int = 2000, seed: int = 20261101) -> dict[str, list[float]]:
    if not y1:
        return {"unweighted_ci95": [0.0, 0.0], "quadratic_weighted_ci95": [0.0, 0.0]}
    rng = np.random.default_rng(seed)
    n = len(y1)
    unw_s, qw_s = [], []
    for _ in range(n_boot):
        idx = rng.integers(0, n, size=n)
        b1 = [y1[i] for i in idx]
        b2 = [y2[i] for i in idx]
        u, q = cohen_kappa(b1, b2)
        unw_s.append(u)
        qw_s.append(q)
    return {
        "unweighted_ci95": [round(float(np.percentile(unw_s, 2.5)), 4), round(float(np.percentile(unw_s, 97.5)), 4)],
        "quadratic_weighted_ci95": [round(float(np.percentile(qw_s, 2.5)), 4), round(float(np.percentile(qw_s, 97.5)), 4)],
    }


def export_blind_tasks(gt_jsonl: Path, out_csv: Path) -> None:
    """Export 1,280 blind annotation task rows (including separate A and B rows for counterfactual pairs)."""
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, str]] = []
    for line in gt_jsonl.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        uid = rec["unit_id"]
        if rec.get("stratum") == "counterfactual_pairs" or ("rel_path_a" in rec and "rel_path_b" in rec):
            rows.append({
                "task_id": f"{uid}__A",
                "unit_id": uid,
                "pair_side": "A",
                "split": rec["split"],
                "stratum": rec["stratum"],
                "category": rec["category"],
                "image_path": rec["rel_path_a"],
                "pair_reference_image_path": rec["rel_path_b"],
                "rater_id": "",
                "assigned_level_L0_to_L3": "",
                "directional_relation_vs_A": "",
                "confidence_1_to_5": "",
                "notes": "",
            })
            rows.append({
                "task_id": f"{uid}__B",
                "unit_id": uid,
                "pair_side": "B",
                "split": rec["split"],
                "stratum": rec["stratum"],
                "category": rec["category"],
                "image_path": rec["rel_path_b"],
                "pair_reference_image_path": rec["rel_path_a"],
                "rater_id": "",
                "assigned_level_L0_to_L3": "",
                "directional_relation_vs_A": "",
                "confidence_1_to_5": "",
                "notes": "",
            })
        else:
            rows.append({
                "task_id": uid,
                "unit_id": uid,
                "pair_side": "",
                "split": rec["split"],
                "stratum": rec["stratum"],
                "category": rec["category"],
                "image_path": rec.get("rel_path", ""),
                "pair_reference_image_path": "",
                "rater_id": "",
                "assigned_level_L0_to_L3": "",
                "directional_relation_vs_A": "",
                "confidence_1_to_5": "",
                "notes": "",
            })
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Exported {len(rows)} blind annotation image tasks to {out_csv}")


def _adjudicate_level(l1: str, l2: str, adj_val: str | None) -> tuple[str, list[str], str, bool]:
    """Return (consensus_level, accepted_set, adjudication_method, disagreed)."""
    if l1 == l2:
        return l1, [l1], "human_unanimous", False
    if adj_val and adj_val in LEVEL_IDX:
        accepted = sorted({l1, l2, adj_val}, key=lambda x: LEVEL_IDX[x]) if abs(LEVEL_IDX[l1] - LEVEL_IDX[l2]) == 1 else [adj_val]
        return adj_val, accepted, "human_third_rater_adjudicated", True
    consensus = LEVELS[max(LEVEL_IDX[l1], LEVEL_IDX[l2])]
    accepted = sorted({l1, l2}, key=lambda x: LEVEL_IDX[x]) if abs(LEVEL_IDX[l1] - LEVEL_IDX[l2]) == 1 else [consensus]
    return consensus, accepted, "conservative_higher_risk_tiebreak", True


def _resolve_rater_relation(row_a: dict[str, str], row_b: dict[str, str], la: str, lb: str, uid: str, rater_tag: str) -> tuple[str | None, str | None]:
    """Validate or derive directional_relation_vs_A from a rater's A and B rows."""
    implied = derive_relation(la, lb)
    explicit = (row_b.get("directional_relation_vs_A") or row_a.get("directional_relation_vs_A") or "").strip()
    if not explicit:
        return implied, None
    if explicit not in VALID_RELATIONS:
        return None, f"ERROR: Invalid directional_relation_vs_A for {uid} ({rater_tag}): {explicit!r}"
    if explicit != implied:
        return None, (
            f"ERROR: Contradictory directional_relation_vs_A for {uid} ({rater_tag}): "
            f"stated {explicit!r} but assigned A={la!r}, B={lb!r} (implies {implied!r})"
        )
    return explicit, None


def ingest_human_csvs(
    r1_csv: Path,
    r2_csv: Path,
    adj_csv: Path | None,
    out_jsonl: Path,
    report_json: Path,
    base_gt_jsonl: Path | None = None,
) -> int:
    def read_task_map(p: Path) -> dict[str, dict[str, str]]:
        with p.open("r", encoding="utf-8") as f:
            out: dict[str, dict[str, str]] = {}
            for row in csv.DictReader(f):
                tid = (row.get("task_id") or "").strip()
                uid = (row.get("unit_id") or "").strip()
                side = (row.get("pair_side") or "").strip().upper()
                key = tid if tid else (f"{uid}__{side}" if side in ("A", "B") else uid)
                out[key] = row
            return out

    r1_map = read_task_map(r1_csv)
    r2_map = read_task_map(r2_csv)
    adj_map = read_task_map(adj_csv) if adj_csv and adj_csv.exists() else {}

    gt_source = base_gt_jsonl if (base_gt_jsonl and base_gt_jsonl.exists()) else DEFAULT_BASE_GT
    base_units: dict[str, dict[str, Any]] = {}
    ordered_uids: list[str] = []
    if gt_source.exists():
        for line in gt_source.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            uid = rec["unit_id"]
            base_units[uid] = rec
            ordered_uids.append(uid)

    # Determine candidate unit_ids present in both rater CSVs
    def extract_unit_ids(tmap: dict[str, dict[str, str]]) -> set[str]:
        uids: set[str] = set()
        for k, row in tmap.items():
            u = (row.get("unit_id") or "").strip()
            if u:
                uids.add(u)
            elif k.endswith("__A") or k.endswith("__B"):
                uids.add(k[:-3])
            else:
                uids.add(k)
        return uids

    common_uids_set = extract_unit_ids(r1_map) & extract_unit_ids(r2_map)
    if not common_uids_set:
        print("ERROR: No matching unit_ids between rater1 and rater2 CSVs", file=sys.stderr)
        return 1

    if ordered_uids:
        common_uids = [u for u in ordered_uids if u in common_uids_set]
        for u in sorted(common_uids_set - set(common_uids)):
            common_uids.append(u)
    else:
        common_uids = sorted(common_uids_set)

    y1_images: list[str] = []
    y2_images: list[str] = []
    y1_relations: list[str] = []
    y2_relations: list[str] = []
    records: list[dict[str, Any]] = []
    image_disagreements = 0
    relation_disagreements = 0

    for uid in common_uids:
        base_rec = dict(base_units.get(uid, {"unit_id": uid}))
        is_pair = (
            base_rec.get("stratum") == "counterfactual_pairs"
            or f"{uid}__A" in r1_map
            or f"{uid}__B" in r1_map
        )

        if is_pair:
            k_a, k_b = f"{uid}__A", f"{uid}__B"
            if k_a not in r1_map or k_b not in r1_map or k_a not in r2_map or k_b not in r2_map:
                print(
                    f"ERROR: Counterfactual pair {uid} requires separate human ratings for both "
                    f"{k_a} (Image A) and {k_b} (Image B) in rater1 and rater2 CSVs.",
                    file=sys.stderr,
                )
                return 1

            r1_a = r1_map[k_a]["assigned_level_L0_to_L3"].strip()
            r1_b = r1_map[k_b]["assigned_level_L0_to_L3"].strip()
            r2_a = r2_map[k_a]["assigned_level_L0_to_L3"].strip()
            r2_b = r2_map[k_b]["assigned_level_L0_to_L3"].strip()

            for tag, val in [("rater1_A", r1_a), ("rater1_B", r1_b), ("rater2_A", r2_a), ("rater2_B", r2_b)]:
                if val not in LEVEL_IDX:
                    print(f"ERROR: Invalid label for {uid} ({tag}): {val!r}", file=sys.stderr)
                    return 1

            rel1, err1 = _resolve_rater_relation(r1_map[k_a], r1_map[k_b], r1_a, r1_b, uid, "rater1")
            rel2, err2 = _resolve_rater_relation(r2_map[k_a], r2_map[k_b], r2_a, r2_b, uid, "rater2")
            if err1 or err2:
                print(err1 or err2, file=sys.stderr)
                return 1
            assert rel1 is not None and rel2 is not None

            adj_a = adj_map[k_a]["assigned_level_L0_to_L3"].strip() if k_a in adj_map else None
            adj_b = adj_map[k_b]["assigned_level_L0_to_L3"].strip() if k_b in adj_map else None

            cons_a, _, method_a, dis_a = _adjudicate_level(r1_a, r2_a, adj_a)
            cons_b, acc_b, method_b, dis_b = _adjudicate_level(r1_b, r2_b, adj_b)
            image_disagreements += int(dis_a) + int(dis_b)

            y1_images.extend([r1_a, r1_b])
            y2_images.extend([r2_a, r2_b])
            y1_relations.append(rel1)
            y2_relations.append(rel2)

            derived_cons_rel = derive_relation(cons_a, cons_b)
            adj_rel_explicit = ""
            if k_b in adj_map:
                adj_rel_explicit = (adj_map[k_b].get("directional_relation_vs_A") or "").strip()
            elif k_a in adj_map:
                adj_rel_explicit = (adj_map[k_a].get("directional_relation_vs_A") or "").strip()

            if rel1 == rel2:
                cons_rel = rel1
                rel_method = "human_unanimous"
            else:
                relation_disagreements += 1
                if adj_rel_explicit in VALID_RELATIONS:
                    if adj_rel_explicit != derived_cons_rel:
                        print(
                            f"ERROR: Adjudicator relation {adj_rel_explicit!r} for {uid} contradicts "
                            f"adjudicated labels A={cons_a!r}, B={cons_b!r} ({derived_cons_rel!r})",
                            file=sys.stderr,
                        )
                        return 1
                    cons_rel = adj_rel_explicit
                    rel_method = "human_third_rater_adjudicated"
                else:
                    cons_rel = derived_cons_rel
                    rel_method = "derived_from_adjudicated_pair_levels"

            base_rec.update({
                "consensus_ground_truth_a": cons_a,
                "consensus_ground_truth": cons_b,
                "accepted_ground_truth_set": acc_b,
                "expected_relation": cons_rel,
                "rater_1_label_a": r1_a,
                "rater_2_label_a": r2_a,
                "adjudication_method_a": method_a,
                "rater_1_label": r1_b,
                "rater_2_label": r2_b,
                "adjudication_method": method_b,
                "rater_1_relation": rel1,
                "rater_2_relation": rel2,
                "relation_adjudication_method": rel_method,
                "provenance": "human",
                "provenance_note": "Labels and counterfactual relations assigned by dual blind human raters with adjudication.",
            })
            records.append(base_rec)
        else:
            l1 = r1_map[uid]["assigned_level_L0_to_L3"].strip()
            l2 = r2_map[uid]["assigned_level_L0_to_L3"].strip()
            if l1 not in LEVEL_IDX or l2 not in LEVEL_IDX:
                print(f"ERROR: Invalid label for {uid}: rater1={l1!r}, rater2={l2!r}", file=sys.stderr)
                return 1
            y1_images.append(l1)
            y2_images.append(l2)
            adj_val = adj_map[uid]["assigned_level_L0_to_L3"].strip() if uid in adj_map else None
            consensus, accepted, method, disagreed = _adjudicate_level(l1, l2, adj_val)
            image_disagreements += int(disagreed)

            base_rec.update({
                "consensus_ground_truth": consensus,
                "accepted_ground_truth_set": accepted,
                "rater_1_label": l1,
                "rater_2_label": l2,
                "adjudication_method": method,
                "provenance": "human",
                "provenance_note": "Labels assigned by dual blind human raters with adjudication.",
            })
            records.append(base_rec)

    unw, qw = cohen_kappa(y1_images, y2_images)
    cis = bootstrap_kappa_ci(y1_images, y2_images)

    rel_cats = ["Risk(B) < Risk(A)", "Risk(B) == Risk(A)", "Risk(B) > Risk(A)"]
    rel_unw, _ = cohen_kappa(y1_relations, y2_relations, categories=rel_cats) if y1_relations else (0.0, 0.0)

    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    out_jsonl.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

    n_imgs = len(y1_images)
    n_pairs = len(y1_relations)
    rep: dict[str, Any] = {
        "provenance": "human",
        "n_units": len(common_uids),
        "n_images_rated": n_imgs,
        "n_counterfactual_pairs_rated": n_pairs,
        "disagreements": image_disagreements,
        "exact_agreement": round(1.0 - (image_disagreements / max(1, n_imgs)), 4),
        "cohen_kappa_unweighted": unw,
        "cohen_kappa_quadratic_weighted": qw,
        **cis,
        "counterfactual_relation_agreement": {
            "n_pairs": n_pairs,
            "relation_disagreements": relation_disagreements,
            "relation_exact_agreement": round(1.0 - (relation_disagreements / max(1, n_pairs)), 4) if n_pairs else 1.0,
            "relation_cohen_kappa_unweighted": rel_unw,
        },
    }
    report_json.parent.mkdir(parents=True, exist_ok=True)
    report_json.write_text(json.dumps(rep, indent=2), encoding="utf-8")
    print(json.dumps(rep, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Export blind annotation tasks or ingest human rater CSVs")
    parser.add_argument("--export-blind-tasks", nargs=2, metavar=("GT_JSONL", "OUT_CSV"))
    parser.add_argument("--ingest", action="store_true")
    parser.add_argument("--base-gt", type=Path, default=DEFAULT_BASE_GT, help="Base ground-truth JSONL to merge full unit metadata from")
    parser.add_argument("--rater1", type=Path)
    parser.add_argument("--rater2", type=Path)
    parser.add_argument("--adjudicator", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=Path("annotations_human.jsonl"))
    parser.add_argument("--report", type=Path, default=Path("irr_report.json"))
    args = parser.parse_args()

    if args.export_blind_tasks:
        export_blind_tasks(Path(args.export_blind_tasks[0]), Path(args.export_blind_tasks[1]))
        return 0
    if args.ingest:
        if not args.rater1 or not args.rater2:
            parser.error("--ingest requires --rater1 and --rater2")
        return ingest_human_csvs(
            args.rater1,
            args.rater2,
            args.adjudicator,
            args.out,
            args.report,
            base_gt_jsonl=args.base_gt,
        )
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
