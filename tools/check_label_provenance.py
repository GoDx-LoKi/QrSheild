#!/usr/bin/env python3
"""Provenance gate:
Verifies that:
1. Every annotation record in qrs_bench_ind/annotations/consensus_ground_truth.jsonl
   carries an explicit 'provenance' field in {'author_assigned', 'human'}.
2. No synthetic rater files (rater_1_blind.jsonl, rater_2_blind.jsonl) or synthesize_dual_raters()
   function exist anywhere in the repository, and no duplicate/retired dataset directories exist.
3. If annotation provenance is 'author_assigned', no benchmark report or documentation file
   claims human inter-rater kappa (e.g., '0.9450', '0.9804', 'two blinded security raters',
   'third-rater adjudication') as an empirical result.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_SYNTHETIC_RATER_PATTERNS = [
    r"synthesize_dual_raters",
    r"0\.9450",
    r"0\.9804",
    r"two\s+blinded\s+security\s+raters",
    r"blind\s+dual-rater\s+consensus",
]


def check_annotations_jsonl(path: Path) -> tuple[int, set[str], list[str]]:
    errors: list[str] = []
    provenances: set[str] = set()
    count = 0
    if not path.exists():
        return 0, set(), [f"Missing required annotation file: {path.relative_to(ROOT)}"]
    for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        count += 1
        rec = json.loads(line)
        prov = rec.get("provenance")
        if prov not in ("author_assigned", "human"):
            errors.append(f"{path.relative_to(ROOT)}:{idx} invalid or missing provenance={prov!r}")
        else:
            provenances.add(prov)
        if prov == "author_assigned":
            if "rater_1_label" in rec or "rater_2_label" in rec:
                errors.append(f"{path.relative_to(ROOT)}:{idx} author_assigned record contains synthetic rater_1/rater_2 fields")
    return count, provenances, errors


def main() -> int:
    errors: list[str] = []

    for rel in [
        "qrs_bench_ind/annotations/rater_1_blind.jsonl",
        "qrs_bench_ind/annotations/rater_2_blind.jsonl",
        "qrs_bench_ind_v1",
        "qrs_bench_ind_v1_1",
        "source/qrshield_research_dataset",
        "source/evaluation/qrs_bench_ind.py",
    ]:
        p = ROOT / rel
        if p.exists():
            errors.append(f"Forbidden or retired path still exists: {rel}")

    ann_files = [
        ROOT / "qrs_bench_ind" / "annotations" / "consensus_ground_truth.jsonl",
    ]

    all_provs: set[str] = set()
    summary_counts: dict[str, int] = {}
    for af in ann_files:
        cnt, provs, errs = check_annotations_jsonl(af)
        summary_counts[str(af.relative_to(ROOT))] = cnt
        all_provs |= provs
        errors.extend(errs)

    scan_targets = [
        ROOT / "build_and_evaluate_qrs_bench_ind.py",
        ROOT / "qrs_bench_ind" / "evaluation_runs" / "benchmark_metrics_report.json",
    ]
    rep_md = ROOT / "qrs_bench_ind" / "evaluation_runs" / "QRS_Bench_Ind_Evaluation_Report.md"
    if rep_md.exists():
        scan_targets.append(rep_md)

    has_human_prov = "human" in all_provs
    for target in scan_targets:
        text = target.read_text(encoding="utf-8", errors="replace")
        for pat in FORBIDDEN_SYNTHETIC_RATER_PATTERNS:
            if not has_human_prov and re.search(pat, text, flags=re.IGNORECASE):
                errors.append(
                    f"Provenance violation in {target.relative_to(ROOT)}: found forbidden pattern {pat!r} while provenance={sorted(all_provs)}"
                )

    result = {
        "status": "PASS" if not errors else "FAIL",
        "checked_annotation_files": summary_counts,
        "detected_provenances": sorted(all_provs),
        "error_count": len(errors),
        "errors": errors,
    }
    out_path = ROOT / "release" / "evidence" / "provenance_audit.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
