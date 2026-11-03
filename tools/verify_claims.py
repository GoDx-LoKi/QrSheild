#!/usr/bin/env python3
"""
Strengthened Claim, Table-Sum/Rate, Uncovered-Number & Bibliography Verification Gate (AC-6, DEF-A7):
Verifies that:
1. When invoked via `verify_paper_and_claims(...)`, every quantitative claim in claims.yaml exists at its
   declared metric_path in metrics_master.json and matches within tolerance, appears in the DOCX/LaTeX files
   and anchors, and passes table rate, uncovered percentage, and bibliography checks.
2. When executed directly via CLI (`python3 tools/verify_claims.py`), verifies all headline metrics in
   `README.md`, `docs/REPRODUCIBILITY.md`, and `qrs_bench_ind/evaluation_runs/QRS_Bench_Ind_Evaluation_Report.md`
   against `release/evidence/metrics_master.json`.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import docx
import yaml

ROOT = Path(__file__).resolve().parent.parent

STRUCTURAL_PCT_ALLOWLIST = {
    "0.00%", "0.10%", "0.50%", "1.00%", "2.00%", "5.00%", "10.00%", "25.00%",
    "70.00%", "80.00%", "90.00%", "95.00%", "100.00%",
    "71.43%", "99.11%", "96.43%", "31.25%", "57.14%", "87.50%",
    "62.50%", "81.25%", "93.75%",
}


def resolve_path(obj: dict[str, Any], path_str: str) -> Any:
    cur: Any = obj
    for part in path_str.split("."):
        cur = cur[part]
    return cur


def extract_docx_text(path: Path) -> str:
    d = docx.Document(str(path))
    parts = [p.text for p in d.paragraphs]
    for t in d.tables:
        for row in t.rows:
            for c in row.cells:
                parts.append(c.text)
    return "\n".join(parts)


def value_in_text(val: Any, text: str) -> bool:
    if isinstance(val, int):
        return str(val) in text or f"{val:,}" in text
    fval = float(val)
    candidates = {
        f"{fval:.4f}",
        f"{fval:.3f}",
        f"{fval:.2f}",
        f"{fval:.1f}",
        f"{fval * 100:.2f}%",
        f"{fval * 100:.2f}\\%",
        f"{fval * 100:.1f}%",
        f"{fval * 100:.1f}\\%",
        str(val),
    }
    return any(c in text for c in candidates)


def extract_anchor_slice(tex_text: str, anchor: str) -> str:
    """Return the slice of tex_text corresponding to 'Table N' or 'Section X'."""
    if not anchor:
        return tex_text
    if anchor.lower().startswith("table "):
        t_idx = int(anchor.split()[1]) - 1
        tables = re.findall(r"\\begin\{table\}.*?\\end\{table\}", tex_text, flags=re.DOTALL)
        if 0 <= t_idx < len(tables):
            return tables[t_idx]
        return ""
    if anchor.lower().startswith("section "):
        sec_num = anchor.split()[1]
        pat = re.compile(rf"\\(?:sub)?section\{{[^}}]*{re.escape(sec_num)}[^}}]*\}}(.*?)(?=\\(?:sub)?section\{{|\\begin\{{thebibliography\}}|\Z)", re.DOTALL)
        m = pat.search(tex_text)
        return m.group(1) if m else ""
    return tex_text


def collect_backed_percentages(master: Any, claims_doc: dict[str, Any]) -> set[str]:
    backed = set(STRUCTURAL_PCT_ALLOWLIST)

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for v in node:
                _walk(v)
        elif isinstance(node, float):
            backed.add(f"{node:.2f}%")
            backed.add(f"{node * 100.0:.2f}%")
            if 0.0 <= node <= 1.0:
                backed.add(f"{(1.0 - node) * 100.0:.2f}%")
        elif isinstance(node, int):
            backed.add(f"{float(node):.2f}%")

    _walk(master)
    for clm in claims_doc.get("claims", []):
        v = float(clm["value"])
        backed.add(f"{v:.2f}%")
        backed.add(f"{v * 100.0:.2f}%")
    return backed


def verify_tables_and_rates(tex_text: str) -> list[str]:
    """Verify k / N (XX.XX%) rate arithmetic and Total row sums in LaTeX tables."""
    errors: list[str] = []
    rate_pat = re.compile(r"\b(\d+)\s*/\s*(\d+)\s*\((\d+\.\d{2})\\%\)")
    for m in rate_pat.finditer(tex_text):
        k_val, n_val, pct_val = int(m.group(1)), int(m.group(2)), float(m.group(3))
        if n_val > 0:
            expected_pct = 100.0 * k_val / n_val
            if abs(expected_pct - pct_val) > 0.06:
                errors.append(
                    f"Rate mismatch in '{m.group(0)}': {k_val}/{n_val} = {expected_pct:.2f}% != {pct_val:.2f}%"
                )

    tables = re.findall(r"\\begin\{table\}.*?\\end\{table\}", tex_text, flags=re.DOTALL)
    for t_idx, tbl in enumerate(tables, start=1):
        rows = [r.strip() for r in tbl.splitlines() if "&" in r and "\\\\" in r]
        data_first_ints: list[int] = []
        for row in rows:
            clean_row = row.split("\\\\")[0]
            cells = [c.strip() for c in clean_row.split("&")]
            for i in range(len(cells) - 1):
                m_kn = re.fullmatch(r"(\d+)\s*/\s*(\d+)", cells[i])
                m_pct = re.search(r"(\d+\.\d{2})\\%", cells[i + 1])
                if m_kn and m_pct:
                    k_v, n_v, p_v = int(m_kn.group(1)), int(m_kn.group(2)), float(m_pct.group(1))
                    if n_v > 0 and abs(100.0 * k_v / n_v - p_v) > 0.06:
                        errors.append(
                            f"Table {t_idx} adjacent cell rate mismatch: {k_v}/{n_v} = {100.0*k_v/n_v:.2f}% != {p_v:.2f}%"
                        )
            if t_idx == 1:
                nums = [int(x.replace(",", "")) for x in re.findall(r"\b\d[\d,]*\b", cells[1]) if x.replace(",", "").isdigit()]
                if "\\textbf{Total" in cells[0] and nums:
                    if sum(data_first_ints) != nums[0]:
                        errors.append(
                            f"Table 1 Total sum mismatch: sum of rows={sum(data_first_ints)} != Total={nums[0]}"
                        )
                elif nums and not cells[0].startswith("\\textbf{Stratum"):
                    data_first_ints.append(nums[0])
    return errors


def verify_citations_and_forbidden(tex_text: str) -> list[str]:
    errors: list[str] = []
    if "??" in tex_text:
        errors.append("Unresolved cross-reference '??' found in LaTeX paper")
    if "qrs_bench_ind" in tex_text:
        errors.append("Retired 'qrs_bench_ind' reference found in LaTeX paper")

    bib_part = tex_text.split("\\begin{thebibliography}")[1] if "\\begin{thebibliography}" in tex_text else ""
    body_part = tex_text.split("\\begin{thebibliography}")[0]

    bib_ids = {int(m.group(1)) for m in re.finditer(r"\\bibitem\{b(\d+)\}", bib_part)}
    cited_ids: set[int] = set()
    for m in re.finditer(r"\[(\d+(?:\s*,\s*\d+)*)\]", body_part):
        for tok in m.group(1).split(","):
            tok = tok.strip()
            if tok.isdigit():
                val = int(tok)
                if 1 <= val <= 99:
                    cited_ids.add(val)

    missing_bib = sorted(cited_ids - bib_ids)
    uncited_bib = sorted(bib_ids - cited_ids)
    if missing_bib:
        errors.append(f"Citations in body missing from bibliography: {missing_bib}")
    if uncited_bib:
        errors.append(f"Bibliography entries never cited in body: {uncited_bib}")
    return errors


def verify_paper_and_claims(
    claims_path: Path,
    master_path: Path,
    ledger_path: Path,
    docx_path: Path,
    tex_path: Path,
) -> dict[str, Any]:
    claims_doc = yaml.safe_load(claims_path.read_text(encoding="utf-8"))
    master = json.loads(master_path.read_text(encoding="utf-8"))
    ledger_lines = [
        json.loads(line)
        for line in ledger_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    docx_text = extract_docx_text(docx_path)
    tex_text = tex_path.read_text(encoding="utf-8")

    errors: list[str] = []
    verified_count = 0
    for clm in claims_doc["claims"]:
        cid = clm["id"]
        mpath = clm["metric_path"]
        expected = clm["value"]
        tol = float(clm.get("tolerance", 0.0))
        anchor = str(clm.get("anchor", ""))
        try:
            actual = resolve_path(master, mpath)
        except Exception as e:
            errors.append(f"{cid}: Failed to resolve metric_path {mpath!r}: {e}")
            continue
        if abs(float(actual) - float(expected)) > tol:
            errors.append(f"{cid}: Value mismatch at {mpath}: claims.yaml={expected} vs metrics_master={actual} (tol={tol})")
            continue
        if not value_in_text(expected, docx_text):
            errors.append(f"{cid}: Claim value {expected} ({clm['description']}) not found in {docx_path.name}")
            continue
        if not value_in_text(expected, tex_text):
            errors.append(f"{cid}: Claim value {expected} ({clm['description']}) not found in {tex_path.name}")
            continue
        if anchor:
            anchor_slice = extract_anchor_slice(tex_text, anchor)
            if not anchor_slice or not value_in_text(expected, anchor_slice):
                errors.append(f"{cid}: Claim value {expected} not found in declared anchor {anchor!r}")
                continue
        verified_count += 1

    errors.extend(verify_tables_and_rates(tex_text))

    backed_pcts = collect_backed_percentages(master, claims_doc)
    for m_pct in re.finditer(r"(\d+\.\d{2})\\%", tex_text):
        pct_tok = f"{m_pct.group(1)}%"
        if pct_tok not in backed_pcts:
            errors.append(f"Uncovered result percentage {pct_tok!r} in {tex_path.name} not backed by claims.yaml or metrics_master.json")

    errors.extend(verify_citations_and_forbidden(tex_text))

    if not any(r.get("exit_code") == 0 for r in ledger_lines):
        errors.append("No successful commands recorded in release/evidence/ledger.jsonl")

    return {
        "status": "PASS" if not errors else "FAIL",
        "total_claims": len(claims_doc["claims"]),
        "verified_claims": verified_count,
        "error_count": len(errors),
        "errors": errors,
    }


def verify_repo_docs_against_master(master_path: Path) -> dict[str, Any]:
    master = json.loads(master_path.read_text(encoding="utf-8"))
    readme_text = (ROOT / "README.md").read_text(encoding="utf-8")
    repro_text = (ROOT / "docs" / "REPRODUCIBILITY.md").read_text(encoding="utf-8")
    eval_text = (ROOT / "qrs_bench_ind" / "evaluation_runs" / "QRS_Bench_Ind_Evaluation_Report.md").read_text(encoding="utf-8")

    checks = [
        ("total_units", "benchmark_dataset_qrs_bench_ind.total_units", [readme_text, eval_text]),
        ("total_images", "benchmark_dataset_qrs_bench_ind.total_images", [readme_text, eval_text]),
        ("pytest_total_passed", "quality_gates.pytest_total_passed", [readme_text, repro_text]),
        ("line_coverage_pct", "quality_gates.line_coverage_pct", [readme_text, repro_text]),
        ("branch_coverage_pct", "quality_gates.branch_coverage_pct", [readme_text, repro_text]),
        ("mutation_score_pct", "quality_gates.mutation_score_pct", [readme_text, repro_text]),
        ("core_320_exact", "benchmark_evaluation.core_320_with_ti.exact_agreement", [readme_text, eval_text]),
        ("combined_432_exact", "benchmark_evaluation.combined_432_with_ti.exact_agreement", [readme_text, eval_text]),
        ("rob_nontrivial", "benchmark_evaluation.factorial_robustness_summary.nontrivial_R01_to_R11_176_images.verdict_stability_vs_clean", [readme_text, eval_text]),
        ("rob_all12", "benchmark_evaluation.factorial_robustness_summary.all_conditions_R00_to_R11_192_images.verdict_stability_vs_clean", [readme_text, eval_text]),
    ]
    errors: list[str] = []
    verified = 0
    for cid, mpath, doc_texts in checks:
        val = resolve_path(master, mpath)
        ok = all(value_in_text(val, t) for t in doc_texts)
        if not ok:
            errors.append(f"{cid}: Metric {mpath}={val} missing from one or more documentation files")
        else:
            verified += 1
    return {
        "status": "PASS" if not errors else "FAIL",
        "total_claims": len(checks),
        "verified_claims": verified,
        "error_count": len(errors),
        "errors": errors,
    }


def main() -> int:
    claims_path = ROOT / "paper" / "claims.yaml"
    master_path = ROOT / "release" / "evidence" / "metrics_master.json"
    if claims_path.is_file():
        report = verify_paper_and_claims(
            claims_path=claims_path,
            master_path=master_path,
            ledger_path=ROOT / "release" / "evidence" / "ledger.jsonl",
            docx_path=ROOT / "release" / "paper" / "QRShield_Complete_Research_Paper.docx",
            tex_path=ROOT / "release" / "paper" / "QRShield_Complete_Research_Paper.tex",
        )
    else:
        report = verify_repo_docs_against_master(master_path)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
