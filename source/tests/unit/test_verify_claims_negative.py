"""Negative unit tests for tools/verify_claims.py (DEF-A7).

Verifies that verify_claims.py detects and rejects:
1. Altered headline numbers in paper/claims.yaml vs release/evidence/metrics_master.json
2. Broken table totals / rates (k / N != pct%) in the manuscript
3. Uncovered result percentages in the manuscript
4. Broken or out-of-range bibliography citations ([99] or uncited bibitems)
5. Missing section/table anchor values in the assigned manuscript section/table
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import docx
import yaml

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import verify_claims  # noqa: E402


def _make_valid_fixture(tmp_path: Path):
    master = {
        "v1_locked": {"exact_acc": 0.9037},
        "full_locked": {"exact_acc": 0.9963},
    }
    master_path = tmp_path / "metrics_master.json"
    master_path.write_text(json.dumps(master), encoding="utf-8")

    claims_data = {
        "claims": [
            {
                "id": "C01",
                "description": "v1.0 exact accuracy",
                "metric_path": "v1_locked.exact_acc",
                "value": 0.9037,
                "tolerance": 0.0001,
                "anchor": "Table 1",
            },
            {
                "id": "C02",
                "description": "1.0 exact accuracy",
                "metric_path": "full_locked.exact_acc",
                "value": 0.9963,
                "tolerance": 0.0001,
                "anchor": "Section 5.2",
            },
        ]
    }
    claims_path = tmp_path / "claims.yaml"
    claims_path.write_text(yaml.safe_dump(claims_data), encoding="utf-8")

    ledger_path = tmp_path / "ledger.jsonl"
    ledger_path.write_text(json.dumps({"command": "pytest", "exit_code": 0}) + "\n", encoding="utf-8")

    tex_text = (
        "\\section{Introduction}\n"
        "We evaluate QRShield [1, 2].\n"
        "\\begin{table}\n"
        "\\caption{Summary}\n"
        "\\begin{tabular}{ll}\n"
        "\\textbf{Stratum} & \\textbf{Units} \\\\\n"
        "Core & 100 \\\\\n"
        "Trap & 50 \\\\\n"
        "\\textbf{Total} & 150 \\\\\n"
        "\\end{tabular}\n"
        "Locked accuracy reached 488 / 540 (90.37\\%).\n"
        "\\end{table}\n"
        "\\subsection{5.2 Locked Test Results}\n"
        "On 1.0, accuracy reached 1076 / 1080 (99.63\\%).\n"
        "\\begin{thebibliography}{99}\n"
        "\\bibitem{b1} First Reference.\n"
        "\\bibitem{b2} Second Reference.\n"
        "\\end{thebibliography}\n"
    )
    tex_path = tmp_path / "paper.tex"
    tex_path.write_text(tex_text, encoding="utf-8")

    docx_path = tmp_path / "paper.docx"
    d = docx.Document()
    d.add_paragraph("Locked accuracy reached 90.37% and 1.0 reached 99.63%.")
    d.save(str(docx_path))

    return claims_path, master_path, ledger_path, docx_path, tex_path


def test_verify_claims_passes_valid_fixture(tmp_path: Path):
    claims_path, master_path, ledger_path, docx_path, tex_path = _make_valid_fixture(tmp_path)
    rep = verify_claims.verify_paper_and_claims(claims_path, master_path, ledger_path, docx_path, tex_path)
    assert rep["status"] == "PASS", rep["errors"]
    assert rep["verified_claims"] == 2


def test_verify_claims_fails_on_altered_metric_value(tmp_path: Path):
    claims_path, master_path, ledger_path, docx_path, tex_path = _make_valid_fixture(tmp_path)
    master = json.loads(master_path.read_text(encoding="utf-8"))
    master["v1_locked"]["exact_acc"] = 0.8500
    master_path.write_text(json.dumps(master), encoding="utf-8")
    rep = verify_claims.verify_paper_and_claims(claims_path, master_path, ledger_path, docx_path, tex_path)
    assert rep["status"] == "FAIL"
    assert any("C01: Value mismatch" in e for e in rep["errors"])


def test_verify_claims_fails_on_broken_table_rate_and_sum(tmp_path: Path):
    claims_path, master_path, ledger_path, docx_path, tex_path = _make_valid_fixture(tmp_path)
    bad_tex = (
        tex_path.read_text(encoding="utf-8")
        .replace("488 / 540 (90.37\\%)", "488 / 540 (95.00\\%)")
        .replace("\\textbf{Total} & 150", "\\textbf{Total} & 999")
    )
    tex_path.write_text(bad_tex, encoding="utf-8")
    rep = verify_claims.verify_paper_and_claims(claims_path, master_path, ledger_path, docx_path, tex_path)
    assert rep["status"] == "FAIL"
    assert any("Rate mismatch" in e for e in rep["errors"])
    assert any("Table 1 Total sum mismatch" in e for e in rep["errors"])


def test_verify_claims_fails_on_uncovered_percentage_in_results(tmp_path: Path):
    claims_path, master_path, ledger_path, docx_path, tex_path = _make_valid_fixture(tmp_path)
    bad_tex = tex_path.read_text(encoding="utf-8").replace(
        "On 1.0, accuracy reached 1076 / 1080 (99.63\\%).",
        "On 1.0, accuracy reached 1076 / 1080 (99.63\\%) and unbacked score was 77.77\\%.",
    )
    tex_path.write_text(bad_tex, encoding="utf-8")
    rep = verify_claims.verify_paper_and_claims(claims_path, master_path, ledger_path, docx_path, tex_path)
    assert rep["status"] == "FAIL"
    assert any("Uncovered result percentage '77.77%'" in e for e in rep["errors"])


def test_verify_claims_fails_on_dangling_bibliography_citation(tmp_path: Path):
    claims_path, master_path, ledger_path, docx_path, tex_path = _make_valid_fixture(tmp_path)
    bad_tex = tex_path.read_text(encoding="utf-8").replace(
        "We evaluate QRShield [1, 2].",
        "We evaluate QRShield [1, 99].",
    )
    tex_path.write_text(bad_tex, encoding="utf-8")
    rep = verify_claims.verify_paper_and_claims(claims_path, master_path, ledger_path, docx_path, tex_path)
    assert rep["status"] == "FAIL"
    assert any("Citations in body missing from bibliography: [99]" in e for e in rep["errors"])
    assert any("Bibliography entries never cited in body: [2]" in e for e in rep["errors"])


def test_verify_claims_fails_on_missing_anchor_value(tmp_path: Path):
    claims_path, master_path, ledger_path, docx_path, tex_path = _make_valid_fixture(tmp_path)
    # Move 90.37% out of Table 1 into Introduction so the Table 1 anchor check fails
    bad_tex = (
        tex_path.read_text(encoding="utf-8")
        .replace("We evaluate QRShield [1, 2].", "We evaluate QRShield [1, 2] at 90.37\\%.")
        .replace("Locked accuracy reached 488 / 540 (90.37\\%).\n", "")
    )
    tex_path.write_text(bad_tex, encoding="utf-8")
    rep = verify_claims.verify_paper_and_claims(claims_path, master_path, ledger_path, docx_path, tex_path)
    assert rep["status"] == "FAIL"
    assert any("C01: Claim value 0.9037 not found in declared anchor 'Table 1'" in e for e in rep["errors"])
