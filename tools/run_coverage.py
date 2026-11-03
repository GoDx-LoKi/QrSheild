#!/usr/bin/env python3
"""Deterministic line and AST-branch coverage gate for qrshield_core (Phase 4, AC-3).

Uses Python's sys.settrace with selective frame filtering (tracing frames inside
source/qrshield_core/*.py) across the ENTIRE test suite (source/tests/) to measure
executable statement coverage across qrshield_core and branch decision outcome coverage
across analyzers/, context/, and decision/.
Never shadows host-installed packages (relies on source/sitecustomize.py to append
tools/offline_fallback to the end of sys.path only if pytest/qrcode are absent on the host).
Enforces:
  - >= 90.0% line coverage across qrshield_core
  - >= 80.0% branch coverage across analyzers/, context/, and decision/
"""
from __future__ import annotations

import ast
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


def get_executable_lines_and_branches(py_file: Path) -> tuple[set[int], set[int]]:
    """Return (executable_statement_lines, branch_condition_lines) via AST analysis."""
    source = py_file.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(py_file))
    lines = source.splitlines()

    exec_lines: set[int] = set()
    branch_lines: set[int] = set()

    docstring_lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str):
                doc_node = node.body[0]
                for ln in range(doc_node.lineno, (doc_node.end_lineno or doc_node.lineno) + 1):
                    docstring_lines.add(ln)

    statement_types = (
        ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Return, ast.Raise,
        ast.Assert, ast.Import, ast.ImportFrom, ast.Call, ast.If, ast.For,
        ast.While, ast.Try, ast.With, ast.Break, ast.Continue, ast.Pass,
        ast.FunctionDef, ast.ClassDef,
    )

    for node in ast.walk(tree):
        if isinstance(node, statement_types) and hasattr(node, "lineno"):
            ln = node.lineno
            if ln not in docstring_lines and 1 <= ln <= len(lines):
                stripped = lines[ln - 1].strip()
                if stripped and not stripped.startswith("#") and not stripped.startswith("@"):
                    exec_lines.add(ln)
        if isinstance(node, (ast.If, ast.While)) and hasattr(node, "lineno"):
            branch_lines.add(node.lineno)

    return exec_lines, branch_lines


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "source"))
    fallback = root / "tools" / "offline_fallback"
    if fallback.is_dir():
        if importlib.util.find_spec("pytest") is None or importlib.util.find_spec("qrcode") is None:
            if str(fallback) not in sys.path:
                sys.path.append(str(fallback))

    core_dir = (root / "source" / "qrshield_core").resolve()
    core_files = sorted(p.resolve() for p in core_dir.rglob("*.py"))
    core_file_strs: dict[str, Path] = {str(p): p for p in core_files}

    file_exec_lines: dict[Path, set[int]] = {}
    file_branch_lines: dict[Path, set[int]] = {}
    for f in core_files:
        el, bl = get_executable_lines_and_branches(f)
        file_exec_lines[f] = el
        file_branch_lines[f] = bl

    hit_lines: dict[Path, set[int]] = {f: set() for f in core_files}
    transitions: dict[Path, set[tuple[int, int]]] = {f: set() for f in core_files}
    prev_line_by_frame: dict[int, int] = {}

    def trace_func(frame: Any, event: str, arg: Any) -> Any:
        fname = frame.f_code.co_filename
        code_path = core_file_strs.get(fname)
        if code_path is None:
            return None
        if event == "line":
            lineno = frame.f_lineno
            hit_lines[code_path].add(lineno)
            fid = id(frame)
            prev = prev_line_by_frame.get(fid)
            if prev is not None:
                transitions[code_path].add((prev, lineno))
            prev_line_by_frame[fid] = lineno
        return trace_func

    import pytest as active_pytest

    test_targets = [
        str(root / "source" / "tests"),
        "-q",
    ]

    sys.settrace(trace_func)
    try:
        exit_code = active_pytest.main(test_targets)
    finally:
        sys.settrace(None)

    if exit_code != 0:
        print(f"Tests failed during coverage run with exit code {exit_code}", file=sys.stderr)
        return exit_code

    total_exec = 0
    total_hit = 0
    per_file_stats: dict[str, dict[str, Any]] = {}

    branch_subsystems = ("analyzers", "context", "decision")
    total_branch_points = 0
    covered_branch_points = 0

    for f in core_files:
        rel = str(f.relative_to(root))
        el = file_exec_lines[f]
        hl = el.intersection(hit_lines[f])
        total_exec += len(el)
        total_hit += len(hl)

        bl = file_branch_lines[f]
        trans = transitions[f]
        b_total = len(bl) * 2
        b_cov = 0
        for b in bl:
            succs = {dst for (src, dst) in trans if src == b and dst != b}
            if len(succs) >= 2:
                b_cov += 2
            elif b in hit_lines[f] or len(succs) == 1:
                b_cov += 1

        if any(f"qrshield_core/{sub}/" in rel for sub in branch_subsystems):
            total_branch_points += b_total
            covered_branch_points += b_cov

        missed = sorted(el - hl)
        per_file_stats[rel] = {
            "executable_lines": len(el),
            "hit_lines": len(hl),
            "line_coverage_pct": round(100.0 * len(hl) / len(el), 2) if el else 100.0,
            "branch_outcomes_total": b_total,
            "branch_outcomes_covered": b_cov,
            "branch_coverage_pct": round(100.0 * b_cov / b_total, 2) if b_total else 100.0,
            "missed_lines": missed[:30],
        }

    overall_line_pct = round(100.0 * total_hit / total_exec, 2) if total_exec else 100.0
    overall_branch_pct = round(100.0 * covered_branch_points / total_branch_points, 2) if total_branch_points else 100.0

    passed = overall_line_pct >= 90.0 and overall_branch_pct >= 80.0
    report = {
        "status": "PASS" if passed else "FAIL",
        "measurement_method": "ast_sys_settrace_coverage (tools/run_coverage.py)",
        "test_suite_scope": "source/tests (all test directories)",
        "overall_line_coverage_pct": overall_line_pct,
        "total_executable_lines": total_exec,
        "total_hit_lines": total_hit,
        "subsystem_branch_coverage_pct": overall_branch_pct,
        "subsystem_branch_outcomes_total": total_branch_points,
        "subsystem_branch_outcomes_covered": covered_branch_points,
        "thresholds": {
            "min_line_coverage_pct": 90.0,
            "min_branch_coverage_pct": 80.0,
        },
        "per_file": per_file_stats,
    }

    out_path = root / "release" / "evidence" / "coverage_summary.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "per_file"}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
