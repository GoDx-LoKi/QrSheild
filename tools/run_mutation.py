#!/usr/bin/env python3
"""Custom AST mutation testing harness on decision/policy.py and matching/entity.py (Phase 4, AC-3).

Generates deterministic single-point AST mutants (relational operators, equality operators,
and boolean operators on code expressions only — never docstrings/comments) across
decision/policy.py and matching/entity.py, executes the unit test suites (including
all @pytest.mark.parametrize cases) against each mutant, and verifies a killed mutation
score >= 70.0%.
Explicitly labeled as 'custom_ast_mutation_harness (tools/run_mutation.py)' in evidence JSON.
"""
from __future__ import annotations

import ast
import contextlib
import copy
import importlib
import importlib.util
import io
import json
import sys
from pathlib import Path
from typing import Any


def collect_ast_mutation_sites(tree: ast.Module, max_sites: int = 25) -> list[tuple[int, int, str]]:
    """Collect (node_index, lineno, description) of mutable AST Compare and BoolOp nodes."""
    sites: list[tuple[int, int, str]] = []
    for idx, node in enumerate(ast.walk(tree)):
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            op = node.ops[0]
            if isinstance(op, (ast.Eq, ast.NotEq, ast.GtE, ast.LtE, ast.Gt, ast.Lt, ast.Is, ast.IsNot)):
                sites.append((idx, getattr(node, "lineno", 0), f"Compare({type(op).__name__})"))
        elif isinstance(node, ast.BoolOp):
            op = node.op
            if isinstance(op, (ast.And, ast.Or)):
                sites.append((idx, getattr(node, "lineno", 0), f"BoolOp({type(op).__name__})"))
        if len(sites) >= max_sites:
            break
    return sites


def apply_ast_mutation(tree: ast.Module, target_idx: int) -> ast.Module:
    mut_tree = copy.deepcopy(tree)
    for idx, node in enumerate(ast.walk(mut_tree)):
        if idx == target_idx:
            if isinstance(node, ast.Compare) and len(node.ops) == 1:
                op = node.ops[0]
                swap = {
                    ast.Eq: ast.NotEq,
                    ast.NotEq: ast.Eq,
                    ast.GtE: ast.Lt,
                    ast.Lt: ast.GtE,
                    ast.LtE: ast.Gt,
                    ast.Gt: ast.LtE,
                    ast.Is: ast.IsNot,
                    ast.IsNot: ast.Is,
                }
                for k, v in swap.items():
                    if isinstance(op, k):
                        node.ops[0] = v()
                        break
            elif isinstance(node, ast.BoolOp):
                if isinstance(node.op, ast.And):
                    node.op = ast.Or()
                elif isinstance(node.op, ast.Or):
                    node.op = ast.And()
            break
    ast.fix_missing_locations(mut_tree)
    return mut_tree


def sync_imported_symbols(
    orig_mod: Any,
    test_files: list[str],
    dependent_modules: list[Any],
) -> None:
    modules = list(dependent_modules)
    for test_file in test_files:
        test_module = sys.modules.get(Path(test_file).stem)
        if test_module is not None:
            modules.append(test_module)
    for module in modules:
        for symbol in ("decide", "Matcher"):
            if hasattr(module, symbol) and hasattr(orig_mod, symbol):
                setattr(module, symbol, getattr(orig_mod, symbol))


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "source"))
    fallback = root / "tools" / "offline_fallback"
    if fallback.is_dir():
        if importlib.util.find_spec("pytest") is None or importlib.util.find_spec("qrcode") is None:
            if str(fallback) not in sys.path:
                sys.path.append(str(fallback))

    import pytest as active_pytest
    import qrshield_core.context.consistency as cons_mod
    import qrshield_core.pipeline.engine as eng_mod

    targets = [
        (
            "qrshield_core.decision.policy",
            root / "source" / "qrshield_core" / "decision" / "policy.py",
            [
                str(root / "source" / "tests" / "unit" / "test_policy.py"),
                str(root / "source" / "tests" / "unit" / "test_consistency.py"),
            ],
        ),
        (
            "qrshield_core.matching.entity",
            root / "source" / "qrshield_core" / "matching" / "entity.py",
            [
                str(root / "source" / "tests" / "unit" / "test_matching.py"),
                str(root / "source" / "tests" / "unit" / "test_consistency.py"),
            ],
        ),
    ]

    total_mutants = 0
    killed_mutants = 0
    survived_details: list[dict[str, Any]] = []
    per_module: dict[str, Any] = {}

    for mod_name, file_path, test_files in targets:
        orig_source = file_path.read_text(encoding="utf-8")
        orig_tree = ast.parse(orig_source, filename=str(file_path))
        orig_mod = importlib.import_module(mod_name)
        orig_dict = dict(orig_mod.__dict__)

        sites = collect_ast_mutation_sites(orig_tree, max_sites=25)
        mod_killed = 0
        for node_idx, line_no, desc in sites:
            total_mutants += 1
            mut_tree = apply_ast_mutation(orig_tree, node_idx)
            dependent_modules = [cons_mod, eng_mod]
            try:
                code_obj = compile(mut_tree, str(file_path), "exec")
                exec(code_obj, orig_mod.__dict__)
                sync_imported_symbols(orig_mod, test_files, dependent_modules)
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                    rc = active_pytest.main(test_files + ["-q"])
                if rc != 0:
                    killed_mutants += 1
                    mod_killed += 1
                else:
                    survived_details.append({"module": mod_name, "line": line_no, "mutation": desc})
            except Exception:
                killed_mutants += 1
                mod_killed += 1
            finally:
                orig_mod.__dict__.clear()
                orig_mod.__dict__.update(orig_dict)
                sync_imported_symbols(orig_mod, test_files, dependent_modules)

        score = round(100.0 * mod_killed / len(sites), 2) if sites else 100.0
        per_module[mod_name] = {
            "total_mutants": len(sites),
            "killed_mutants": mod_killed,
            "survived_mutants": len(sites) - mod_killed,
            "mutation_score_pct": score,
        }

    overall_score = round(100.0 * killed_mutants / total_mutants, 2) if total_mutants else 100.0
    passed = overall_score >= 70.0
    report = {
        "status": "PASS" if passed else "FAIL",
        "measurement_method": "custom_ast_mutation_harness (tools/run_mutation.py)",
        "operators_mutated": "Compare (Eq, NotEq, GtE, LtE, Gt, Lt, Is, IsNot) and BoolOp (And, Or)",
        "overall_mutation_score_pct": overall_score,
        "total_mutants": total_mutants,
        "killed_mutants": killed_mutants,
        "survived_mutants": total_mutants - killed_mutants,
        "min_threshold_pct": 70.0,
        "per_module": per_module,
        "survived_sample": survived_details[:15],
    }

    out_path = root / "release" / "evidence" / "mutation_summary.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
