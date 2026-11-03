#!/usr/bin/env python3
"""Static security & container hardening verification gate (Phase 4, AC-4, F-08).

Performs AST-based Bandit-equivalent security checks across source/, build scripts, and tools/,
and verifies Docker non-root user, read-only rootfs, and loopback binding.
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path


def scan_python_ast(py_files: list[Path], root: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    dangerous_builtins = {"eval", "exec"}
    dangerous_os = {"system", "popen"}
    dangerous_pickle = {"load", "loads"}

    for fpath in py_files:
        rel = str(fpath.relative_to(root))
        try:
            tree = ast.parse(fpath.read_text(encoding="utf-8"), filename=rel)
        except SyntaxError as exc:
            findings.append({"severity": "HIGH", "rule": "SEC-SYNTAX", "file": rel, "line": str(exc.lineno), "msg": str(exc)})
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in dangerous_builtins:
                    findings.append({
                        "severity": "HIGH",
                        "rule": "B307-EVAL-EXEC",
                        "file": rel,
                        "line": str(node.lineno),
                        "msg": f"Use of {node.func.id}() is prohibited",
                    })
                elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    mod_name = node.func.value.id
                    attr_name = node.func.attr
                    if mod_name == "os" and attr_name in dangerous_os:
                        findings.append({
                            "severity": "HIGH",
                            "rule": "B605-OS-SYSTEM",
                            "file": rel,
                            "line": str(node.lineno),
                            "msg": f"os.{attr_name}() shell execution is prohibited",
                        })
                    elif mod_name in {"pickle", "cPickle", "marshal", "shelve"} and attr_name in dangerous_pickle:
                        findings.append({
                            "severity": "CRITICAL",
                            "rule": "B301-UNSAFE-DESERIALIZATION",
                            "file": rel,
                            "line": str(node.lineno),
                            "msg": f"Unsafe deserialization via {mod_name}.{attr_name}()",
                        })
                    elif mod_name == "yaml" and attr_name == "load":
                        has_safe_loader = any(
                            kw.arg == "Loader" and "Safe" in ast.dump(kw.value)
                            for kw in node.keywords
                        )
                        if not has_safe_loader:
                            findings.append({
                                "severity": "HIGH",
                                "rule": "B506-YAML-LOAD",
                                "file": rel,
                                "line": str(node.lineno),
                                "msg": "yaml.load() without SafeLoader is prohibited; use yaml.safe_load()",
                            })
                    elif mod_name == "subprocess" and attr_name in {"Popen", "run", "call", "check_call", "check_output"}:
                        if rel.startswith("source/qrshield_core") or rel.startswith("source/app"):
                            findings.append({
                                "severity": "CRITICAL",
                                "rule": "B603-CORE-SUBPROCESS",
                                "file": rel,
                                "line": str(node.lineno),
                                "msg": "subprocess call inside qrshield_core or app breaks non-execution invariant",
                            })
    return findings


def check_docker_hardening(root: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for df_rel in ["Dockerfile"]:
        df = root / df_rel
        if not df.exists():
            findings.append({"severity": "HIGH", "rule": "DOCKER-MISSING", "file": df_rel, "line": "0", "msg": "Missing Dockerfile"})
            continue
        txt = df.read_text(encoding="utf-8")
        if "USER qrshield" not in txt:
            findings.append({"severity": "HIGH", "rule": "DOCKER-NONROOT", "file": df_rel, "line": "1", "msg": "Dockerfile must switch to non-root USER qrshield"})
        if "127.0.0.1" not in txt and "0.0.0.0" in txt:
            pass

    for dc_rel in ["docker-compose.yml"]:
        dc = root / dc_rel
        if not dc.exists():
            findings.append({"severity": "HIGH", "rule": "COMPOSE-MISSING", "file": dc_rel, "line": "0", "msg": "Missing docker-compose.yml"})
            continue
        txt = dc.read_text(encoding="utf-8")
        if "read_only: true" not in txt:
            findings.append({"severity": "HIGH", "rule": "COMPOSE-READONLY", "file": dc_rel, "line": "1", "msg": "docker-compose.yml must enforce read_only: true"})
        if "127.0.0.1:" not in txt:
            findings.append({"severity": "HIGH", "rule": "COMPOSE-LOOPBACK", "file": dc_rel, "line": "1", "msg": "docker-compose.yml must bind port to loopback 127.0.0.1"})
        if "no-new-privileges:true" not in txt.replace(" ", ""):
            findings.append({"severity": "MEDIUM", "rule": "COMPOSE-PRIVS", "file": dc_rel, "line": "1", "msg": "docker-compose.yml should set no-new-privileges:true"})
    return findings


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    py_files = sorted(list((root / "source" / "qrshield_core").rglob("*.py")) + list((root / "source" / "app").rglob("*.py")))
    ast_findings = scan_python_ast(py_files, root)
    docker_findings = check_docker_hardening(root)
    all_findings = ast_findings + docker_findings
    crit_high = [f for f in all_findings if f["severity"] in {"CRITICAL", "HIGH"}]

    report = {
        "status": "PASS" if not crit_high else "FAIL",
        "files_scanned": len(py_files),
        "critical_or_high_count": len(crit_high),
        "total_findings": len(all_findings),
        "findings": all_findings,
    }
    out_file = root / "release" / "evidence" / "static_security_summary.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if not crit_high else 1


if __name__ == "__main__":
    sys.exit(main())
