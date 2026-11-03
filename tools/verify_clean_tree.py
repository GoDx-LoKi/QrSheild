#!/usr/bin/env python3
"""Verify that the repository contains zero __pycache__ directories, .pyc files, runtime scratch dirs, or retired/duplicate directories."""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def clean_bytecode(root: Path) -> int:
    removed = 0
    for p in list(root.rglob("__pycache__")):
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
            removed += 1
    for p in list(root.rglob("*.pyc")):
        if p.is_file():
            p.unlink(missing_ok=True)
            removed += 1
    for scratch in (root / "source" / "artifacts", root / "artifacts", root / ".pytest_cache"):
        if scratch.exists():
            shutil.rmtree(scratch, ignore_errors=True)
            removed += 1
    return removed


def main() -> int:
    if "--clean" in sys.argv:
        clean_bytecode(ROOT)

    pycache_dirs = [str(p.relative_to(ROOT)) for p in ROOT.rglob("__pycache__") if ".git" not in p.parts]
    pyc_files = [str(p.relative_to(ROOT)) for p in ROOT.rglob("*.pyc") if ".git" not in p.parts]
    retired_dirs = [
        rel for rel in (
            "source/qrshield_research_dataset",
            "qrs_bench_ind_v1",
            "qrs_bench_ind_v1_1",
            "source/audit",
            "source/docs",
            "source/artifacts",
            "evaluation",
            "tools/vendor",
        )
        if (ROOT / rel).exists()
    ]
    required_root_files = [
        rel for rel in (
            "pyproject.toml",
            "requirements.txt",
            "requirements.lock",
            "Dockerfile",
            "docker-compose.yml",
            ".gitignore",
            ".dockerignore",
            ".env.example",
            "LICENSE",
            "README.md",
            "CONTRIBUTING.md",
            "SECURITY.md",
            ".github/workflows/ci.yml",
            "docs/TUNING_DISCLOSURE.md",
            "qrs_bench_ind/annotations/consensus_ground_truth.jsonl",
        )
        if not (ROOT / rel).exists()
    ]

    ok = not (pycache_dirs or pyc_files or retired_dirs or required_root_files)
    report = {
        "status": "PASS" if ok else "FAIL",
        "pycache_dirs": pycache_dirs,
        "pyc_files": pyc_files,
        "retired_dirs_present": retired_dirs,
        "missing_required_files": required_root_files,
    }
    print(json.dumps(report, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
