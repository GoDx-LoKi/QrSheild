#!/usr/bin/env python3
"""Command execution logger for release/evidence/ledger.jsonl (Non-Negotiable Rule 1)."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = ROOT / "release" / "evidence" / "ledger.jsonl"


def get_git_sha() -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return "uncommitted"


def run_and_log(cmd: str, cwd: Path = ROOT, output_file: Path | None = None, step_id: str = "") -> int:
    LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    git_sha = get_git_sha()
    env = os.environ.copy()
    vendor_dir = str(ROOT / "tools" / "vendor")
    source_dir = str(ROOT / "source")
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{vendor_dir}:{source_dir}" + (f":{existing_pp}" if existing_pp else "")

    proc = subprocess.run(
        cmd,
        shell=True,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
    )
    combined_out = (proc.stdout or "") + (proc.stderr or "")
    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(combined_out, encoding="utf-8")
        out_sha256 = hashlib.sha256(output_file.read_bytes()).hexdigest()
    else:
        out_sha256 = hashlib.sha256(combined_out.encode("utf-8")).hexdigest()

    entry = {
        "step_id": step_id or cmd[:60],
        "command": cmd,
        "cwd": str(cwd.relative_to(ROOT)) if cwd != ROOT else ".",
        "exit_code": proc.returncode,
        "timestamp": ts,
        "git_sha": git_sha,
        "output_sha256": out_sha256,
        "output_file": str(output_file.relative_to(ROOT)) if output_file else None,
    }
    with LEDGER_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    return proc.returncode


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a command and log evidence to release/evidence/ledger.jsonl")
    parser.add_argument("--step", default="", help="Step identifier")
    parser.add_argument("--cwd", default=".", help="Working directory relative to repo root")
    parser.add_argument("--out", default="", help="Optional output file path relative to repo root")
    parser.add_argument("cmd", help="Shell command to execute")
    args = parser.parse_args()

    cwd_path = (ROOT / args.cwd).resolve()
    out_path = (ROOT / args.out).resolve() if args.out else None
    rc = run_and_log(args.cmd, cwd=cwd_path, output_file=out_path, step_id=args.step)
    sys.exit(rc)


if __name__ == "__main__":
    main()
