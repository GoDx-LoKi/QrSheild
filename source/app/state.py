"""Process-wide application state: the engine, short-lived analysis sessions, and artifact helpers."""
from __future__ import annotations

import json
import re
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from qrshield_core.config import Settings
from qrshield_core.pipeline import QRShieldEngine

ID_RE = re.compile(r"^[a-f0-9]{32}$")
RUN_RE = re.compile(r"^\d{8}T\d{6}Z-[a-zA-Z0-9_]+-[0-9a-fA-F]+$")
RUN_EXTENSIONS = {".json", ".jsonl", ".csv", ".html", ".md"}


class AppState:
    def __init__(self, settings: Settings | None = None, engine: QRShieldEngine | None = None):
        self.settings = settings or Settings.from_env()
        self.engine = engine or QRShieldEngine(self.settings)
        self._lock = threading.Lock()
        self._sessions: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
        self.max_sessions, self.ttl = 40, 3600
        self.purge_old_artifacts()

    # ---- sessions (prepared images and analysis requests, in memory only)
    def put(self, key: str, value: dict[str, Any]) -> None:
        with self._lock:
            self._sessions[key] = {**value, "_t": time.time()}
            self._sessions.move_to_end(key)
            while len(self._sessions) > self.max_sessions:
                self._sessions.popitem(last=False)

    def get(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            v = self._sessions.get(key)
            if v and time.time() - v["_t"] > self.ttl:
                self._sessions.pop(key, None)
                return None
            return v

    # ---- artifacts
    def save_upload(self, aid: str, png: bytes) -> None:
        (self.settings.artifacts_dir / "uploads" / f"{aid}.png").write_bytes(png)

    def upload_path(self, aid: str) -> Path | None:
        if not ID_RE.match(aid):
            return None
        p = self.settings.artifacts_dir / "uploads" / f"{aid}.png"
        return p if p.is_file() else None

    def save_result(self, aid: str, data: dict[str, Any]) -> None:
        (self.settings.artifacts_dir / "results" / f"{aid}.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def load_result(self, aid: str) -> dict[str, Any] | None:
        if not ID_RE.match(aid):
            return None
        p = self.settings.artifacts_dir / "results" / f"{aid}.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None

    def purge_old_artifacts(self) -> int:
        days = self.settings.result_retention_days
        if days <= 0:
            return 0
        cutoff, n = time.time() - days * 86400, 0
        for sub in ("uploads", "results", "sessions"):
            d = self.settings.artifacts_dir / sub
            for f in d.glob("*") if d.is_dir() else []:
                try:
                    if f.is_file() and f.stat().st_mtime < cutoff:
                        f.unlink()
                        n += 1
                except OSError:
                    pass
        return n

    def list_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        d = self.settings.artifacts_dir / "runs"
        out = []
        if not d.is_dir():
            return out
        for r in sorted((x for x in d.iterdir() if x.is_dir() and RUN_RE.match(x.name)), reverse=True)[:limit]:
            files = []
            for f in sorted(r.rglob("*")):
                if f.is_file() and f.suffix in RUN_EXTENSIONS:
                    files.append(f.relative_to(r).as_posix())
            out.append({"run_id": r.name, "files": files})
        return out
