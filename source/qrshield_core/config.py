"""Environment-driven configuration. No secrets are ever hard-coded."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Tiny .env loader (does not override variables already in the environment)."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


@dataclass
class Settings:
    env: str = "development"
    ocr_enabled: bool = True
    ocr_provider: str = "paddleocr"         # paddleocr | tesseract | auto
    threat_intel_enabled: bool = True
    virustotal_api_key: str = field(default="", repr=False)   # never printed
    access_token: str = field(default="", repr=False)         # required for non-loopback deployments
    vt_malicious_threshold: int = 3        # engines flagging "malicious" to call it confirmed evidence
    vt_timeout_seconds: float = 10.0
    max_image_size_mb: int = 10
    max_image_pixels: int = 40_000_000
    max_image_side: int = 4000
    result_retention_days: int = 7
    log_level: str = "INFO"
    artifacts_dir: Path = REPO_ROOT / "artifacts"
    rules_dir: Path = REPO_ROOT / "rules"
    load_synthetic_reference: bool = False  # disabled by default so live/CLI matches locked research config
    allowed_hosts: list[str] = field(default_factory=lambda: ["127.0.0.1", "localhost", "[::1]"])

    @classmethod
    def from_env(cls) -> "Settings":
        _load_dotenv(REPO_ROOT / ".env")
        return cls(
            env=os.environ.get("QRSHIELD_ENV", "development"),
            ocr_enabled=_bool("OCR_ENABLED", True),
            ocr_provider=os.environ.get("OCR_PROVIDER", "paddleocr").strip().lower() or "paddleocr",
            threat_intel_enabled=_bool("THREAT_INTEL_ENABLED", True),
            virustotal_api_key=os.environ.get("VIRUSTOTAL_API_KEY", "").strip(),
            access_token=os.environ.get("QRSHIELD_ACCESS_TOKEN", "").strip(),
            vt_malicious_threshold=_int("VT_MALICIOUS_THRESHOLD", 3),
            vt_timeout_seconds=float(os.environ.get("VT_TIMEOUT_SECONDS", "10") or 10),
            max_image_size_mb=_int("MAX_IMAGE_SIZE_MB", 10),
            max_image_pixels=_int("MAX_IMAGE_PIXELS", 40_000_000),
            max_image_side=_int("MAX_IMAGE_SIDE", 4000),
            result_retention_days=_int("RESULT_RETENTION_DAYS", 7),
            log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
            artifacts_dir=Path(os.environ.get("ARTIFACTS_DIR", str(REPO_ROOT / "artifacts"))),
            rules_dir=Path(os.environ.get("RULES_DIR", str(REPO_ROOT / "rules"))),
            load_synthetic_reference=_bool("LOAD_SYNTHETIC_REFERENCE", False),
            allowed_hosts=[h.strip() for h in os.environ.get("ALLOWED_HOSTS", "127.0.0.1,localhost,[::1]").split(",") if h.strip()],
        )

    @property
    def virustotal_configured(self) -> bool:
        return bool(self.virustotal_api_key)

    def ensure_dirs(self) -> None:
        for sub in ("uploads", "results", "runs", "cache", "sessions"):
            (self.artifacts_dir / sub).mkdir(parents=True, exist_ok=True)
