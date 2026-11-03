"""Research image runner: orchestrates the SAME QRShieldEngine per image.

This module is an orchestration layer. It does NOT contain any security logic.
All security analysis is delegated to QRShieldEngine.

Canonical research flow per image:
    image_path
    → load bytes
    → engine.prepare_image()
    → QR detection check
    → build_context(auto_use_unconfirmed=True)  -- ALL OCR candidates accepted
    → engine.analyze_prepared(config=RESEARCH_CONFIG)
    → FREEZE prediction
    → return ItemResult (no ground truth mixed in)
"""
from __future__ import annotations

import hashlib
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from qrshield_core.context.extract import build_context
from qrshield_core.image.loader import ImageError
from qrshield_core.pipeline import AnalysisConfig, QRShieldEngine

from .failures import FailureCode

REPO_ROOT = Path(__file__).resolve().parent.parent

# Research analysis configuration:
# - threat_intel_mode MUST be "off" — no external lookups during research evaluation
# - all evidence layers enabled for full analysis
RESEARCH_CONFIG = AnalysisConfig(
    name="research_full",
    use_payload=True,
    use_context=True,
    use_action=True,
    threat_intel_mode="off",
    ti_override=False,
)


def portable_image_path(image_path: Path | str) -> str:
    """Return a portable POSIX path relative to REPO_ROOT when possible (P2 #11)."""
    raw = str(image_path).replace("\\", "/")
    if "/qrs_bench_ind/" in raw:
        suffix = raw.split("/qrs_bench_ind/", 1)[1]
        return f"qrs_bench_ind/{suffix}"
    try:
        p = Path(image_path).resolve(strict=False)
        rel = p.relative_to(REPO_ROOT.resolve(strict=False))
        return rel.as_posix()
    except Exception:
        return Path(raw).as_posix()


@dataclass
class ItemResult:
    """Frozen result for one research image. Ground truth is NOT included here.

    Ground truth is loaded separately AFTER predictions are frozen, then
    passed to the scorer. This separation is enforced architecturally.
    """
    item_id: str
    suite: str
    image_path: str
    image_hash: str
    failure_code: FailureCode
    failure_stage: str | None = None
    failure_message: str | None = None
    # Structural lineage (non-label identifiers for joining variants/pairs)
    base_id: str | None = None
    variant_id: str | None = None
    transformation: str | None = None
    pair_id: str | None = None
    pair_role: str | None = None
    # Pipeline stage outputs
    qr_detected: bool | None = None
    qr_count: int | None = None
    qr_decoder: str | None = None
    qr_decode_success: bool | None = None
    qr_payload_redacted: str | None = None
    ocr_status: str | None = None
    ocr_engine: str | None = None
    ocr_engine_version: str | None = None
    ocr_duration_ms: float | None = None
    ocr_block_count: int | None = None
    context_candidate_count: int | None = None
    context_accepted_count: int | None = None
    # Full raw QRShield result (frozen, pre-scoring)
    raw_result: dict[str, Any] | None = None
    # Prediction extracted from raw_result for quick access
    payload_type: str | None = None
    assessment_level: str | None = None
    assessment_label: str | None = None
    assessment_confidence: str | None = None
    action_sensitivity: str | None = None
    context_status: str | None = None
    context_incomplete: bool | None = None
    # Timings
    timings_ms: dict[str, float] = field(default_factory=dict)
    total_ms: float = 0.0

    @property
    def evaluable(self) -> bool:
        return self.failure_code is FailureCode.SUCCESS and self.raw_result is not None


def _hash_image(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def run_image(
    engine: QRShieldEngine,
    item_id: str,
    suite: str,
    image_path: Path,
    *,
    base_id: str | None = None,
    variant_id: str | None = None,
    transformation: str | None = None,
    pair_id: str | None = None,
    pair_role: str | None = None,
) -> ItemResult:
    """Process one research image through the QRShieldEngine pipeline.

    Failures at any stage are recorded but never suppress payload security analysis.
    Ground truth is intentionally NOT accepted as a parameter to prevent leakage.
    """
    t_start = time.perf_counter()
    path_str = portable_image_path(image_path)
    lineage = {
        "base_id": base_id,
        "variant_id": variant_id,
        "transformation": transformation,
        "pair_id": pair_id,
        "pair_role": pair_role,
    }

    # --- Load image bytes ---
    try:
        image_data = image_path.read_bytes()
    except OSError as exc:
        return ItemResult(
            item_id=item_id, suite=suite, image_path=path_str, image_hash="",
            failure_code=FailureCode.IMAGE_LOAD_ERROR, failure_stage="image_load",
            failure_message=f"Cannot read image file: {exc}",
            total_ms=round((time.perf_counter() - t_start) * 1000, 1),
            **lineage,
        )

    image_hash = _hash_image(image_data)

    # --- Stage A: prepare image (QR decode + OCR) ---
    try:
        prep = engine.prepare_image(image_data, image_path.name)
    except ImageError as exc:
        return ItemResult(
            item_id=item_id, suite=suite, image_path=path_str, image_hash=image_hash,
            failure_code=FailureCode.IMAGE_LOAD_ERROR, failure_stage="image_load",
            failure_message=exc.message,
            total_ms=round((time.perf_counter() - t_start) * 1000, 1),
            **lineage,
        )
    except Exception as exc:
        return ItemResult(
            item_id=item_id, suite=suite, image_path=path_str, image_hash=image_hash,
            failure_code=FailureCode.RUNTIME_ERROR, failure_stage="prepare_image",
            failure_message=f"{type(exc).__name__}: {exc}",
            total_ms=round((time.perf_counter() - t_start) * 1000, 1),
            **lineage,
        )

    # --- QR detection / decoding check ---
    qr_count = prep.decode.count
    decoded_codes = [c for c in prep.decode.codes if c.decoded]

    if qr_count == 0:
        return ItemResult(
            item_id=item_id, suite=suite, image_path=path_str, image_hash=image_hash,
            failure_code=FailureCode.QR_DETECT_ERROR, failure_stage="qr_detect",
            failure_message="No QR code detected in image.",
            qr_detected=False, qr_count=0,
            ocr_status=prep.ocr.status, ocr_engine=prep.ocr.engine,
            ocr_engine_version=prep.ocr.engine_version,
            ocr_duration_ms=prep.ocr.duration_ms,
            ocr_block_count=len(prep.ocr.blocks),
            timings_ms=prep.timings,
            total_ms=round((time.perf_counter() - t_start) * 1000, 1),
            **lineage,
        )

    if qr_count > 1:
        return ItemResult(
            item_id=item_id, suite=suite, image_path=path_str, image_hash=image_hash,
            failure_code=FailureCode.MULTIPLE_QR_AMBIGUOUS, failure_stage="qr_detect",
            failure_message=f"Image contains {qr_count} QR codes; research images must have exactly one.",
            qr_detected=True, qr_count=qr_count,
            ocr_status=prep.ocr.status, ocr_engine=prep.ocr.engine,
            ocr_engine_version=prep.ocr.engine_version,
            timings_ms=prep.timings,
            total_ms=round((time.perf_counter() - t_start) * 1000, 1),
            **lineage,
        )

    if not decoded_codes:
        return ItemResult(
            item_id=item_id, suite=suite, image_path=path_str, image_hash=image_hash,
            failure_code=FailureCode.QR_DECODE_ERROR, failure_stage="qr_decode",
            failure_message="QR code detected but payload could not be decoded.",
            qr_detected=True, qr_count=1, qr_decode_success=False,
            qr_decoder=prep.decode.codes[0].decoder if prep.decode.codes else None,
            ocr_status=prep.ocr.status, ocr_engine=prep.ocr.engine,
            ocr_engine_version=prep.ocr.engine_version,
            timings_ms=prep.timings,
            total_ms=round((time.perf_counter() - t_start) * 1000, 1),
            **lineage,
        )

    code = prep.decode.codes[0]  # exactly one QR, confirmed decoded

    # --- OCR status recording (failures don't stop payload analysis) ---
    ocr_code = FailureCode.SUCCESS
    if prep.ocr.status == "failed":
        ocr_code = FailureCode.OCR_ERROR
    elif prep.ocr.status == "no_text":
        ocr_code = FailureCode.OCR_NO_TEXT

    # --- Build context: accept ALL OCR candidates automatically ---
    ctx = build_context(
        prep.candidates,
        decisions=None,
        manual=None,
        auto_use_unconfirmed=True,
        default_source="ocr",
    )

    # --- Stage B: analyze (SAME QRShieldEngine as normal Analyze) ---
    try:
        result = engine.analyze_prepared(
            prep=prep,
            qr_index=0,
            context=ctx,
            config=RESEARCH_CONFIG,
            ti_service=None,   # forces RESEARCH_CONFIG.threat_intel_mode="off"
            analysis_id=f"research_{item_id}",
        )
    except Exception as exc:
        return ItemResult(
            item_id=item_id, suite=suite, image_path=path_str, image_hash=image_hash,
            failure_code=FailureCode.SECURITY_ANALYSIS_ERROR, failure_stage="analysis",
            failure_message=f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-600:]}",
            qr_detected=True, qr_count=1, qr_decode_success=True,
            qr_decoder=code.decoder,
            qr_payload_redacted=code.payload[:100] + "..." if code.payload and len(code.payload) > 100 else code.payload,
            ocr_status=prep.ocr.status, ocr_engine=prep.ocr.engine,
            ocr_engine_version=prep.ocr.engine_version,
            ocr_duration_ms=prep.ocr.duration_ms,
            ocr_block_count=len(prep.ocr.blocks),
            context_candidate_count=len(prep.candidates),
            context_accepted_count=len(ctx.attributes),
            timings_ms=prep.timings,
            total_ms=round((time.perf_counter() - t_start) * 1000, 1),
            **lineage,
        )

    # --- FREEZE prediction ---
    raw = result.to_dict()
    a = raw.get("assessment", {})
    payload_info = raw.get("payload") or {}

    # Verify threat intel was NOT used (defence in depth)
    ti_results = raw.get("threat_intel_results", [])
    for ti in ti_results:
        status = ti.get("status", "")
        if status not in ("not_queried", "unavailable", ""):
            raw.setdefault("_research_warnings", []).append(
                f"UNEXPECTED TI query detected: status={status}"
            )

    total_ms = round((time.perf_counter() - t_start) * 1000, 1)

    return ItemResult(
        item_id=item_id,
        suite=suite,
        image_path=path_str,
        image_hash=image_hash,
        failure_code=ocr_code if ocr_code != FailureCode.SUCCESS else FailureCode.SUCCESS,
        failure_stage="ocr" if ocr_code != FailureCode.SUCCESS else None,
        failure_message=prep.ocr.message if ocr_code != FailureCode.SUCCESS else None,
        qr_detected=True,
        qr_count=1,
        qr_decoder=code.decoder,
        qr_decode_success=True,
        qr_payload_redacted=raw.get("qr", {}).get("payload_raw"),
        ocr_status=prep.ocr.status,
        ocr_engine=prep.ocr.engine,
        ocr_engine_version=prep.ocr.engine_version,
        ocr_duration_ms=prep.ocr.duration_ms,
        ocr_block_count=len(prep.ocr.blocks),
        context_candidate_count=len(prep.candidates),
        context_accepted_count=len(ctx.attributes),
        raw_result=raw,
        payload_type=payload_info.get("type"),
        assessment_level=a.get("level"),
        assessment_label=a.get("label"),
        assessment_confidence=a.get("confidence"),
        action_sensitivity=a.get("action_sensitivity"),
        context_status=a.get("context_status"),
        context_incomplete=a.get("context_incomplete"),
        timings_ms=prep.timings,
        total_ms=total_ms,
        **lineage,
    )


def preflight_ocr(engine: QRShieldEngine) -> tuple[bool, str]:
    """Verify the configured local OCR provider can initialise before starting a research run."""
    if engine.ocr_provider is None:
        return False, "OCR is disabled (OCR_ENABLED=false). A local OCR provider is required for research testing."
    ok, why = engine.ocr_provider.available()
    provider_label = getattr(engine.ocr_provider, "name", "OCR")
    if not ok:
        return False, f"{provider_label} failed to initialise: {why}"
    return True, ""
