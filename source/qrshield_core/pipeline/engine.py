"""QRShield orchestration: QR Image → Decoder → Payload Classifier → Payload Security Analyzer → Context Analyzer →
Context Consistency Engine → Action Sensitivity → (optional) Threat Intelligence → Evidence Grouping → Decision →
Explanation/Recommendation.

The engine has no HTTP dependency, never executes a payload action, and treats every input as untrusted data.
"""
from __future__ import annotations

import importlib
import platform
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .. import ANALYZER_VERSION, __version__
from ..action.sensitivity import action_evidence, assess_action
from ..analyzers import Deps, analyze_payload_security
from ..config import Settings
from ..context.consistency import ConsistencyEngine
from ..context.extract import ContextCandidate, extract_candidates
from ..decision.policy import TISummary, decide
from ..decoder.qr import DecodeResult, detect_and_decode
from ..evidence.grouping import group_evidence
from ..image.loader import LoadedImage, load_image, sanitize_filename
from ..logging_utils import configure_logging, get_logger, stage
from ..matching.entity import Matcher
from ..models import (
    Confidence, Context, Evidence, MatchRecord, MatchResult, Payload, PayloadType, ThreatIntelStatus, to_dict,
)
from ..normalizer.normalize import normalize
from ..ocr.engine import OCRProvider, OCRResult, PaddleOCRProvider, TesseractOCRProvider, create_ocr_provider, run_ocr
from ..redaction import redact_payload_raw
from ..reporting.explain import build_explanation, build_recommendations
from ..rules import ReferenceData, RuleRegistry
from ..threat_intel.base import ResultCache, ThreatIntelPolicy, ThreatIntelProvider, ThreatIntelResult
from ..threat_intel.service import ThreatIntelService, to_evidence
from ..threat_intel.virustotal import VirusTotalProvider

log = get_logger("engine")


@dataclass
class AnalysisConfig:
    """Which evidence layers are used. Presets implement the ablation configurations of the paper."""

    name: str = "full"
    use_payload: bool = True
    use_context: bool = True
    use_action: bool = True
    threat_intel_mode: str = "off"          # off | lookup | scan  (lookup/scan send the URL to the provider)
    ti_override: bool = False               # explicit user confirmation for soft privacy blocks

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "use_payload": self.use_payload, "use_context": self.use_context,
                "use_action": self.use_action, "threat_intel_mode": self.threat_intel_mode, "ti_override": self.ti_override}


ABLATIONS = {
    "payload_only": AnalysisConfig("payload_only", True, False, False, "off"),
    "context_only": AnalysisConfig("context_only", False, True, False, "off"),
    "payload_context": AnalysisConfig("payload_context", True, True, False, "off"),
    "payload_context_action": AnalysisConfig("payload_context_action", True, True, True, "off"),
    "full": AnalysisConfig("full", True, True, True, "lookup"),
}


@dataclass
class PreparedImage:
    analysis_id: str
    filename: str
    loaded: LoadedImage = field(repr=False)
    decode: DecodeResult
    ocr: OCRResult
    candidates: list[ContextCandidate]
    timings: dict[str, float]


@dataclass
class AnalysisResult:
    data: dict[str, Any]

    @property
    def level(self) -> str:
        return self.data["assessment"]["level"]

    def to_dict(self) -> dict[str, Any]:
        return self.data


def _versions() -> dict[str, str]:
    out = {"python": platform.python_version(), "platform": platform.platform(terse=True)}
    for mod in ("cv2", "numpy", "PIL", "yaml", "httpx", "zxingcpp", "paddleocr", "pytesseract"):
        try:
            m = importlib.import_module(mod)
            out[mod] = str(getattr(m, "__version__", "installed"))
        except Exception:
            out[mod] = "not installed"
    return out


class QRShieldEngine:
    def __init__(self, settings: Settings | None = None, *, ocr_provider: OCRProvider | None = None,
                 ti_provider: ThreatIntelProvider | None = None, use_default_ocr: bool = True):
        self.settings = settings or Settings.from_env()
        configure_logging(self.settings.log_level)
        self.settings.ensure_dirs()
        self.reg = RuleRegistry(self.settings.rules_dir)
        self.ref = ReferenceData.load(self.settings.rules_dir, self.settings.load_synthetic_reference)
        self.matcher = Matcher(self.ref)
        self.deps = Deps(self.reg, self.ref, self.matcher)
        self.consistency = ConsistencyEngine(self.deps)
        if ocr_provider is not None:
            self.ocr_provider: OCRProvider | None = ocr_provider
        else:
            if use_default_ocr and self.settings.ocr_enabled:
                self.ocr_provider = create_ocr_provider(getattr(self.settings, "ocr_provider", "paddleocr"))
            else:
                self.ocr_provider = None
        if ti_provider is None and self.settings.threat_intel_enabled and self.settings.virustotal_configured:
            ti_provider = VirusTotalProvider(self.settings.virustotal_api_key, timeout=self.settings.vt_timeout_seconds,
                                             malicious_threshold=self.settings.vt_malicious_threshold,
                                             cache=ResultCache(self.settings.artifacts_dir / "cache"))
        self.ti_provider = ti_provider
        self.policy = ThreatIntelPolicy(self.ref)
        self.ti_service = ThreatIntelService(ti_provider, self.policy)

    # ------------------------------------------------------------------ manifest
    def manifest(self, dataset_version: str | None = None, ocr: OCRResult | None = None,
                 config: AnalysisConfig | None = None, ti_service: ThreatIntelService | None = None) -> dict[str, Any]:
        svc = ti_service or self.ti_service
        st = svc.provider_state()
        return {
            "qrshield_version": __version__, "analyzer_version": ANALYZER_VERSION, "rule_version": self.reg.version,
            "rule_files": self.reg.file_versions, "reference_data_version": self.ref.version,
            "synthetic_reference_loaded": self.settings.load_synthetic_reference, "dataset_version": dataset_version,
            "ocr": {"engine": getattr(self.ocr_provider, "name", "none"), "enabled": self.settings.ocr_enabled,
                    "engine_version": ocr.engine_version if ocr else getattr(self.ocr_provider, "version", None),
                    "config": getattr(self.ocr_provider, "config", {}), "status": ocr.status if ocr else "not run"},
            "threat_intel": {"provider": st["provider"], "enabled": self.settings.threat_intel_enabled and (config.threat_intel_mode != "off" if config else False),
                             "configured": st["configured"]},
            "analysis_config": config.to_dict() if config else None, "environment": _versions(),
        }

    def preview_payload(self, raw: str) -> dict[str, Any]:
        """Type and redacted form of a decoded payload (no analysis, no network)."""
        pl = normalize(raw, self.ref)
        return {"type": pl.type.value, "action": pl.action, "raw_redacted": pl.raw_redacted, "parse_ok": pl.parse_ok,
                "classification_reason": pl.classification_reason}

    # ------------------------------------------------------------------ stage A: image
    def prepare_image(self, data: bytes, filename: str | None = None, analysis_id: str | None = None) -> PreparedImage:
        aid = analysis_id or uuid.uuid4().hex
        timings: dict[str, float] = {}
        with stage(log, aid, "image_load", timings):
            loaded = load_image(data, max_bytes=self.settings.max_image_size_mb * 1024 * 1024,
                                max_pixels=self.settings.max_image_pixels, max_side=self.settings.max_image_side)
        with stage(log, aid, "qr_decode", timings):
            dec = detect_and_decode(loaded.bgr)
        with stage(log, aid, "ocr", timings):
            ocr = run_ocr(self.ocr_provider, loaded.bgr, self.ref, enabled=self.settings.ocr_enabled,
                          qr_boxes=[c.bbox for c in dec.codes])
        with stage(log, aid, "context_candidates", timings):
            cands = extract_candidates(ocr.blocks, self.ref) if ocr.blocks else []
        log.info("analysis=%s qr_count=%d ocr_status=%s candidates=%d", aid, dec.count, ocr.status, len(cands))
        return PreparedImage(aid, sanitize_filename(filename), loaded, dec, ocr, cands, timings)

    # ------------------------------------------------------------------ stage B: analysis
    def analyze_prepared(self, prep: PreparedImage, qr_index: int, context: Context, config: AnalysisConfig | None = None,
                         ti_service: ThreatIntelService | None = None, analysis_id: str | None = None) -> AnalysisResult:
        code = prep.decode.codes[qr_index]
        qr_meta = {"detected": True, "count": prep.decode.count, "selected_index": qr_index, "decoder": code.decoder,
                   "decoder_variant": code.variant, "decode_success": code.decoded, "bbox": code.bbox,
                   "decode_attempts": prep.decode.attempts[-6:], "encoding_note": prep.decode.encoding_note}
        input_meta = {"image_id": prep.analysis_id, "image_name": prep.filename, "image_hash": prep.loaded.sha256, "image_quality": prep.loaded.quality,
                      "image_warnings": prep.loaded.warnings, "width": prep.loaded.width, "height": prep.loaded.height}
        if not code.decoded:
            return self._undecoded(prep, qr_meta, input_meta, analysis_id)
        return self.analyze_payload(code.payload or "", context, config, analysis_id=analysis_id or prep.analysis_id,
                                    input_meta=input_meta, qr_meta=qr_meta, ocr=prep.ocr, candidates=prep.candidates,
                                    ti_service=ti_service)

    def _undecoded(self, prep: PreparedImage, qr_meta: dict, input_meta: dict, analysis_id: str | None) -> AnalysisResult:
        aid = analysis_id or prep.analysis_id
        data = {"analysis_id": aid, "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "manifest": self.manifest(ocr=prep.ocr), "input": input_meta, "qr": {**qr_meta, "payload_raw": None},
                "payload": None, "ocr": self._ocr_dict(prep.ocr, prep.candidates), "context": None,
                "payload_findings": [], "context_findings": [], "matching_findings": [], "action_findings": [],
                "threat_intel_findings": [], "threat_intel_results": [], "evidence_groups": [],
                "assessment": {"level": "not_assessed", "label": "Not assessed", "confidence": "low",
                               "confidence_basis": "the QR code could not be decoded", "trace": [], "local_level": "not_assessed",
                               "basis": {}, "context_status": "missing", "context_incomplete": True},
                "explanation": {"headline": "Not assessed", "text": "A QR pattern was located but could not be decoded, so no payload analysis was possible. "
                                "A failed decode is not a security verdict. Try a sharper, better-lit or closer image.",
                                "what_was_found": [], "why_it_matters": [], "what_matched": [], "what_did_not_match": [],
                                "what_remains_uncertain": ["The QR content could not be decoded."], "what_to_verify": [], "decision_trace": [],
                                "interpretation": "No payload was available to analyse.", "where_it_came_from": [], "plausible_legitimate_explanations": []},
                "recommendations": ["Retake the photo (sharper, better lit, QR fully in frame) and analyse again."],
                "limitations": ["The QR content could not be decoded."], "config": None, "timings_ms": prep.timings}
        return AnalysisResult(data)

    def _ocr_dict(self, ocr: OCRResult | None, cands: list[ContextCandidate] | None) -> dict[str, Any]:
        if ocr is None:
            return {"status": "not run", "text_blocks": [], "candidate_context": []}
        return {"status": ocr.status, "message": ocr.message, "engine": ocr.engine, "engine_version": ocr.engine_version,
                "duration_ms": ocr.duration_ms, "masked_qr_regions": ocr.masked_qr_regions,
                "text_blocks": [to_dict(b) for b in ocr.blocks], "candidate_context": [to_dict(c) for c in (cands or [])]}

    def analyze_payload(self, raw: str, context: Context | None, config: AnalysisConfig | None = None, *,
                        analysis_id: str | None = None, input_meta: dict | None = None, qr_meta: dict | None = None,
                        ocr: OCRResult | None = None, candidates: list[ContextCandidate] | None = None,
                        ti_service: ThreatIntelService | None = None, dataset_version: str | None = None) -> AnalysisResult:
        cfg = config or AnalysisConfig()
        aid = analysis_id or uuid.uuid4().hex
        ctx = context or Context()
        timings: dict[str, float] = {}
        limitations: list[str] = []
        svc = ti_service or self.ti_service

        with stage(log, aid, "classify_normalize", timings):
            payload: Payload = normalize(raw, self.ref)

        payload_ev: list[Evidence] = []
        if cfg.use_payload:
            with stage(log, aid, "payload_analysis", timings):
                try:
                    payload_ev = analyze_payload_security(payload, self.deps)
                except Exception as exc:     # an analyzer bug must never become a verdict
                    limitations.append(f"The {payload.type.value} analyzer failed ({type(exc).__name__}); payload findings are incomplete.")
                    log.error("analysis=%s analyzer_error=%s", aid, type(exc).__name__)

        context_ev: list[Evidence] = []
        matches: list[MatchRecord] = []
        if cfg.use_context:
            with stage(log, aid, "context_consistency", timings):
                try:
                    context_ev, matches = self.consistency.evaluate(payload, ctx)
                except Exception as exc:
                    limitations.append(f"The context-consistency engine failed ({type(exc).__name__}); context findings are incomplete.")
                    log.error("analysis=%s consistency_error=%s", aid, type(exc).__name__)

        ctype = self.consistency._ctype(ctx) if cfg.use_context else None
        sens, action_ev, reasons = None, [], []
        if cfg.use_action:
            with stage(log, aid, "action_sensitivity", timings):
                a = assess_action(payload, ctx if cfg.use_context else None, payload_ev, context_ev, ctype, self.deps)
                sens, reasons = a.level, a.reasons
                action_ev = [action_evidence(a, payload, self.deps)]

        ti_results: list[ThreatIntelResult] = []
        ti_ev: list[Evidence] = []
        with stage(log, aid, "threat_intel", timings):
            ti_results = svc.query(payload, mode=cfg.threat_intel_mode, override=cfg.ti_override)
            ti_ev = to_evidence(ti_results, self.reg)
        tis = TISummary(
            queried=any(r.status not in (ThreatIntelStatus.NOT_QUERIED, ThreatIntelStatus.UNAVAILABLE) for r in ti_results),
            confirmed=any(r.status is ThreatIntelStatus.CONFIRMED_MALICIOUS_EVIDENCE for r in ti_results),
            suspicious=any(r.status is ThreatIntelStatus.SUSPICIOUS_MIXED for r in ti_results),
            statuses=[r.status.value for r in ti_results])

        all_ev = payload_ev + context_ev + action_ev + ti_ev
        with stage(log, aid, "decision", timings):
            groups = group_evidence(all_ev)
            comp = [m for m in matches if m.result is not MatchResult.INSUFFICIENT_CONTEXT]
            ctx_conf: Confidence | None = None
            if cfg.use_context and comp:
                ctx_conf = min((m.confidence for m in comp), key=lambda c: {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}[c])
            # Determine whether organization/identity context is present when context analysis is active.
            if not cfg.use_context:
                has_org_context = True
            elif ocr is not None and ocr.status == "no_text":
                has_org_context = False
            elif not ctx.is_empty():
                has_org_context = bool(ctx.get("organization") or ctx.get("service") or ctx.get("network"))
            else:
                has_org_context = True
            decision = decide(
                groups,
                sens,
                tis,
                context_confidence=ctx_conf,
                context_needed=payload.type is not PayloadType.PLAIN_TEXT,
                parse_ok=payload.parse_ok,
                has_org_context=has_org_context,
                ocr_status=ocr.status if ocr is not None else None,
                payload_type=payload.type.value,
            )

        if not cfg.use_context:
            limitations.append("Context analysis was not used in this configuration.")
        elif ctx.is_empty():
            limitations.append("No context was provided, so identity and purpose consistency were not assessed.")
        if ocr is not None and ocr.status in ("unavailable", "failed", "disabled", "no_text"):
            limitations.append(ocr.message)
        if any(r.status is ThreatIntelStatus.UNAVAILABLE for r in ti_results):
            limitations.append("Threat intelligence unavailable — local analysis only.")
        limitations.append("Static, pre-action analysis only: destinations were not visited, resolved or followed.")

        recs = build_recommendations(decision.level, payload, payload_ev + context_ev, ti_results)
        with stage(log, aid, "explain", timings):
            expl = build_explanation(level=decision.level, label=decision.label, trace=decision.trace, p=payload,
                                     ctx=ctx if cfg.use_context else None, sensitivity=sens, action_reasons=reasons,
                                     findings=payload_ev + context_ev, matches=matches, ti=ti_results,
                                     limitations=limitations, recommendations=recs)
        log.info("analysis=%s type=%s level=%s", aid, payload.type.value, decision.level.value)

        data = {
            "analysis_id": aid, "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "manifest": self.manifest(dataset_version, ocr, cfg, svc),
            "input": input_meta or {"image_name": None, "image_hash": None, "image_quality": None},
            "qr": {**(qr_meta or {"detected": None, "count": None, "decoder": None}), "payload_raw": redact_payload_raw(raw)},
            "payload": to_dict(payload),
            "ocr": self._ocr_dict(ocr, candidates),
            "context": to_dict(ctx) if cfg.use_context else None,
            "payload_findings": to_dict(payload_ev), "context_findings": to_dict(context_ev),
            "matching_findings": to_dict(matches), "action_findings": to_dict(action_ev),
            "threat_intel_findings": to_dict(ti_ev), "threat_intel_results": to_dict(ti_results),
            "evidence_groups": to_dict(groups),
            "assessment": {"level": decision.level.value, "label": decision.label, "confidence": decision.confidence.value,
                           "confidence_basis": decision.confidence_basis, "local_level": decision.local_level.value,
                           "trace": decision.trace, "basis": decision.basis,
                           "action_sensitivity": sens.value if sens else None,
                           "context_status": decision.context_status,
                           "context_incomplete": decision.context_incomplete},
            "explanation": expl, "recommendations": recs, "limitations": limitations,
            "config": cfg.to_dict(), "timings_ms": timings,
        }
        return AnalysisResult(data)
