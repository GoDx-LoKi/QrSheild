"""Qualitative decision policy. There is NO numeric score and NO probability.

Levels: no_material_concern < needs_verification < high_concern < harmful_corroborated.

Principles
* Action sensitivity and external evidence are modifiers, not anomalies.
* "Harmful / corroborated" needs strong external corroboration on top of local HIGH concern.
* No single weak indicator and no single mismatch can reach HARMFUL (and a lone weak indicator never escalates).
* Missing context, failed OCR or an unavailable provider never raise the level on a clean payload, and when
  context-dependent payload indicators are present (or OCR returns no_text on an outbound communication channel),
  missing/partial context never silently downgrades a verification-worthy item to no_material_concern.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..evidence.grouping import EvidenceGroup
from ..models import (
    LEVEL_LABELS, LEVEL_ORDER, SEVERITY_ORDER, AssessmentLevel, Confidence, Family, Sensitivity, Severity,
    ThreatIntelStatus,
)

L = AssessmentLevel

# Context-dependent payload indicators whose safety depends on verifying the surrounding visual identity/context.
CONTEXT_DEPENDENT_WEAK_IDS = {
    "URL-003", "URL-011",
    "DL-001", "DL-002", "DL-003", "DL-004", "DL-005", "DL-006",
    "CON-001", "CON-002", "CON-003",
}


@dataclass
class TISummary:
    queried: bool = False
    confirmed: bool = False
    suspicious: bool = False
    statuses: list[str] = field(default_factory=list)


@dataclass
class Decision:
    level: AssessmentLevel
    label: str
    local_level: AssessmentLevel
    confidence: Confidence
    confidence_basis: str
    trace: list[str] = field(default_factory=list)
    basis: dict = field(default_factory=dict)
    context_status: str = "complete"
    context_incomplete: bool = False


def _ge(g: EvidenceGroup, s: Severity) -> bool:
    return SEVERITY_ORDER[g.strength] >= SEVERITY_ORDER[s]


def decide(
    groups: list[EvidenceGroup],
    sensitivity: Sensitivity | None,
    ti: TISummary | None,
    *,
    context_confidence: Confidence | None,
    context_needed: bool,
    parse_ok: bool,
    has_org_context: bool = True,
    ocr_status: str | None = None,
    payload_type: str | None = None,
) -> Decision:
    trace: list[str] = []
    anomalies = [g for g in groups if g.family not in (Family.ACTION, Family.EXTERNAL_CORROBORATION) and _ge(g, Severity.WEAK)]
    meaningful = [g for g in anomalies if _ge(g, Severity.MEANINGFUL)]
    strong = [g for g in anomalies if g.strength is Severity.STRONG]
    action_high = sensitivity is Sensitivity.HIGH

    if not context_needed:
        context_status = "not_applicable"
        context_incomplete = False
    elif context_confidence is None:
        context_status = "missing"
        context_incomplete = True
    elif not has_org_context or context_confidence is Confidence.LOW:
        context_status = "partial"
        context_incomplete = True
    else:
        context_status = "complete"
        context_incomplete = False

    basis = {
        "independent_anomaly_families": len(anomalies),
        "meaningful_or_stronger_families": len(meaningful),
        "strong_families": len(strong),
        "action_sensitivity": sensitivity.value if sensitivity else "not assessed",
        "families": [g.family.value for g in anomalies],
        "context_status": context_status,
        "context_incomplete": context_incomplete,
    }

    level = L.NO_MATERIAL_CONCERN
    if strong and (action_high or len(anomalies) >= 2):
        level = L.HIGH_CONCERN
        trace.append("R1: a strong indicator together with " + ("HIGH action sensitivity" if action_high else "a second independent evidence family") + " → high concern.")
    elif len(meaningful) >= 2 and action_high:
        level = L.HIGH_CONCERN
        trace.append("R2: two or more independent evidence families with meaningful anomalies and HIGH action sensitivity → high concern.")
    elif len(anomalies) >= 3 and meaningful:
        level = L.HIGH_CONCERN
        trace.append("R3: three or more independent evidence families, at least one meaningful → high concern.")
    elif strong or meaningful:
        level = L.NEEDS_VERIFICATION
        trace.append("R4: at least one meaningful (or strong) anomaly in a single family → needs verification.")
        if action_high:
            trace.append("   (HIGH action sensitivity raises the consequence of the anomaly but does not by itself add evidence.)")
    elif len(anomalies) >= 2:
        level = L.NEEDS_VERIFICATION
        trace.append("R5: two independent weak indicators → needs verification.")
    elif anomalies:
        trace.append("R6: a single weak indicator was observed; it is reported as informational and does not change the assessment.")
    else:
        trace.append("R7: no anomalous indicator was observed in the evidence that was available.")

    # Calibrated escalation for clearly security-relevant weak indicators.
    # This may only raise a low/no-concern result; it never downgrades an
    # already stronger decision and R0..R0c are disabled when context/OCR evidence
    # is unavailable or explicitly low-confidence.
    ids = {i for g in anomalies for i in g.indicator_ids}
    high_consequence_weak = bool(ids & {
        "PAY-002", "PAY-003", "PAY-005", "PAY-006", "PAY-007", "PAY-010",
        "CTX-007",
        "WIFI-001", "WIFI-002", "WIFI-005",
    })
    medium_wifi_security_weak = bool(ids & {"WIFI-001", "WIFI-002", "WIFI-005"})
    application_target_risk = bool(ids & {"DL-002", "DL-003", "DL-004", "DL-005", "DL-006", "CTX-008"})
    active_ctx_dep_ids = set(CONTEXT_DEPENDENT_WEAK_IDS)
    if ocr_status == "no_text" and context_confidence is None:
        active_ctx_dep_ids.discard("URL-003")
    context_dependent_weak = bool(ids & active_ctx_dep_ids)
    context_ready = bool(parse_ok) and (not context_needed or (context_confidence is not None and context_confidence is not Confidence.LOW))
    if level is L.NO_MATERIAL_CONCERN and context_ready:
        if anomalies and action_high and high_consequence_weak:
            level = L.NEEDS_VERIFICATION
            trace.append("R0: a security-relevant weak indicator was observed on a HIGH-consequence action → needs verification.")
        elif anomalies and action_high and application_target_risk:
            level = L.NEEDS_VERIFICATION
            trace.append("R0a: an application/deep-link target risk was observed on a HIGH-consequence action → needs verification.")
        elif anomalies and application_target_risk and sensitivity is Sensitivity.MEDIUM:
            level = L.NEEDS_VERIFICATION
            trace.append("R0b: an unverified or sensitive application target was observed on a MEDIUM-consequence action → needs verification.")
        elif anomalies and medium_wifi_security_weak and sensitivity is Sensitivity.MEDIUM:
            level = L.NEEDS_VERIFICATION
            trace.append("R0c: an open, legacy-encrypted, or malformed Wi-Fi security condition was observed on a MEDIUM-consequence network join → needs verification.")

    # Fail-safe against silent context-failure downgrades (P0 #3):
    # 1. R0d: If a context-dependent payload/target indicator is present (e.g., unrecognized domain/brand URL-011,
    #    unverified deep-link target DL-001..006, or contact card missing org/identity CON-001..003) and organization
    #    context is missing or occluded (has_org_context=False), escalate to needs_verification rather than silently
    #    downgrading to no_material_concern.
    # 2. R0e: If OCR recognised no text in the scene (ocr_status == "no_text") for an outbound email communication
    #    payload whose recipient identity requires visual context verification, require verification.
    if level is L.NO_MATERIAL_CONCERN and bool(parse_ok):
        if anomalies and not has_org_context and context_dependent_weak:
            level = L.NEEDS_VERIFICATION
            trace.append(
                "R0d: a context-dependent payload or target indicator was observed while organization/identity "
                "context was missing or incomplete → needs verification."
            )
        elif ocr_status == "no_text" and (payload_type or "").lower() == "email":
            level = L.NEEDS_VERIFICATION
            trace.append(
                "R0e: no surrounding text was recognised by OCR on an outbound communication payload whose "
                "recipient identity requires visual context verification → needs verification."
            )

    local = level

    if ti and ti.confirmed:
        if LEVEL_ORDER[local] >= LEVEL_ORDER[L.HIGH_CONCERN]:
            level = L.HARMFUL_CORROBORATED
            trace.append("R8: local high concern plus strong external corroboration of a malicious destination → harmful / corroborated.")
        else:
            level = max(local, L.HIGH_CONCERN, key=lambda x: LEVEL_ORDER[x])
            trace.append("R9: strong external detections on the destination raise the assessment to at least high concern; "
                         "it is not 'harmful' because local evidence alone did not reach high concern.")
    elif ti and ti.suspicious and level is L.NO_MATERIAL_CONCERN:
        level = L.NEEDS_VERIFICATION
        trace.append("R10: a small number of external detections (mixed/suspicious) → needs verification.")
    if ti and ti.queried and not ti.confirmed and not ti.suspicious:
        trace.append("External lookup: no corroborating detections were returned (this is not a statement that the destination is safe).")

    # confidence in the assessment (evidence completeness), never a probability
    if not parse_ok:
        conf, why = Confidence.LOW, "the payload could not be fully normalised"
    elif context_needed and context_confidence is None:
        conf, why = Confidence.LOW, "no usable context was available, so identity/purpose consistency was not assessed"
    elif context_needed and context_confidence is Confidence.LOW:
        conf, why = Confidence.LOW, "context came from low-confidence extraction"
    elif context_needed and context_confidence is Confidence.MEDIUM:
        conf, why = Confidence.MEDIUM, "context had medium confidence"
    else:
        conf, why = (Confidence.HIGH, "payload and context were both available") if context_needed else (Confidence.MEDIUM, "context is not required to interpret this payload")
    if LEVEL_ORDER[level] >= LEVEL_ORDER[L.HIGH_CONCERN] and (strong or (ti and ti.confirmed)) and conf is not Confidence.LOW:
        conf, why = Confidence.HIGH, why + "; strong indicator present"
    return Decision(
        level, LEVEL_LABELS[level], local, conf, why, trace, basis,
        context_status=context_status, context_incomplete=context_incomplete,
    )
