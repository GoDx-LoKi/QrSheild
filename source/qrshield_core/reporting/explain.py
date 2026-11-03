"""Explainable report generation: WHAT was found, WHY it matters, WHERE it came from, WHAT matched / did not match,
WHAT remains uncertain, WHAT the user should verify. Generated deterministically from structured evidence."""
from __future__ import annotations

from typing import Any

from ..models import (
    SEVERITY_ORDER, AssessmentLevel as L, Context, Evidence, MatchRecord, MatchResult, Payload, PayloadType, Sensitivity,
    ThreatIntelStatus,
)
from ..threat_intel.base import ThreatIntelResult

VERIFY = {
    PayloadType.PAYMENT: "Verify the recipient through a trusted channel (ask staff, check the printed receipt or the merchant's official page) before completing the transaction.",
    PayloadType.URL: "Do not enter credentials or payment details. Open the organisation's website by typing its known address, or check the full destination before proceeding.",
    PayloadType.WIFI: "Ask the venue for the exact network name and security type before connecting.",
    PayloadType.CONTACT: "Compare the contact details with the organisation's official contact page before saving or using them.",
    PayloadType.SMS: "Do not send the pre-filled message. Contact the organisation through a number you already trust.",
    PayloadType.EMAIL: "Do not send the pre-filled email. Contact the organisation through an address you already trust.",
    PayloadType.DEEP_LINK: "Do not open the link. Install or open the application yourself from its official store listing.",
    PayloadType.PLAIN_TEXT: "Treat the text as untrusted; do not act on instructions it contains without verifying them independently.",
}

INTERPRETATION = {
    L.NO_MATERIAL_CONCERN: ("No indicator reached the level of a material concern in the evidence that was available. "
                            "This is NOT a statement that the QR code is safe: absence of findings can also mean missing context or a threat "
                            "that static, pre-action analysis cannot see."),
    L.NEEDS_VERIFICATION: ("At least one observation deserves checking before you act. Observations of this kind often have legitimate explanations "
                           "(listed below), so this is a prompt to verify, not a finding of fraud."),
    L.HIGH_CONCERN: ("Several independent observations, or a strong observation combined with a sensitive action, point the same way. "
                     "Legitimate explanations are still possible, but you should not perform the encoded action until you have verified it independently."),
    L.HARMFUL_CORROBORATED: ("Local evidence of high concern is corroborated by independent external detections of the destination. "
                             "Do not perform the encoded action. External detections are corroborating evidence, not infallible proof."),
}


def payload_summary(p: Payload) -> list[str]:
    nf, t = p.normalized_fields, p.type
    if not p.parse_ok:
        return ["The payload matched a known format but could not be safely normalized."] + p.notes
    if t is PayloadType.PAYMENT:
        out = [f"A {nf.get('rail', 'payment')} instruction (scheme: {nf.get('scheme')})."]
        out.append(f"Recipient: {nf.get('payee_name') or '(no name encoded)'}" + (f" — {nf['recipient']}" if nf.get("recipient") else ""))
        out.append("Amount: " + (f"{nf['amount']} {nf.get('currency') or ''}".strip() + " (fixed by the code)" if nf.get("amount") else "not fixed by the code"))
        if nf.get("ancillary_url"):
            out.append("Auxiliary URL: " + nf["ancillary_url_parsed"]["url_redacted"])
        return out
    if t is PayloadType.URL:
        return [f"A {nf.get('scheme') or 'scheme-less'} URL to host '{nf.get('host') or '(none)'}'" + (f", path '{nf['path']}'" if nf.get("path") else ""),
                f"Full (redacted) URL: {nf.get('url_redacted')}"]
    if t is PayloadType.WIFI:
        return [f"A Wi-Fi configuration for network “{nf.get('ssid')}” with {nf.get('auth_type')} security"
                + ("; a password is embedded (redacted)." if nf.get("password_present") else "; no password.")]
    if t is PayloadType.CONTACT:
        return [f"A {nf.get('format')} contact: {nf.get('name') or '(no name)'}, organisation {nf.get('organization') or '(none)'}.",
                f"Phones: {', '.join(nf.get('phones') or []) or 'none'}; emails: {', '.join(nf.get('emails') or []) or 'none'}; sites: {', '.join(nf.get('websites') or []) or 'none'}."]
    if t is PayloadType.SMS:
        return [f"A pre-filled SMS to {', '.join(nf.get('recipients') or []) or '(none)'}.", f"Message (OTP-like digits redacted): “{nf.get('body') or ''}”"]
    if t is PayloadType.EMAIL:
        return [f"A pre-filled email to {', '.join(nf.get('to') or []) or '(none)'}.", f"Subject: “{nf.get('subject') or ''}”; body (redacted): “{(nf.get('body') or '')[:160]}”"]
    if t is PayloadType.DEEP_LINK:
        return [f"An application link: scheme '{nf.get('scheme')}://' ({nf.get('app') or 'application not in the reference registry'}), operation: {nf.get('operation')}.",
                f"Parameters (values redacted): {', '.join(nf.get('param_names') or []) or 'none'}."]
    return [f"Text content ({nf.get('length')} characters): “{nf.get('text', '')[:160]}”"]


def context_summary(ctx: Context | None) -> list[str]:
    if ctx is None or ctx.is_empty():
        return ["No context was provided."]
    return [f"{a.attribute.replace('_', ' ').capitalize()}: “{a.value}” (source: {a.source}, confidence: {a.confidence.value})"
            for a in ctx.attributes if a.value.strip()]


def _notable(findings: list[Evidence]) -> list[Evidence]:
    return sorted([e for e in findings if SEVERITY_ORDER[e.severity] >= 1],
                  key=lambda e: (-SEVERITY_ORDER[e.severity], e.indicator_id))


def build_recommendations(level: L, p: Payload, findings: list[Evidence], ti: list[ThreatIntelResult]) -> list[str]:
    recs: list[str] = []
    if level is L.HARMFUL_CORROBORATED:
        recs.append("Do not perform the encoded action. Consider reporting the code to the organisation displaying it and to the relevant fraud-reporting channel.")
    elif level is L.HIGH_CONCERN:
        recs.append("Do not perform the encoded action until you have verified it independently.")
    if level is not L.NO_MATERIAL_CONCERN or p.type in (PayloadType.PAYMENT,):
        recs.append(VERIFY[p.type])
    for e in _notable(findings):
        if e.recommendation and e.recommendation not in recs:
            recs.append(e.recommendation)
    if any(r.status is ThreatIntelStatus.NO_RESULT for r in ti):
        recs.append("An external scan can be requested explicitly; note that this sends the URL to the provider.")
    if level is L.NO_MATERIAL_CONCERN:
        recs.append("Proceed with normal caution: QRShield performs static, pre-action analysis and cannot prove that a code is safe.")
    return recs[:8]


def build_explanation(*, level: L, label: str, trace: list[str], p: Payload, ctx: Context | None, sensitivity: Sensitivity | None,
                      action_reasons: list[str], findings: list[Evidence], matches: list[MatchRecord],
                      ti: list[ThreatIntelResult], limitations: list[str], recommendations: list[str]) -> dict[str, Any]:
    notable = _notable(findings)
    found = context_summary(ctx) + payload_summary(p)
    if sensitivity:
        found.append(f"Intended action: {p.action.replace('_', ' ')} — sensitivity {sensitivity.value.upper()} ({'; '.join(action_reasons)}).")
    why = [{"indicator_id": e.indicator_id, "title": e.title, "severity": e.severity.value, "family": e.family.value,
            "observation": e.observation, "expected": e.expected, "rationale": e.rationale,
            "plausible_exceptions": e.plausible_exceptions, "notes": e.notes} for e in notable]
    where = [{"indicator_id": e.indicator_id, "source": e.source.value, "context_provenance": e.provenance, "payload_field": e.payload_field,
              "context_attribute": e.context_attribute} for e in notable]
    matched = [f"{m.comparison}: “{m.expected}” ↔ “{m.observed}” — {m.result.value}" for m in matches
               if m.result in (MatchResult.MATCH, MatchResult.LIKELY_MATCH)]
    not_matched = [f"{m.comparison}: “{m.expected}” ↔ “{m.observed}” — {m.rationale}" for m in matches if m.result is MatchResult.MISMATCH]
    uncertain = [f"{m.comparison}: {m.rationale}" + (f" {m.exception_hint}" if m.exception_hint else "") for m in matches
                 if m.result in (MatchResult.UNCERTAIN, MatchResult.INSUFFICIENT_CONTEXT)] + limitations
    for r in ti:
        if r.status in (ThreatIntelStatus.UNAVAILABLE, ThreatIntelStatus.NO_RESULT, ThreatIntelStatus.NOT_QUERIED,
                        ThreatIntelStatus.RATE_LIMITED, ThreatIntelStatus.AUTH_FAILURE):
            uncertain.append(f"External corroboration: {r.message}")
    verify = [r for r in recommendations]
    seen_ex: list[str] = []
    for e in notable:
        for x in e.plausible_exceptions:
            if x not in seen_ex:
                seen_ex.append(x)
    ex_note = ("Possible legitimate explanations: " + "; ".join(seen_ex) + ".") if seen_ex else None
    interp = INTERPRETATION[level]
    text_lines = [label.upper(), "", "WHAT WAS FOUND"] + [f"  - {x}" for x in found]
    if why:
        text_lines += ["", "WHY IT MATTERS"] + [f"  - [{w['severity']}] {w['title']}: {w['observation']}" for w in why]
    if matched:
        text_lines += ["", "WHAT MATCHED"] + [f"  - {x}" for x in matched]
    if not_matched:
        text_lines += ["", "WHAT DID NOT MATCH"] + [f"  - {x}" for x in not_matched]
    if uncertain:
        text_lines += ["", "WHAT REMAINS UNCERTAIN"] + [f"  - {x}" for x in uncertain]
    text_lines += ["", "WHAT TO VERIFY"] + [f"  - {x}" for x in verify] + ([f"  - {ex_note}"] if ex_note else [])
    text_lines += ["", "INTERPRETATION", f"  {interp}"]
    return {
        "headline": label, "what_was_found": found, "why_it_matters": why, "where_it_came_from": where,
        "what_matched": matched, "what_did_not_match": not_matched, "what_remains_uncertain": uncertain,
        "what_to_verify": verify, "plausible_legitimate_explanations": seen_ex, "interpretation": interp,
        "decision_trace": trace, "text": "\n".join(text_lines),
    }
