"""Action sensitivity: how much harm an unintended execution could cause (LOW / MEDIUM / HIGH).

Sensitivity is a modifier of other evidence. It is never, by itself, evidence of malicious intent.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..analyzers.common import Deps
from ..context.consistency import TRUST_TYPES
from ..models import Confidence, Context, Evidence, Payload, PayloadType, SENS_ORDER, Sensitivity, Source

HIGH_DL_OPS = {"device_linking", "account_recovery", "authentication", "payment", "account_change", "auth_secret"}
_HOST_SENSITIVE_TOKENS = {
    "pay", "payment", "gateway", "verify", "auth", "login", "secure",
    "portal", "billing", "records", "sso", "checkin", "booking", "fine", "claim",
}


@dataclass
class ActionAssessment:
    level: Sensitivity
    reasons: list[str] = field(default_factory=list)


def _max(a: Sensitivity, b: Sensitivity) -> Sensitivity:
    return a if SENS_ORDER[a] >= SENS_ORDER[b] else b


def assess_action(p: Payload, ctx: Context | None, payload_ev: list[Evidence], context_ev: list[Evidence],
                  ctype: str | None, deps: Deps) -> ActionAssessment:
    nf, ref = p.normalized_fields, deps.ref
    ids = {e.indicator_id for e in payload_ev}
    ctx_ids = {e.indicator_id for e in context_ev}
    level, why = Sensitivity.LOW, []
    sensitive_request = bool(ids & {"COM-001", "COM-002", "COM-003"})

    if p.type is PayloadType.PAYMENT:
        level, why = Sensitivity.HIGH, ["initiates a financial transaction"]
    elif p.type is PayloadType.URL:
        toks = {t for t in re.split(r"[^a-z0-9\-]+", (nf.get("path") or "").lower()) if t}
        sld_toks = {t for t in re.split(r"[^a-z0-9]+", (nf.get("sld") or "").lower()) if t}
        login = bool(toks & set(ref.url_keywords["login_path"]))
        pay = bool(toks & set(ref.url_keywords["payment_path"]))
        dl = (nf.get("path") or "").lower().rsplit(".", 1)[-1] in ref.url_keywords["download_ext"]
        cred_param = any(n.lower() in {"password", "passwd", "pwd", "otp", "pin", "passcode"} for n in nf.get("query_names", []))
        if nf.get("scheme") in {"javascript", "data", "file", "vbscript"}:
            level, why = Sensitivity.HIGH, ["a script or local-resource scheme could run code in some scanners"]
        elif dl:
            level, why = Sensitivity.HIGH, ["the link points to an installable file type"]
        elif nf.get("fragment_redirect"):
            level, why = Sensitivity.HIGH, ["the URL contains a client-side fragment redirect to an external resource"]
        elif login or pay or cred_param:
            what = "sign-in/verification" if login else "payment"
            if ctype in TRUST_TYPES or cred_param or pay:
                level, why = Sensitivity.HIGH, [f"the page path suggests {what}, where sensitive data is typically entered"]
            else:
                level, why = Sensitivity.MEDIUM, [f"the page path suggests {what}"]
        elif ("CTX-003" in ctx_ids and "URL-005" in (ids | ctx_ids) and bool(sld_toks & _HOST_SENSITIVE_TOKENS)):
            level, why = Sensitivity.HIGH, ["the destination domain embeds sensitive authentication/payment keywords while contradicting the displayed domain"]
        elif ctype in TRUST_TYPES:
            level, why = Sensitivity.MEDIUM, ["the link is presented in a financial/government context"]
        else:
            level, why = Sensitivity.LOW, ["opens a web page; no sensitive operation is indicated"]
    elif p.type is PayloadType.WIFI:
        level, why = Sensitivity.MEDIUM, ["joins a wireless network"]
        if ctx_ids & {"CTX-006", "CTX-013"} and nf.get("auth_type") in {"open", "WEP"}:
            level, why = Sensitivity.HIGH, ["joins a weakly protected network while the context conflicts with the network identity"]
        elif (
            nf.get("auth_type") == "open"
            and not nf.get("hidden")
            and ctx is not None
            and ctx.get("network") is not None
            and not (ctx_ids & {"CTX-006", "CTX-011", "CTX-013", "CTX-014"})
            and re.search(r"\b(?:guest\s+wi-?fi|free\s+wi-?fi|public\s+wi-?fi|complimentary\s+wi-?fi)\b", (ctx.get("purpose").value if ctx.get("purpose") else ""), re.I)
        ):
            level, why = Sensitivity.LOW, ["joins an explicitly disclosed venue guest Wi-Fi network with matching printed SSID"]
    elif p.type is PayloadType.CONTACT:
        level, why = Sensitivity.MEDIUM, ["adds a contact record to the device"]
        if sensitive_request:
            level, why = Sensitivity.HIGH, ["the contact carries a request for sensitive information"]
    elif p.type in (PayloadType.SMS, PayloadType.EMAIL):
        kind = "SMS" if p.type is PayloadType.SMS else "email"
        level, why = Sensitivity.MEDIUM, [f"composes a pre-filled {kind}"]
        if sensitive_request:
            level, why = Sensitivity.HIGH, [f"the pre-filled {kind} asks for credentials, financial or personal information"]
    elif p.type is PayloadType.DEEP_LINK:
        op = nf.get("operation")
        if op in HIGH_DL_OPS:
            level, why = Sensitivity.HIGH, [f"launches an application to {op.replace('_', ' ')}"]
        elif nf.get("known_scheme"):
            level, why = Sensitivity.LOW, ["opens a known application to view content"]
        else:
            level, why = Sensitivity.MEDIUM, ["launches an application that is not in the reference registry"]
    else:
        if p.action == "initiate_call":
            level, why = Sensitivity.MEDIUM, ["starts a phone call"]
        elif "COM-001" in ids and (nf.get("embedded_phones") or nf.get("embedded_urls")):
            level, why = Sensitivity.HIGH, ["text directs the user to disclose credentials or secret digits via phone or link"]
        elif sensitive_request:
            level, why = Sensitivity.MEDIUM, ["text that asks for sensitive information"]
        else:
            level, why = Sensitivity.LOW, ["displays text"]
    return ActionAssessment(level, why)


def action_evidence(a: ActionAssessment, p: Payload, deps: Deps) -> Evidence:
    return deps.reg.make(
        "ACT-001", f"Action '{p.action.replace('_', ' ')}': {a.level.value.upper()} sensitivity — {'; '.join(a.reasons)}.",
        source=Source.ACTION_ANALYZER, confidence=Confidence.MEDIUM, related_action=p.action,
        notes=["Sensitivity measures the consequence of execution; it is not evidence of malicious intent."])
