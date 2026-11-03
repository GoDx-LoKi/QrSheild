"""Application deep-link analysis. Never launches or resolves the link."""
from __future__ import annotations

from ..models import Confidence, Evidence, Family, Payload, Severity, Source
from ..normalizer.common import parse_url
from .common import Deps
from .url import analyze_url_dict

A = "launch_app"
OP_TEXT = {
    "device_linking": "link another device to an account",
    "account_recovery": "recover or reset an account",
    "account_change": "change or delete account data",
    "payment": "start a payment or transfer",
    "authentication": "sign in or exchange an authentication token",
    "auth_secret": "provision an authentication secret",
}
_HIGH_PRIV_PARAMS = {
    "grant_custody", "custody", "allowance", "delegate", "mandate",
    "private_key", "seed", "mnemonic",
}


def analyze_deeplink(p: Payload, deps: Deps) -> list[Evidence]:
    reg, ref, nf = deps.reg, deps.ref, p.normalized_fields
    S = Source.QR_PAYLOAD
    out: list[Evidence] = []
    if not p.parse_ok:
        return [reg.make("TXT-006", "; ".join(p.notes) or "The deep link could not be safely normalized.", source=S, related_action=A)]
    scheme = nf["scheme"]
    if nf["known_scheme"]:
        out.append(reg.make("DL-007", f"The scheme '{scheme}://' maps to {nf['app']} ({nf['app_category']}).", source=S, payload_field="scheme", related_action=A))
    else:
        out.append(reg.make("DL-001", f"'{scheme}://' is a custom scheme not in the reference registry; any installed app can claim it.", source=S,
                            payload_field="scheme", related_action=A, confidence=Confidence.MEDIUM))
    op = nf.get("operation")
    guest_params = {n.lower() for n in nf.get("guest_token_params", [])}
    param_low = {n.lower() for n in nf.get("param_names", [])} - guest_params
    has_custody_param = bool(param_low & _HIGH_PRIV_PARAMS)
    has_auth_code_param = op in ("authentication", "device_linking", "account_recovery") and bool(param_low & {"code", "otp", "pin", "passcode", "secret"})
    if op in OP_TEXT and op != "content":
        dl2_sev = Severity.MEANINGFUL if (has_custody_param or has_auth_code_param) else None
        out.append(reg.make("DL-002", f"The link appears to {OP_TEXT[op]} (operation keywords: {', '.join(nf.get('operations') or [op])}).",
                            source=S, payload_field="path/parameters", related_action=A, confidence=Confidence.MEDIUM,
                            severity=dl2_sev))
    sens = sorted({
        n for n in nf.get("param_names", [])
        if n.lower() not in guest_params and (n.lower() in ref.url_keywords["sensitive_param"] or n.lower() in {"uuid", "pub_key", "secret"})
    })
    if sens and op != "auth_secret":
        if has_custody_param:
            e_dl3 = reg.make("DL-003", f"High-privilege custody/delegation parameter(s) {', '.join(sens)} are present (values redacted).",
                             source=S, payload_field="parameters", related_action=A, severity=Severity.MEANINGFUL,
                             independent_group="deeplink_custody_grant")
            e_dl3.family = Family.TRANSACTION
            out.append(e_dl3)
        else:
            out.append(reg.make("DL-003", f"Parameter name(s) {', '.join(sens)} are present (values redacted).", source=S, payload_field="parameters", related_action=A))
    if nf["param_count"] > 8:
        out.append(reg.make("DL-004", f"The link carries {nf['param_count']} parameters.", source=S, payload_field="parameters", related_action=A))
    if op == "auth_secret":
        out.append(reg.make("DL-006", "The otpauth link provisions a one-time-password secret (value redacted).", source=S, payload_field="secret", related_action=A))
    if nf.get("fallback_url"):
        out.append(reg.make("DL-005", "The Android intent defines a browser fallback URL.", source=S, payload_field="fallback_url", related_action=A))
        out += analyze_url_dict(parse_url(nf["fallback_url"]), deps, field="fallback_url", action=A)
    for i, eu in enumerate(nf.get("embedded_urls", [])[:2]):
        out += analyze_url_dict(parse_url(eu), deps, field=f"parameters.url[{i}]", action=A)
    return out
