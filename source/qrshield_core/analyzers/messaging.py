"""SMS and email payload analysis. Never sends a message."""
from __future__ import annotations

from ..models import Confidence, Evidence, Payload, Source
from .common import Deps
from .url import analyze_url_dict, find_lookalikes
from ..matching.domains import split_host
from ..normalizer.common import has_hidden_chars


def analyze_sms(p: Payload, deps: Deps) -> list[Evidence]:
    reg, nf = deps.reg, p.normalized_fields
    S, A = Source.QR_PAYLOAD, "send_sms"
    out: list[Evidence] = []
    if not p.parse_ok:
        return [reg.make("TXT-006", "; ".join(p.notes) or "The SMS payload could not be safely normalized.", source=S, related_action=A)]
    rec, valid = nf.get("recipients", []), nf.get("recipients_valid", [])
    if not all(valid):
        bad = [r for r, v in zip(rec, valid) if not v]
        out.append(reg.make("SMS-001", f"Destination(s) {bad} are not plausible phone numbers or short codes.", source=S, payload_field="recipient", related_action=A))
    if len(rec) > 1:
        out.append(reg.make("SMS-002", f"The payload addresses {len(rec)} recipients.", source=S, payload_field="recipient", related_action=A))
    if nf.get("body_present"):
        out.append(reg.make("SMS-003", "The QR code pre-fills the message text.", source=S, payload_field="body", related_action=A))
        out += deps.request_evidence(nf["body"], field_name="body", related_action=A)
    if nf.get("body_has_hidden_chars"):
        out.append(reg.make("TXT-001", "The message body contains hidden or control characters.", source=S, payload_field="body", related_action=A))
    for i, u in enumerate(nf.get("body_urls", [])):
        out += analyze_url_dict(u, deps, field=f"body.url[{i}]", action=A)
    return out


def analyze_email(p: Payload, deps: Deps) -> list[Evidence]:
    reg, ref, nf = deps.reg, deps.ref, p.normalized_fields
    S, A = Source.QR_PAYLOAD, "send_email"
    out: list[Evidence] = []
    if not p.parse_ok:
        return [reg.make("TXT-006", "; ".join(p.notes) or "The email payload could not be safely normalized.", source=S, related_action=A)]
    allr = nf["to"] + nf["cc"] + nf["bcc"]
    if not all(nf.get("recipients_valid", [])):
        out.append(reg.make("EML-004", "At least one recipient is not a plausible email address.", source=S, payload_field="recipient", related_action=A))
    if len(allr) > 1 or nf["bcc"]:
        out.append(reg.make("EML-001", f"The payload has {len(allr)} recipient(s)" + (" including a hidden (bcc) recipient." if nf["bcc"] else "."),
                            source=S, payload_field="recipient", related_action=A))
    for dom in nf.get("recipient_domains", []):
        if dom in ref.email_providers:
            out.append(reg.make("EML-002", f"The recipient uses the free provider '{dom}'.", source=S, payload_field="recipient", related_action=A))
        else:
            hp = split_host(dom)
            fake = {"registrable": hp.registrable, "sld": hp.sld, "subdomains": hp.subdomains, "is_ip": False}
            for h in find_lookalikes(fake, deps):
                out.append(reg.make("EML-003", f"The recipient domain '{dom}' resembles or embeds '{h['brand']}' ({h['official']}) — {h['kind']}.",
                                    source=Source.URL_STATIC_ANALYSIS, payload_field="recipient", related_action=A,
                                    confidence=Confidence.MEDIUM, expected=h["official"]))
    text = f"{nf.get('subject', '')}\n{nf.get('body', '')}"
    out += deps.request_evidence(text, field_name="subject/body", related_action=A)
    if nf.get("body_has_hidden_chars"):
        out.append(reg.make("TXT-001", "The subject/body contains hidden or control characters.", source=S, payload_field="body", related_action=A))
    for i, u in enumerate(nf.get("body_urls", [])):
        out += analyze_url_dict(u, deps, field=f"body.url[{i}]", action=A)
    return out
