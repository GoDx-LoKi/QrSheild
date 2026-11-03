"""Plain-text / unknown payload analysis. Unknown is never treated as safe."""
from __future__ import annotations

from ..models import Evidence, Payload, Source
from .common import Deps
from .url import analyze_url_dict


def analyze_text(p: Payload, deps: Deps) -> list[Evidence]:
    reg, ref, nf = deps.reg, deps.ref, p.normalized_fields
    S = Source.QR_PAYLOAD
    A = p.action
    out: list[Evidence] = []
    if not p.parse_ok:
        out.append(reg.make("TXT-006", "; ".join(p.notes) or "The payload is empty or could not be safely normalized.", source=S, related_action=A))
    if nf.get("subtype") == "tel":
        out.append(reg.make("TXT-005", "The payload is a tel: URI that would start a phone call.", source=S, related_action=A))
    elif nf.get("subtype") == "text":
        out.append(reg.make("TXT-004", f"Not recognised as a supported action ({nf.get('classification_reason')}); treated as text.", source=S, related_action=A))
    if nf.get("has_hidden_chars"):
        out.append(reg.make("TXT-001", "The text contains hidden, bidirectional-override or control characters.", source=S, payload_field="text", related_action=A))
    if nf.get("length", 0) > ref.thresholds["max_payload_length"]:
        out.append(reg.make("TXT-003", f"The payload is {nf['length']} characters long.", source=S, payload_field="text", related_action=A))
    found = [k for k in ("embedded_urls", "embedded_emails", "embedded_phones") if nf.get(k)]
    if found:
        out.append(reg.make("TXT-002", "The text contains embedded " + ", ".join(k.replace("embedded_", "") for k in found) + ".", source=S, payload_field="text", related_action=A))
    for i, u in enumerate(nf.get("embedded_urls", [])):
        out += analyze_url_dict(u, deps, field=f"text.url[{i}]", action=A)
    out += deps.request_evidence(nf.get("text", ""), field_name="text", related_action=A)
    return out
