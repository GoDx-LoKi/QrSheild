"""Contact payload analysis (vCard / MECARD). Never imports the contact."""
from __future__ import annotations

from ..matching.domains import registrable_domain
from ..models import Confidence, Evidence, MatchResult, Payload, Source
from .common import Deps
from .url import analyze_url_dict

A = "add_contact"


def analyze_contact(p: Payload, deps: Deps) -> list[Evidence]:
    reg, ref, m, nf = deps.reg, deps.ref, deps.matcher, p.normalized_fields
    S = Source.QR_PAYLOAD
    out: list[Evidence] = []
    if not p.parse_ok:
        return [reg.make("TXT-006", "; ".join(p.notes) or "The contact payload could not be safely normalized.", source=S, related_action=A)]
    org = nf.get("organization")
    email_domains = nf.get("email_domains", [])
    for ph, ok in zip(nf.get("phones", []), nf.get("phones_valid", [])):
        if not ok:
            out.append(reg.make("CON-005", f"The phone value '{ph}' is not a plausible phone number.", source=S, payload_field="phone", related_action=A))
    for dom in email_domains:
        if dom in ref.email_providers:
            out.append(reg.make("CON-004", f"The email address uses the free provider '{dom}'.", source=S, payload_field="email", related_action=A))
        elif org:
            rel = m.org_domain_relation(org, dom)
            if rel.result == MatchResult.MISMATCH:
                out.append(reg.make("CON-001", f"The email domain '{dom}' does not appear related to the organisation '{org}'. {rel.rationale}",
                                    source=Source.ENTITY_MATCHER, payload_field="email", related_action=A, confidence=Confidence.MEDIUM))
    sites = nf.get("websites_parsed", [])
    for u in sites:
        host = u.get("host", "")
        if org and host:
            rel = m.org_domain_relation(org, host)
            if rel.result == MatchResult.MISMATCH:
                out.append(reg.make("CON-002", f"The website '{host}' does not appear related to the organisation '{org}'. {rel.rationale}",
                                    source=Source.ENTITY_MATCHER, payload_field="website", related_action=A, confidence=Confidence.MEDIUM))
        out += analyze_url_dict(u, deps, field="website", action=A)
    site_regs = {u.get("registrable") for u in sites if u.get("registrable")}
    mail_regs = {registrable_domain(d) for d in email_domains if d not in ref.email_providers}
    if site_regs and mail_regs and not (site_regs & mail_regs):
        out.append(reg.make("CON-003", f"Email domain(s) {sorted(mail_regs)} differ from website domain(s) {sorted(site_regs)}.",
                            source=Source.ENTITY_MATCHER, payload_field="email/website", related_action=A, confidence=Confidence.MEDIUM))
    if nf.get("note"):
        out += deps.request_evidence(nf["note"], field_name="note", related_action=A)
    return out
