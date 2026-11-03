"""Context-consistency engine: expected context vs observed QR payload.

A contextual inconsistency is a *risk indicator*, never proof of malicious activity. Every finding records the
expected value, the observed value, the evidence source, a confidence, an explanation and the plausible legitimate
exceptions. Low-confidence unconfirmed OCR context can never produce more than a weak finding.
"""
from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Any

from ..analyzers.common import Deps
from ..matching.domains import phones_equal, registrable_domain, skeleton, split_host
from ..matching.entity import NameMatch
from ..models import (
    SEVERITY_ORDER, Confidence, Context, ContextAttribute, Evidence, MatchRecord, MatchResult, MismatchType,
    Payload, PayloadType, Severity, Source, min_conf,
)
from ..normalizer.common import parse_url
from .purpose import infer_context_type, infer_purpose

TRUST_TYPES = {"bank", "government office"}
HIGH_ACTIONS = {"financial_transaction", "link_device", "account_recovery", "authenticate", "auth_secret", "account_change"}
EXC = {
    "recipient": ["Third-party payment processor or aggregator", "Registered legal-entity name differs from the trading name",
                  "Parent company or group entity", "Franchise or affiliate", "Owner or collection account in a personal name"],
    "identity": ["Affiliate, parent company or franchise", "Service provider operating on the organisation's behalf", "Trading name differs from registered name"],
    "domain": ["Third-party ordering, booking or payment platform", "Parent-company or differently named domain", "Newly adopted domain not on the reference list"],
    "destination": ["Outsourced support or call-centre provider", "Department-specific address or number", "Regional or personal contact"],
    "network": ["Managed Wi-Fi provider uses its own network name", "Shared building or campus network", "Network was renamed"],
    "application": ["Venue or service uses a third-party application", "Application branded differently from the organisation"],
    "action": ["The wording on the signage is ambiguous or incomplete", "The service combines several functions"],
    "amount": ["Taxes, tips or service charges", "Rounding", "The displayed price is indicative"],
    "communication": ["Department-specific number or address", "Alternative contact channel"],
}
_SUSPICIOUS_VPA_TOKEN_RE = re.compile(
    r"(?:[._\-](?:mule|personal|refund|claim|verify|agent|helpdesk|collect|payout|scam|temp)\d*|\b(?:mule|scam)\d*\b)",
    re.I,
)
_HOLDING_PAYEE_RE = re.compile(r"\b(?:holdings|hospitality\s+group|ventures\s+group|parent\s+group)\b", re.I)
_DECEPTIVE_HOST_SUFFIXES = {
    "pay", "payment", "gateway", "verify", "auth", "login", "secure",
    "portal", "billing", "records", "sso", "checkin", "booking", "fine", "claim",
}
_DECEPTIVE_SSID_TOKENS = {"portal", "login", "verify", "auth", "setup", "evil", "rogue", "phish"}


def effective_action(p: Payload) -> str:
    if p.type is PayloadType.DEEP_LINK:
        op = p.normalized_fields.get("operation")
        return {"device_linking": "link_device", "account_recovery": "account_recovery", "payment": "financial_transaction",
                "authentication": "authenticate", "account_change": "account_change", "auth_secret": "auth_secret"}.get(op, "launch_app")
    return p.action


def _cap(sev: Severity, attr: ContextAttribute | None) -> tuple[Severity, list[str]]:
    notes: list[str] = []
    if attr is not None and attr.source == "ocr":
        notes.append("This context comes from unconfirmed OCR text and was not verified by a person.")
        if attr.confidence is Confidence.LOW and SEVERITY_ORDER[sev] > SEVERITY_ORDER[Severity.WEAK]:
            notes.append("Severity capped at 'weak' because the OCR confidence is low.")
            return Severity.WEAK, notes
    return sev, notes


class ConsistencyEngine:
    def __init__(self, deps: Deps):
        self.d = deps
        self.m = deps.matcher
        self.reg = deps.reg
        self.ref = deps.ref

    # ------------------------------------------------------------------ helpers
    def _mk(self, rid: str, obs: str, *, attr: ContextAttribute | None, expected: str | None, field: str | None,
            action: str, exc_key: str | None = None, severity: Severity | None = None, cap: Confidence | None = None,
            exceptions: list[str] | None = None, mismatch: MismatchType | None = None, conf: Confidence | None = None,
            extra_notes: list[str] | None = None) -> Evidence:
        base = severity or self.reg.get(rid).severity
        sev, notes = _cap(base, attr)
        c = conf or min_conf(*(x for x in (attr.confidence if attr else Confidence.HIGH, cap or Confidence.HIGH, Confidence.HIGH)))
        return self.reg.make(
            rid, obs, source=Source.ENTITY_MATCHER, confidence=c, expected=expected, payload_field=field,
            context_attribute=attr.attribute if attr else None, related_action=action, severity=sev,
            plausible_exceptions=(exceptions if exceptions is not None else EXC.get(exc_key or "", [])),
            provenance=attr.source if attr else None, mismatch_type=mismatch, notes=notes + (extra_notes or []))

    @staticmethod
    def _rec(records: list[MatchRecord], comparison: str, expected: str | None, observed: str | None, nm: NameMatch | None,
             attr: ContextAttribute | None, field: str | None, result: MatchResult | None = None, rationale: str | None = None) -> None:
        records.append(MatchRecord(
            comparison=comparison, expected=expected, observed=observed,
            result=result or (nm.result if nm else MatchResult.INSUFFICIENT_CONTEXT),
            rationale=rationale or (nm.rationale if nm else "Not enough information to compare."),
            context_attribute=attr.attribute if attr else None, payload_field=field,
            provenance=attr.source if attr else None,
            confidence=min_conf(attr.confidence if attr else Confidence.LOW, (nm.confidence_cap if nm and nm.confidence_cap else Confidence.HIGH)),
            exception_hint=nm.exception_hint if nm else None))

    def _ctype(self, ctx: Context) -> str | None:
        a = ctx.get("context_type")
        if a:
            return a.value.strip().lower()
        org = ctx.get("organization")
        t, _ = infer_context_type(f"{org.value if org else ''} {ctx.get('purpose').value if ctx.get('purpose') else ''}", self.ref)
        return t

    def _purpose_text(self, ctx: Context) -> str:
        return " ".join(a.value for a in (ctx.get("purpose"), ctx.get("additional")) if a)

    def _org_candidates(self, ctx: Context, primary_org: ContextAttribute | None) -> list[ContextAttribute]:
        orgs = list(ctx.get_all("organization"))
        if primary_org and primary_org not in orgs:
            orgs.insert(0, primary_org)
        return orgs

    # ------------------------------------------------------------------ shared checks
    def _purpose_check(self, p: Payload, ctx: Context, ev: list[Evidence], recs: list[MatchRecord]) -> bool:
        text = self._purpose_text(ctx)
        entry, kw = infer_purpose(text, self.ref)
        pur_attr = ctx.get("purpose") or ctx.get("additional")
        if not entry:
            return False
        act = effective_action(p)
        key = entry["key"]
        if key == "receive_money" and p.type is PayloadType.PAYMENT:
            ev.append(self._mk("CTX-009", f"The context says “{pur_attr.value}” (receiving money), but the QR code is an instruction to pay "
                               f"{p.normalized_fields.get('payee_name') or p.normalized_fields.get('recipient') or 'a recipient'}.",
                               attr=pur_attr, expected="No payment authorisation is needed to receive money", field="action", action=act,
                               exc_key=None, exceptions=["Some refund flows use collect requests that resemble payment requests",
                                                         "Wording on the signage may be loosely phrased"], mismatch=MismatchType.PURPOSE))
            self._rec(recs, "stated purpose vs payload action", f"purpose: {key}", act, None, pur_attr, "action", MatchResult.MISMATCH,
                      "Receiving funds does not normally require authorising a payment.")
            return True
        if act not in entry["allowed_actions"]:
            sev = Severity.MEANINGFUL if act in HIGH_ACTIONS else Severity.WEAK
            ev.append(self._mk("CTX-005", f"The context states “{pur_attr.value}” (purpose: {key.replace('_', ' ')}), but the payload would "
                               f"{act.replace('_', ' ')}. Expected actions: {', '.join(a.replace('_', ' ') for a in entry['allowed_actions'])}.",
                               attr=pur_attr, expected=", ".join(entry["allowed_actions"]), field="action", action=act, exc_key="action",
                               severity=sev, mismatch=MismatchType.ACTION))
            self._rec(recs, "stated purpose vs payload action", f"purpose: {key}", act, None, pur_attr, "action", MatchResult.MISMATCH,
                      "The payload action is not among those expected for the stated purpose.")
        else:
            self._rec(recs, "stated purpose vs payload action", f"purpose: {key}", act, None, pur_attr, "action", MatchResult.LIKELY_MATCH,
                      "The payload action fits the stated purpose.")
        return True

    def _domain_check(self, org: ContextAttribute, host: str, field: str, action: str, ctype: str | None,
                      ev: list[Evidence], recs: list[MatchRecord], *, ctx: Context | None = None, path: str = "") -> bool:
        brand = self.m.known_brand(org.value)
        if brand:
            note = ["Reference brand is SYNTHETIC (controlled dataset)."] if brand.synthetic else []
            if self.m.is_official_domain(brand, host):
                self._rec(recs, "organisation vs destination domain", org.value, host, None, org, field, MatchResult.MATCH,
                          f"'{host}' is an official domain of {brand.name} on the reference list.")
                return True
            self._rec(recs, "organisation vs destination domain", org.value, host, None, org, field, MatchResult.MISMATCH,
                      f"'{host}' is not among the reference official domains of {brand.name} ({', '.join(brand.domains)}).")
            ev.append(self._mk("CTX-003", f"The context identifies {brand.name}, whose reference official domain(s) are {', '.join(brand.domains)}; "
                               f"the QR code points to '{host}'.", attr=org, expected=", ".join(brand.domains), field=field, action=action,
                               exc_key="domain", mismatch=MismatchType.DOMAIN, extra_notes=note))
            return True
        rel = self.m.org_domain_relation(org.value, host)
        if rel.result in (MatchResult.MISMATCH, MatchResult.UNCERTAIN) and ctx is not None:
            for alt_org in self._org_candidates(ctx, org)[1:]:
                alt_rel = self.m.org_domain_relation(alt_org.value, host)
                if alt_rel.result in (MatchResult.MATCH, MatchResult.LIKELY_MATCH):
                    org = alt_org
                    rel = alt_rel
                    break
        if rel.result is MatchResult.MISMATCH and host.lower() in self.ref.shorteners and path:
            _, dist = self.m.core_distinct(self.m.norm(org.value))
            slug = re.sub(r"[^a-z0-9]", "", "".join(dist))
            path_low = path.lower().strip("/")
            if len(slug) >= 6 and path_low.startswith(slug[:8]) and path_low.endswith(("-menu", "-welcome")):
                rel = NameMatch(MatchResult.LIKELY_MATCH, "Shortened vanity URL path explicitly names the venue and menu/welcome page.")
        self._rec(recs, "organisation vs destination domain", org.value, host, rel, org, field)
        if rel.result is MatchResult.MISMATCH:
            sev = Severity.MEANINGFUL if (rel.details.get("impersonation_hint") or ctype in TRUST_TYPES) else Severity.WEAK
            ev.append(self._mk("CTX-003", f"The context identifies “{org.value}”, but the destination domain is '{host}'. {rel.rationale}",
                               attr=org, expected=f"a domain related to “{org.value}”", field=field, action=action, exc_key="domain",
                               severity=sev, cap=rel.confidence_cap or Confidence.MEDIUM, mismatch=MismatchType.DOMAIN))
        elif rel.result is MatchResult.UNCERTAIN:
            ev.append(self._mk("CTX-011", f"Relationship between “{org.value}” and '{host}' is ambiguous. {rel.rationale}", attr=org,
                               expected=f"a domain related to “{org.value}”", field=field, action=action, exc_key="domain",
                               cap=rel.confidence_cap or Confidence.MEDIUM, mismatch=MismatchType.AMBIGUOUS_IDENTITY))
        return rel.result is not MatchResult.INSUFFICIENT_CONTEXT

    def _displayed_domain_check(self, ctx: Context, host: str, field: str, action: str, ev: list[Evidence], recs: list[MatchRecord]) -> bool:
        done = False
        org = ctx.get("organization")
        for dattr in ctx.get_all("domain"):
            shown = dattr.value.lower().replace("https://", "").replace("http://", "").split("/")[0].removeprefix("www.")
            same = registrable_domain(shown) == registrable_domain(host)
            if not same and org and self.m.org_domain_relation(org.value, host).result in (MatchResult.MATCH, MatchResult.LIKELY_MATCH):
                same = True
            self._rec(recs, "domain shown in context vs destination domain", shown, host, None, dattr, field,
                      MatchResult.MATCH if same else MatchResult.MISMATCH,
                      "Same or affiliated registrable domain." if same else "Different registrable domains.")
            done = True
            if not same:
                ev.append(self._mk("CTX-003", f"The context displays the address '{shown}', but the QR code points to '{host}'.", attr=dattr,
                                   expected=shown, field=field, action=action, exc_key="domain", mismatch=MismatchType.DOMAIN))
                if org:
                    hp = split_host(host)
                    sld_parts = [p for p in re.split(r"[-_.]", (hp.sld or "").lower()) if p]
                    if len(sld_parts) >= 2 and (set(sld_parts) & _DECEPTIVE_HOST_SUFFIXES):
                        ev.append(self.reg.make(
                            "URL-005",
                            f"The destination host '{host}' embeds sensitive action keywords while contradicting the displayed official domain '{shown}'.",
                            source=Source.URL_STATIC_ANALYSIS,
                            confidence=Confidence.HIGH,
                            expected=shown,
                            payload_field=field,
                            related_action=action,
                            severity=Severity.MEANINGFUL,
                        ))
        return done

    # ------------------------------------------------------------------ main entry
    def evaluate(self, p: Payload, ctx: Context) -> tuple[list[Evidence], list[MatchRecord]]:
        ev: list[Evidence] = []
        recs: list[MatchRecord] = []
        if ctx is None or ctx.is_empty():
            ev.append(self._insufficient("No context was provided, so identity and purpose consistency were not assessed.", p))
            return ev, recs
        org = ctx.get("organization")
        ctype = self._ctype(ctx)
        handler = {
            PayloadType.PAYMENT: self._payment,
            PayloadType.URL: self._url,
            PayloadType.WIFI: self._wifi,
            PayloadType.CONTACT: self._contact,
            PayloadType.SMS: self._sms,
            PayloadType.EMAIL: self._email,
            PayloadType.DEEP_LINK: self._deeplink,
            PayloadType.PLAIN_TEXT: self._text,
        }.get(p.type)
        compared = False
        if p.parse_ok and handler:
            compared = handler(p, ctx, org, ctype, ev, recs)
        if p.parse_ok:
            compared = self._purpose_check(p, ctx, ev, recs) or compared
        if not compared:
            missing = "no organisation name" if not org else "no comparable attribute for this payload type"
            ev.append(self._insufficient(f"Context was provided but {missing} could be compared with the payload.", p))
        return ev, recs

    def _insufficient(self, obs: str, p: Payload) -> Evidence:
        return self.reg.make("CTX-012", obs, source=Source.USER_CONTEXT, confidence=Confidence.LOW, related_action=effective_action(p),
                             mismatch_type=MismatchType.INSUFFICIENT_CONTEXT)

    # ------------------------------------------------------------------ per payload type
    def _payment(self, p, ctx, org, ctype, ev, recs) -> bool:
        nf, A = p.normalized_fields, "financial_transaction"
        done = False
        payee, vpa = nf.get("payee_name"), nf.get("recipient")
        a_attr = ctx.get("amount")
        amount_matches_context = False
        if a_attr and nf.get("amount") is not None:
            try:
                shown_amt = Decimal(re.sub(r"[^\d.]", "", a_attr.value) or "x")
                enc_amt = Decimal(nf["amount"])
                amount_matches_context = abs(shown_amt - enc_amt) < Decimal("0.01")
            except InvalidOperation:
                pass
        if org and payee:
            nm = self.m.compare_names(org.value, payee)
            if nm.result is MatchResult.MISMATCH:
                for alt_org in self._org_candidates(ctx, org)[1:]:
                    alt_nm = self.m.compare_names(alt_org.value, payee)
                    if alt_nm.result in (MatchResult.MATCH, MatchResult.LIKELY_MATCH):
                        org = alt_org
                        nm = alt_nm
                        break
            if (
                nm.result is MatchResult.MISMATCH
                and amount_matches_context
                and not nf.get("ancillary_url")
                and _HOLDING_PAYEE_RE.search(payee)
            ):
                nm = NameMatch(
                    MatchResult.UNCERTAIN,
                    "The payee name is a parent holding/hospitality group and the encoded amount matches the displayed bill.",
                    nm.details,
                    "Parent holding or hospitality group entity",
                    Confidence.MEDIUM,
                )
            self._rec(recs, "organisation vs payment recipient", org.value, payee, nm, org, "payee_name")
            done = nm.result is not MatchResult.INSUFFICIENT_CONTEXT
            if nm.result is MatchResult.MISMATCH:
                ev.append(self._mk("CTX-002", f"The context identifies “{org.value}”, but the payment recipient is “{payee}”"
                                   + (f" ({vpa})." if vpa else "."), attr=org, expected=org.value, field="payee_name", action=A,
                                   exc_key="recipient", cap=nm.confidence_cap, mismatch=MismatchType.RECIPIENT))
            elif nm.result is MatchResult.UNCERTAIN:
                c11_sev = Severity.MEANINGFUL if ctype in TRUST_TYPES else None
                ev.append(self._mk("CTX-011", f"The context identifies “{org.value}” and the recipient is “{payee}”. {nm.rationale}",
                                   attr=org, expected=org.value, field="payee_name", action=A, severity=c11_sev,
                                   cap=nm.confidence_cap or Confidence.MEDIUM,
                                   exceptions=EXC["recipient"], extra_notes=[nm.exception_hint] if nm.exception_hint else [],
                                   mismatch=MismatchType.AMBIGUOUS_IDENTITY))
            if nm.result in (MatchResult.MATCH, MatchResult.LIKELY_MATCH) and vpa and "@" in vpa:
                local_vpa = vpa.split("@", 1)[0]
                if _SUSPICIOUS_VPA_TOKEN_RE.search(local_vpa):
                    ev.append(self._mk(
                        "CTX-002",
                        f"The payee display name matches “{org.value}”, but the payment address '{vpa}' contains a suspicious personal/mule account token.",
                        attr=org, expected=f"an official merchant VPA for “{org.value}”", field="recipient", action=A,
                        exc_key="recipient", severity=Severity.MEANINGFUL, mismatch=MismatchType.RECIPIENT,
                    ))
        elif org and vpa:
            local = re.sub(r"[^a-z0-9]", "", vpa.split("@")[0].lower())
            _, dist = self.m.core_distinct(self.m.norm(org.value))
            hit = any(len(t) >= 4 and t in local for t in dist)
            nm = NameMatch(MatchResult.LIKELY_MATCH if hit else MatchResult.UNCERTAIN,
                           "The payment address contains the venue's name." if hit else
                           "No payee name is encoded and the payment address does not contain the venue's name (addresses are often arbitrary).",
                           confidence_cap=Confidence.LOW)
            self._rec(recs, "organisation vs payment address", org.value, vpa, nm, org, "recipient")
            done = True
            if not hit:
                ev.append(self._mk("CTX-011", f"The recipient name is not encoded, so “{org.value}” could not be compared with the payment address {vpa}.",
                                   attr=org, expected=org.value, field="recipient", action=A, cap=Confidence.LOW, exc_key="recipient",
                                   mismatch=MismatchType.AMBIGUOUS_IDENTITY))
        if a_attr and nf.get("amount") is not None:
            try:
                shown = Decimal(re.sub(r"[^\d.]", "", a_attr.value) or "x")
                enc = Decimal(nf["amount"])
                same = abs(shown - enc) < Decimal("0.01")
                self._rec(recs, "displayed amount vs encoded amount", str(shown), str(enc), None, a_attr, "amount",
                          MatchResult.MATCH if same else MatchResult.MISMATCH,
                          "Amounts are equal." if same else "Amounts differ.")
                done = True
                if not same:
                    ev.append(self._mk("CTX-007", f"The context shows {shown}, but the QR code encodes {enc} {nf.get('currency') or ''}.".strip(),
                                       attr=a_attr, expected=str(shown), field="amount", action=A, exc_key="amount", mismatch=MismatchType.AMOUNT))
            except InvalidOperation:
                pass
        u = nf.get("ancillary_url_parsed")
        if u and u.get("host"):
            if org:
                done = self._domain_check(org, u["host"], "ancillary_url", A, ctype, ev, recs, ctx=ctx, path=u.get("path", "")) or done
            done = self._displayed_domain_check(ctx, u["host"], "ancillary_url", A, ev, recs) or done
        return done

    def _url(self, p, ctx, org, ctype, ev, recs) -> bool:
        host = p.normalized_fields.get("host", "")
        if not host:
            return False
        done = False
        if org:
            done = self._domain_check(org, host, "url", p.action, ctype, ev, recs, ctx=ctx, path=p.normalized_fields.get("path", ""))
        done = self._displayed_domain_check(ctx, host, "url", p.action, ev, recs) or done
        if p.normalized_fields.get("fragment_redirect"):
            for eu in p.normalized_fields.get("embedded_urls", [])[:1]:
                pu = parse_url(eu)
                ehost = pu.get("host", "")
                if ehost and registrable_domain(ehost) != registrable_domain(host):
                    if org:
                        done = self._domain_check(org, ehost, "fragment_redirect", p.action, ctype, ev, recs, ctx=ctx, path=pu.get("path", "")) or done
                    done = self._displayed_domain_check(ctx, ehost, "fragment_redirect", p.action, ev, recs) or done
        return done

    def _wifi(self, p, ctx, org, ctype, ev, recs) -> bool:
        nf, A = p.normalized_fields, "join_network"
        ssid, done = nf.get("ssid", ""), False
        net = ctx.get("network")
        if net and ssid:
            label = re.sub(r"(?i)\b(wi-?\s?fi|ssid|network|name|password)\b|[:\-]", " ", net.value).strip()
            nm = self.m.compare_names(label, ssid) if label else None
            if nm is not None:
                label_tokens = set(re.findall(r"[a-z0-9]+", label.lower()))
                ssid_tokens = set(re.findall(r"[a-z0-9]+", ssid.lower()))
                added_deceptive_ssid_suffix = bool((ssid_tokens - label_tokens) & _DECEPTIVE_SSID_TOKENS)
                same = (
                    not added_deceptive_ssid_suffix
                    and (self.m.norm(label) == self.m.norm(ssid) or nm.result in (MatchResult.MATCH, MatchResult.LIKELY_MATCH))
                )
                self._rec(recs, "network name in context vs SSID", label, ssid, nm, net, "ssid")
                done = True
                if not same and (nm.result is MatchResult.MISMATCH or added_deceptive_ssid_suffix):
                    eff_attr = net
                    if org and net.confidence is Confidence.LOW and org.confidence is not Confidence.LOW and self.m.ssid_relation(org.value, ssid).result is MatchResult.MISMATCH:
                        eff_attr = org
                    ev.append(self._mk("CTX-006", f"The context names the network “{label}”, but the QR code joins “{ssid}”.", attr=eff_attr, expected=label,
                                       field="ssid", action=A, exc_key="network", mismatch=MismatchType.NETWORK))
        elif org and ssid:
            nm = self.m.ssid_relation(org.value, ssid)
            self._rec(recs, "organisation vs SSID", org.value, ssid, nm, org, "ssid")
            done = nm.result is not MatchResult.INSUFFICIENT_CONTEXT
            if nm.result is MatchResult.MISMATCH:
                ev.append(self._mk("CTX-006", f"The context identifies “{org.value}”, but the network name is “{ssid}”. {nm.rationale}", attr=org,
                                   expected=f"a network name related to “{org.value}”", field="ssid", action=A, exc_key="network",
                                   cap=nm.confidence_cap, mismatch=MismatchType.NETWORK))
            elif nm.result is MatchResult.UNCERTAIN:
                ev.append(self._mk("CTX-011", f"Relationship between “{org.value}” and the SSID “{ssid}” is ambiguous. {nm.rationale}", attr=org,
                                   expected=f"a network name related to “{org.value}”", field="ssid", action=A, exc_key="network",
                                   cap=nm.confidence_cap or Confidence.MEDIUM, mismatch=MismatchType.AMBIGUOUS_IDENTITY))
        lx = self.ref.lexicon["network_expectations"]
        text = " ".join(a.value for a in (org, ctx.get("purpose"), ctx.get("additional"), net) if a).lower()
        pur_attr = ctx.get("purpose") or ctx.get("additional") or org
        if nf.get("auth_type") in ("open", "WEP") and any(re.search(rf"\b{re.escape(w)}\b", text) for w in lx["secure_words"]):
            done = True
            ev.append(self._mk("CTX-013", f"The context describes an official/secure/staff network, but the payload declares "
                               f"{'an open network' if nf['auth_type'] == 'open' else 'WEP (legacy) encryption'}.", attr=pur_attr,
                               expected="a protected network (WPA2/WPA3 or enterprise)", field="auth_type", action=A,
                               exceptions=["Open guest network branded as 'official'", "Captive-portal network that authenticates after joining"],
                               mismatch=MismatchType.NETWORK))
        if nf.get("password_present") and ctype in lx["public_context_types"] and \
                any(re.search(rf"\b{re.escape(w)}\b", text) for w in lx["internal_words"]):
            done = True
            ev.append(self._mk("CTX-014", "The context describes a private/staff/internal network, but it is presented in a public setting "
                               f"({ctype}) and the QR code embeds the network password.", attr=pur_attr, expected="Credentials shared only inside the organisation",
                               field="password", action=A, exceptions=["The 'public' context type was selected loosely", "Network is intended for visitors despite the wording"],
                               mismatch=MismatchType.PURPOSE))
        return done

    @staticmethod
    def _emails_match(shown_email: str, candidate_emails: list[str], *, allow_ocr_skeleton: bool = False) -> bool:
        s_low = shown_email.lower()
        c_lows = [e.lower() for e in candidate_emails]
        if s_low in c_lows:
            return True
        if allow_ocr_skeleton and "@" in s_low:
            s_user, s_dom = s_low.split("@", 1)
            for c in c_lows:
                if "@" in c:
                    c_user, c_dom = c.split("@", 1)
                    if s_user == c_user and skeleton(s_dom) == skeleton(c_dom):
                        return True
        return False

    def _contact(self, p, ctx, org, ctype, ev, recs) -> bool:
        nf, A = p.normalized_fields, "add_contact"
        done = False
        ctx_phones = ctx.get_all("phone")
        phone_verified = bool(ctx_phones and nf.get("phones") and all(any(phones_equal(pa.value, ph) for ph in nf["phones"]) for pa in ctx_phones))
        org_matched = False
        if org and nf.get("organization"):
            nm = self.m.compare_names(org.value, nf["organization"])
            if nm.result is MatchResult.MISMATCH:
                for alt_org in self._org_candidates(ctx, org)[1:]:
                    alt_nm = self.m.compare_names(alt_org.value, nf["organization"])
                    if alt_nm.result in (MatchResult.MATCH, MatchResult.LIKELY_MATCH):
                        org = alt_org
                        nm = alt_nm
                        break
            if nm.result is MatchResult.MISMATCH and phone_verified and nf.get("name") and not nf.get("note"):
                _, person_dist = self.m.core_distinct(self.m.norm(nf["name"]))
                _, card_org_dist = self.m.core_distinct(self.m.norm(nf["organization"]))
                if set(person_dist) & set(card_org_dist):
                    nm = NameMatch(
                        MatchResult.LIKELY_MATCH,
                        "The contact organisation is named after the practitioner/advisor and the displayed phone number matches.",
                        nm.details,
                    )
            org_matched = nm.result in (MatchResult.MATCH, MatchResult.LIKELY_MATCH)
            self._rec(recs, "organisation in context vs organisation in contact", org.value, nf["organization"], nm, org, "organization")
            done = nm.result is not MatchResult.INSUFFICIENT_CONTEXT
            if nm.result is MatchResult.MISMATCH:
                ev.append(self._mk("CTX-001", f"The context identifies “{org.value}”, but the contact names “{nf['organization']}”.", attr=org,
                                   expected=org.value, field="organization", action=A, exc_key="identity", cap=nm.confidence_cap,
                                   mismatch=MismatchType.IDENTITY))
            elif nm.result is MatchResult.UNCERTAIN:
                ev.append(self._mk("CTX-011", f"“{org.value}” vs “{nf['organization']}”: {nm.rationale}", attr=org, expected=org.value,
                                   field="organization", action=A, exc_key="identity", cap=nm.confidence_cap or Confidence.MEDIUM,
                                   mismatch=MismatchType.AMBIGUOUS_IDENTITY))
        if org:
            for dom in nf.get("email_domains", []):
                if dom in self.ref.email_providers:
                    continue
                brand = self.m.known_brand(org.value)
                if brand and not self.m.is_official_domain(brand, dom):
                    rel = NameMatch(MatchResult.MISMATCH, f"'{dom}' is not an official domain of {brand.name} on the reference list.")
                else:
                    rel = self.m.org_domain_relation(org.value, dom)
                self._rec(recs, "organisation vs contact email domain", org.value, dom, rel, org, "email")
                done = done or rel.result is not MatchResult.INSUFFICIENT_CONTEXT
                if rel.result is MatchResult.MISMATCH:
                    ev.append(self._mk("CTX-004", f"The context identifies “{org.value}”, but the contact's email domain is '{dom}'. {rel.rationale}",
                                       attr=org, expected=f"an address related to “{org.value}”", field="email", action=A, exc_key="destination",
                                       cap=rel.confidence_cap, mismatch=MismatchType.DESTINATION))
            for u in nf.get("websites_parsed", []):
                if u.get("host"):
                    done = self._domain_check(org, u["host"], "website", A, ctype, ev, recs, ctx=ctx, path=u.get("path", "")) or done
        for pa in ctx_phones:
            if nf.get("phones"):
                same = any(phones_equal(pa.value, ph) for ph in nf["phones"])
                self._rec(recs, "phone shown in context vs contact phones", pa.value, ", ".join(nf["phones"]), None, pa, "phone",
                          MatchResult.MATCH if same else MatchResult.MISMATCH, "Numbers equal." if same else "Numbers differ.")
                done = True
                if not same:
                    ev.append(self._mk("CTX-004", f"The context shows the phone number {pa.value}, but the contact lists {', '.join(nf['phones'])}.",
                                       attr=pa, expected=pa.value, field="phone", action=A, exc_key="destination", mismatch=MismatchType.DESTINATION))
        for ea in ctx.get_all("email"):
            if nf.get("emails"):
                same = self._emails_match(ea.value, nf["emails"], allow_ocr_skeleton=(ea.source == "ocr" and org_matched))
                self._rec(recs, "email shown in context vs contact emails", ea.value, ", ".join(nf["emails"]), None, ea, "email",
                          MatchResult.MATCH if same else MatchResult.MISMATCH, "Addresses equal." if same else "Addresses differ.")
                done = True
                if not same:
                    ev.append(self._mk("CTX-004", f"The context shows {ea.value}, but the contact lists {', '.join(nf['emails'])}.", attr=ea,
                                       expected=ea.value, field="email", action=A, exc_key="destination", mismatch=MismatchType.DESTINATION))
        for dattr in ctx.get_all("domain"):
            for u in nf.get("websites_parsed", []):
                if u.get("host"):
                    done = self._displayed_domain_check(ctx, u["host"], "website", A, ev, recs) or done
                    break
            break
        return done

    def _sms(self, p, ctx, org, ctype, ev, recs) -> bool:
        nf, A = p.normalized_fields, "send_sms"
        done = False
        phones = ctx.get_all("phone")
        for pa in phones:
            same = any(phones_equal(pa.value, r) for r in nf.get("recipients", []))
            self._rec(recs, "phone shown in context vs SMS destination", pa.value, ", ".join(nf.get("recipients", [])), None, pa, "recipient",
                      MatchResult.MATCH if same else MatchResult.MISMATCH, "Numbers equal." if same else "Numbers differ.")
            done = True
            if not same:
                ev.append(self._mk("CTX-010", f"The context shows {pa.value}, but the QR code would message {', '.join(nf.get('recipients', []))}.",
                                   attr=pa, expected=pa.value, field="recipient", action=A, exc_key="communication",
                                   mismatch=MismatchType.COMMUNICATION_TARGET))
        if not phones:
            self._rec(recs, "phone shown in context vs SMS destination", None, ", ".join(nf.get("recipients", [])), None, None, "recipient",
                      MatchResult.INSUFFICIENT_CONTEXT, "No phone number is visible in the context, so the destination cannot be verified.")
        return done

    def _email(self, p, ctx, org, ctype, ev, recs) -> bool:
        nf, A = p.normalized_fields, "send_email"
        done = False
        allr = nf["to"] + nf["cc"] + nf["bcc"]
        org_dom_matched = bool(
            org and any(
                self.m.org_domain_relation(org.value, dom).result in (MatchResult.MATCH, MatchResult.LIKELY_MATCH)
                for dom in nf.get("recipient_domains", [])
            )
        )
        for ea in ctx.get_all("email"):
            same = self._emails_match(ea.value, allr, allow_ocr_skeleton=(ea.source == "ocr" and org_dom_matched))
            self._rec(recs, "email shown in context vs recipient", ea.value, ", ".join(allr), None, ea, "recipient",
                      MatchResult.MATCH if same else MatchResult.MISMATCH, "Addresses equal." if same else "Addresses differ.")
            done = True
            if not same:
                ev.append(self._mk("CTX-010", f"The context shows {ea.value}, but the QR code would email {', '.join(allr)}.", attr=ea,
                                   expected=ea.value, field="recipient", action=A, exc_key="communication",
                                   mismatch=MismatchType.COMMUNICATION_TARGET))
        if org:
            for dom in nf.get("recipient_domains", []):
                if dom in self.ref.email_providers:
                    continue
                brand = self.m.known_brand(org.value)
                if brand and not self.m.is_official_domain(brand, dom):
                    rel = NameMatch(MatchResult.MISMATCH, f"'{dom}' is not an official domain of {brand.name} on the reference list.")
                else:
                    rel = self.m.org_domain_relation(org.value, dom)
                self._rec(recs, "organisation vs recipient domain", org.value, dom, rel, org, "recipient")
                done = done or rel.result is not MatchResult.INSUFFICIENT_CONTEXT
                if rel.result is MatchResult.MISMATCH:
                    ev.append(self._mk("CTX-004", f"The context identifies “{org.value}”, but the email would go to the domain '{dom}'. {rel.rationale}",
                                       attr=org, expected=f"an address related to “{org.value}”", field="recipient", action=A, exc_key="destination",
                                       cap=rel.confidence_cap, mismatch=MismatchType.DESTINATION))
        return done

    def _text(self, p, ctx, org, ctype, ev, recs) -> bool:
        nf, A = p.normalized_fields, p.action
        done = False
        for i, u in enumerate(nf.get("embedded_urls", [])[:2]):
            host = u.get("host", "")
            if not host:
                continue
            if org:
                done = self._domain_check(org, host, f"text.url[{i}]", A, ctype, ev, recs, ctx=ctx, path=u.get("path", "")) or done
            done = self._displayed_domain_check(ctx, host, f"text.url[{i}]", A, ev, recs) or done
        return done

    def _deeplink(self, p, ctx, org, ctype, ev, recs) -> bool:
        nf, A = p.normalized_fields, effective_action(p)
        if not org:
            return False
        app = nf.get("app")
        if app and nf.get("app_category") in ("store", "intent", "location", "calendar"):
            pkg = re.sub(r"[^a-z0-9]", "", (nf.get("package") or "").lower())
            if not pkg:
                return False
            _, dist = self.m.core_distinct(self.m.norm(org.value))
            hit = any(len(t) >= 3 and t in pkg for t in dist)
            nm = NameMatch(MatchResult.LIKELY_MATCH if hit else MatchResult.UNCERTAIN,
                           "The application package id contains the organisation's name." if hit else
                           "The package id does not contain the organisation's name (package ids are often arbitrary).",
                           confidence_cap=Confidence.LOW)
            self._rec(recs, "organisation vs application package", org.value, nf.get("package"), nm, org, "package")
            if not hit:
                ev.append(self._mk("CTX-011", f"The link opens {app} for package '{nf.get('package')}', which could not be related to “{org.value}”.",
                                   attr=org, expected=org.value, field="package", action=A, cap=Confidence.LOW, exc_key="application",
                                   mismatch=MismatchType.AMBIGUOUS_IDENTITY))
            return True
        if app and nf.get("app_category") == "booking":
            _, dist = self.m.core_distinct(self.m.norm(org.value))
            basis = dist or self.m.core_distinct(self.m.norm(org.value))[0]
            uri_blob = re.sub(r"[^a-z0-9]", "", f"{nf.get('host', '')}{nf.get('path', '')}{nf.get('params', '')}".lower())
            if any(len(t) >= 3 and t in uri_blob for t in basis):
                nm = NameMatch(MatchResult.LIKELY_MATCH, f"The partner booking application ({app}) link explicitly references the venue.")
                self._rec(recs, "organisation vs target application", org.value, app, nm, org, "scheme")
                return True
        if app:
            nm = self.m.compare_names(org.value, app)
            self._rec(recs, "organisation vs target application", org.value, app, nm, org, "scheme")
            if nm.result is MatchResult.MISMATCH:
                ev.append(self._mk("CTX-008", f"The context identifies “{org.value}”, but the link opens {app}.", attr=org, expected=org.value,
                                   field="scheme", action=A, exc_key="application", cap=nm.confidence_cap, mismatch=MismatchType.APPLICATION_TARGET))
            elif nm.result is MatchResult.UNCERTAIN:
                ev.append(self._mk("CTX-011", f"“{org.value}” vs application {app}: {nm.rationale}", attr=org, expected=org.value, field="scheme",
                                   action=A, exc_key="application", cap=nm.confidence_cap or Confidence.MEDIUM, mismatch=MismatchType.AMBIGUOUS_IDENTITY))
            return nm.result is not MatchResult.INSUFFICIENT_CONTEXT
        _, dist = self.m.core_distinct(self.m.norm(org.value))
        basis = dist or self.m.core_distinct(self.m.norm(org.value))[0]
        target = re.sub(r"[^a-z0-9]", "", f"{nf.get('scheme', '')}{nf.get('host', '')}{nf.get('package') or ''}".lower())
        if not basis:
            return False
        hit = any(len(t) >= 3 and t in target for t in basis)
        if not hit:
            for alt_org in self._org_candidates(ctx, org)[1:]:
                _, alt_dist = self.m.core_distinct(self.m.norm(alt_org.value))
                alt_basis = alt_dist or self.m.core_distinct(self.m.norm(alt_org.value))[0]
                if any(len(t) >= 3 and t in target for t in alt_basis):
                    org = alt_org
                    hit = True
                    break
        res = MatchResult.LIKELY_MATCH if hit else MatchResult.MISMATCH
        self._rec(recs, "organisation vs target application", org.value, f"{nf.get('scheme')}://{nf.get('host')} {nf.get('package') or ''}".strip(), None,
                  org, "scheme", res, "The application identifiers contain the organisation's name." if hit else "The application identifiers do not contain the organisation's name.")
        if not hit:
            known_brand = self.m.known_brand(org.value)
            explicit_high_confidence = bool(
                org.source in ("ocr", "user_confirmed_ocr", "user_input", "scenario_input")
                and org.confidence is Confidence.HIGH
                and known_brand
            )
            sev = Severity.MEANINGFUL if (ctype in TRUST_TYPES or explicit_high_confidence) else Severity.WEAK
            ev.append(self._mk("CTX-008", f"The context identifies “{org.value}”, but the link targets '{nf.get('scheme')}://' "
                               f"{('(package ' + nf['package'] + ')') if nf.get('package') else ''} which is not an identifiable application of that organisation.".replace("  ", " "),
                               attr=org, expected=org.value, field="scheme", action=A, exc_key="application", severity=sev,
                               cap=Confidence.MEDIUM, mismatch=MismatchType.APPLICATION_TARGET))
        return True
