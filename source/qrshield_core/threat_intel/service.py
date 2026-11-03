"""Threat-intel orchestration: privacy gating, URL selection, evidence conversion."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..models import Confidence, Evidence, Payload, PayloadType, Source, ThreatIntelStatus
from ..normalizer.common import parse_url
from ..rules import RuleRegistry
from .base import ThreatIntelPolicy, ThreatIntelProvider, ThreatIntelResult

MAX_URLS = 5


@dataclass
class UrlCandidate:
    parsed: dict[str, Any]
    field: str
    from_payment: bool = False


def candidate_urls(p: Payload) -> list[UrlCandidate]:
    nf, out = p.normalized_fields, []
    if p.type is PayloadType.URL and nf.get("host"):
        out.append(UrlCandidate(nf, "url"))
        for i, eu in enumerate(nf.get("embedded_urls", [])):
            pu = parse_url(eu) if isinstance(eu, str) else eu
            if pu.get("host"):
                out.append(UrlCandidate(pu, f"url.embedded[{i}]"))
    elif p.type is PayloadType.PAYMENT and nf.get("ancillary_url_parsed"):
        out.append(UrlCandidate(nf["ancillary_url_parsed"], "ancillary_url", True))
    elif p.type is PayloadType.DEEP_LINK:
        if nf.get("fallback_url"):
            pu = parse_url(nf["fallback_url"])
            if pu.get("host"):
                out.append(UrlCandidate(pu, "fallback_url"))
        for i, eu in enumerate(nf.get("embedded_urls", [])):
            pu = parse_url(eu) if isinstance(eu, str) else eu
            if pu.get("host"):
                out.append(UrlCandidate(pu, f"deeplink.embedded[{i}]"))
    elif p.type is PayloadType.CONTACT:
        out += [UrlCandidate(u, "website") for u in nf.get("websites_parsed", []) if u.get("host")]
    elif p.type in (PayloadType.SMS, PayloadType.EMAIL):
        out += [UrlCandidate(u, f"body.url[{i}]") for i, u in enumerate(nf.get("body_urls", []))]
    elif p.type is PayloadType.PLAIN_TEXT:
        out += [UrlCandidate(u, f"text.url[{i}]") for i, u in enumerate(nf.get("embedded_urls", []))]
    return out[:MAX_URLS]


class ThreatIntelService:
    def __init__(self, provider: ThreatIntelProvider | None, policy: ThreatIntelPolicy):
        self.provider = provider
        self.policy = policy

    def provider_state(self) -> dict[str, Any]:
        if self.provider is None:
            return {"provider": "none", "configured": False, "message": "No provider configured."}
        ok, msg = self.provider.configured()
        return {"provider": self.provider.name, "configured": ok, "message": msg or "Configured."}

    def query(self, p: Payload, *, mode: str, override: bool = False) -> list[ThreatIntelResult]:
        cands = candidate_urls(p)
        results: list[ThreatIntelResult] = []
        for c in cands:
            shown = c.parsed.get("url_redacted", "")
            name = self.provider.name if self.provider else "none"
            if mode == "off":
                r = ThreatIntelResult(name, "none", shown, ThreatIntelStatus.NOT_QUERIED, "External lookup was not requested for this analysis.")
            else:
                allowed, why = self.policy.check(c.parsed, from_payment=c.from_payment, override=override)
                if not allowed:
                    r = ThreatIntelResult(name, "none", shown, ThreatIntelStatus.NOT_QUERIED, why)
                elif self.provider is None:
                    r = ThreatIntelResult(name, "none", shown, ThreatIntelStatus.UNAVAILABLE, "Threat intelligence unavailable — local analysis only.")
                else:
                    ok, msg = self.provider.configured()
                    if not ok:
                        r = ThreatIntelResult(name, "none", shown, ThreatIntelStatus.UNAVAILABLE, "Threat intelligence unavailable — local analysis only. " + msg)
                    else:
                        # only the indicator itself is transmitted (redacted form == original for eligible URLs)
                        r = self.provider.submit_scan(shown) if mode == "scan" else self.provider.lookup(shown)
            r.payload_field = c.field
            results.append(r)
        return results


_RULE = {
    ThreatIntelStatus.CONFIRMED_MALICIOUS_EVIDENCE: "TI-001", ThreatIntelStatus.SUSPICIOUS_MIXED: "TI-002",
    ThreatIntelStatus.NO_KNOWN_MALICIOUS_REPORT: "TI-003", ThreatIntelStatus.NO_RESULT: "TI-004",
    ThreatIntelStatus.UNAVAILABLE: "TI-005", ThreatIntelStatus.NOT_QUERIED: "TI-006",
    ThreatIntelStatus.RATE_LIMITED: "TI-007", ThreatIntelStatus.AUTH_FAILURE: "TI-008",
}


def to_evidence(results: list[ThreatIntelResult], reg: RuleRegistry) -> list[Evidence]:
    out = []
    for r in results:
        obs = (f"{r.provider} — {r.query_type} for {r.url}: {r.message} "
               f"[{r.timestamp}{', cached' if r.cached else ''}]")
        out.append(reg.make(_RULE[r.status], obs, source=Source.THREAT_INTEL, confidence=Confidence.MEDIUM,
                            payload_field=r.payload_field, related_action="open_web_resource"))
    return out
