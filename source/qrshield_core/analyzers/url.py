"""Static URL analysis. Nothing is fetched, resolved or followed."""
from __future__ import annotations

import re
from typing import Any

from ..matching.domains import edit_distance, registrable_domain, skeleton, split_host
from ..models import Confidence, Evidence, Severity, Source
from ..normalizer.common import parse_url
from .common import Deps

DANGEROUS = {"javascript", "data", "file", "vbscript"}


def find_lookalikes(u: dict[str, Any], deps: Deps, limit: int = 2) -> list[dict[str, str]]:
    """Compare a parsed host against the small reference brand list (homoglyph, typo, embedded name)."""
    reg, sld, subs = u.get("registrable") or "", u.get("sld") or "", u.get("subdomains") or []
    if not reg or u.get("is_ip"):
        return []
    brands = deps.ref.brands
    for b in brands:
        if reg in {registrable_domain(d) for d in b.domains}:
            return []  # official domain of a known brand: nothing to flag
    hits: list[dict[str, str]] = []
    for b in brands:
        for d in b.domains:
            hp = split_host(d)
            bl = hp.sld
            if len(bl) < 4:
                continue
            kind = None
            if sld != bl and skeleton(sld) == skeleton(bl):
                kind = "homoglyph"
            elif len(bl) >= 6 and 0 < edit_distance(sld, bl) <= (1 if len(bl) < 9 else 2):
                kind = "typo"
            if kind:
                hits.append({"rule": "URL-004", "brand": b.name, "official": d, "kind": kind, "synthetic": str(b.synthetic)})
                break
            parts = re.split(r"[-_.]", sld)
            if bl in parts or (len(bl) >= 5 and bl in sld and sld != bl):
                kind = "embedded in domain label"
            elif len(bl) >= 4 and any(bl in s.replace("-", "") for s in subs):
                kind = "embedded in subdomain"
            if kind:
                hits.append({"rule": "URL-005", "brand": b.name, "official": d, "kind": kind, "synthetic": str(b.synthetic)})
                break
        if len(hits) >= limit:
            break
    return hits


def analyze_url_dict(u: dict[str, Any], deps: Deps, *, field: str = "url", action: str = "open_web_resource") -> list[Evidence]:
    reg, ref = deps.reg, deps.ref
    S = Source.URL_STATIC_ANALYSIS
    out: list[Evidence] = []

    def add(rid: str, obs: str, **kw: Any) -> None:
        out.append(reg.make(rid, obs, source=S, payload_field=field, related_action=action, **kw))

    if not u.get("parse_ok", True):
        out.append(reg.make("TXT-006", "The URL could not be parsed safely and is reported as text.", source=Source.QR_PAYLOAD,
                            payload_field=field, related_action=action))
        return out
    scheme, host = u.get("scheme", ""), u.get("host", "")
    if scheme in DANGEROUS:
        add("URL-013", f"The scheme is '{scheme}:', which is not an ordinary web destination.")
    elif scheme == "http":
        add("URL-001", "The URL uses HTTP (not HTTPS).")
    elif scheme not in ("https", ""):
        add("URL-021", f"The URL uses the '{scheme}:' scheme.")
    if u.get("scheme_missing"):
        add("URL-015", "The payload is a bare domain/path without a scheme; the scanner decides how to complete it.")
    if u.get("userinfo_present"):
        u7_sev = Severity.STRONG if u.get("is_ip") else None
        add("URL-007", "The URL contains user:password@ information before the host; the real host is the part after '@'.", severity=u7_sev)
    if host:
        if u.get("is_ip"):
            if u.get("special_host"):
                add("URL-018", f"The host is the IP address {host} ({u.get('special_reason')}).")
            else:
                add("URL-002", f"The host is the raw public IP address {host}.")
        elif u.get("obfuscated_ip"):
            add("URL-019", f"The host '{host}' is an IP address written in a non-standard (integer/hex/octal) form.")
        else:
            if u.get("special_host"):
                add("URL-018", f"The host '{host}' is a {u.get('special_reason')}.")
            if u.get("punycode"):
                add("URL-008", f"The host contains internationalised characters (decoded: {u.get('decoded_host')}).")
            if u.get("mixed_script"):
                add("URL-009", f"A label in '{u.get('decoded_host')}' mixes characters from more than one script.")
            if host in ref.shorteners or u.get("registrable") in ref.shorteners:
                cat = ref.shorteners.get(host) or ref.shorteners.get(u.get("registrable"), "url_shortener")
                add("URL-003", f"'{u.get('registrable') or host}' is a known {cat.replace('_', ' ')} service; the final destination is not visible and was not resolved.")
            if len(u.get("subdomains", [])) > ref.thresholds["max_subdomain_depth"]:
                add("URL-010", f"The host has {len(u['subdomains'])} subdomain labels.")
            for h in find_lookalikes(u, deps):
                if h["rule"] == "URL-004":
                    add("URL-004", f"'{u['registrable']}' resembles '{h['official']}' ({h['brand']}) by {h['kind']}.",
                        expected=h["official"], confidence=Confidence.MEDIUM,
                        notes=["Reference brand is SYNTHETIC (controlled dataset)."] if h["synthetic"] == "True" else [])
                else:
                    add("URL-005", f"The name '{h['brand']}' appears {h['kind']} of '{u['registrable']}', which is not an official domain on the reference list ({h['official']}).",
                        expected=h["official"], confidence=Confidence.MEDIUM,
                        notes=["Reference brand is SYNTHETIC (controlled dataset)."] if h["synthetic"] == "True" else [])
    port = u.get("port")
    if port not in (None, 80, 443):
        add("URL-014", f"The URL specifies port {port}.")
    path_tokens = [t for t in re.split(r"[^a-z0-9\-]+", (u.get("path") or "").lower()) if t]
    query_names_low = {n.lower() for n in u.get("query_names", [])}
    hit_kw = sorted({k for k in ref.url_keywords["sensitive_path"] if k in path_tokens})
    if not hit_kw and ("request" in path_tokens or "payments" in host.lower()) and (
        {"recipient", "amount"} <= query_names_low or {"payee", "amount"} <= query_names_low
    ):
        hit_kw = ["payment_request"]
    if hit_kw:
        add("URL-011", f"The path contains: {', '.join(hit_kw)}.")
    sens = sorted({n for n in u.get("query_names", []) if n.lower() in ref.url_keywords["sensitive_param"]})
    if sens:
        add("URL-006", f"The query string contains parameter name(s): {', '.join(sens)} (values are redacted).")
    if u.get("param_count", 0) > ref.thresholds["max_query_params"] or u.get("long_param_values", 0) > 0:
        add("URL-012", f"The URL has {u.get('param_count', 0)} query parameters"
            + (f" and {u['long_param_values']} very long value(s)." if u.get("long_param_values") else "."))
    redir_params = sorted({n for n in u.get("query_names", []) if n.lower() in ref.url_keywords["redirect_param"]})
    if u.get("fragment_redirect"):
        add("URL-016", "The URL fragment contains an embedded client-side redirect target.", severity=Severity.MEANINGFUL)
        for eu in u.get("embedded_urls", [])[:2]:
            pu = parse_url(eu)
            eu_toks = [t for t in re.split(r"[^a-z0-9\-]+", (pu.get("path") or "").lower()) if t]
            eu_kw = sorted({k for k in ref.url_keywords["sensitive_path"] if k in eu_toks})
            if eu_kw and not hit_kw:
                add("URL-011", f"The redirect target path contains: {', '.join(eu_kw)}.")
    elif u.get("embedded_urls"):
        add("URL-016", "A query parameter value is itself a URL (possible redirect).")
    elif redir_params and ("redirect" in path_tokens or "return" in path_tokens or "bounce" in path_tokens):
        add("URL-016", f"The URL is a redirect endpoint with parameter(s): {', '.join(redir_params)}.")
    if u.get("length", 0) > ref.thresholds["max_url_length"]:
        add("URL-017", f"The URL is {u['length']} characters long.")
    return out
