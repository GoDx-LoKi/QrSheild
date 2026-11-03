"""Shared parsing helpers used by the per-type normalizers."""
from __future__ import annotations

import re
import socket
import ipaddress
import unicodedata
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from ..matching.domains import split_host
from ..redaction import REDACTED, SENSITIVE_PARAM_NAMES, redact_otp_text, redact_url

URL_IN_TEXT = re.compile(r"https?://[^\s<>\"']+", re.I)
EMAIL_RE = re.compile(r"^[^@\s,;:<>]+@[^@\s,;:<>]+\.[^@\s,;:<>]{2,}$")
EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_IN_TEXT = re.compile(r"(?<![\w])\+?\d[\d\s().-]{7,16}\d")
HIDDEN_CHARS = re.compile("[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
DANGEROUS_SCHEMES = {"javascript", "data", "file", "vbscript"}
_FRAG_REDIR_KEYS = {"url", "redirect", "redirect_uri", "redirect_url", "return", "return_url", "next", "continue", "dest", "destination", "goto", "target", "returnto", "callback"}


def tokenize_escaped(s: str, sep: str = ";") -> list[str]:
    """Split on unescaped separators, keeping backslash escapes for later unescaping."""
    parts, cur, i = [], [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            cur.append(c + s[i + 1])
            i += 2
            continue
        if c == sep:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


def unescape(s: str) -> str:
    return re.sub(r"\\(.)", r"\1", s)


def has_hidden_chars(s: str) -> bool:
    if HIDDEN_CHARS.search(s):
        return True
    return any(unicodedata.category(c) == "Cc" and c not in "\n\r\t" for c in s)


def _script_of(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    try:
        return unicodedata.name(ch).split()[0]
    except ValueError:
        return None


def _is_obfuscated_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    if not re.fullmatch(r"[0-9a-fxA-FX.]+", host or ""):
        return False
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        return False
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


def parse_url(raw: str) -> dict[str, Any]:
    """Parse a URL string statically. Nothing is fetched, resolved or followed."""
    s = (raw or "").strip()
    out: dict[str, Any] = {"parse_ok": True, "length": len(s), "url_redacted": redact_url(s)}
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.\-]*):", s)
    scheme_missing = False
    is_hostport = bool(m) and bool(re.match(r"^[A-Za-z0-9.\-]+:\d+(/|$)", s))
    if not m or is_hostport:
        scheme_missing = True
        s2 = "//" + s
    else:
        s2 = s
    try:
        parts = urlsplit(s2)
        port = parts.port
        host = parts.hostname or ""
    except ValueError:
        out.update(parse_ok=False, scheme="", host="", scheme_missing=scheme_missing)
        return out
    scheme = "" if scheme_missing else (parts.scheme or "").lower()
    params = parse_qsl(parts.query, keep_blank_values=True)
    qnames: list[str] = []
    qvals: dict[str, list[str]] = {}
    embedded: list[str] = []
    long_values = 0
    for k, v in params:
        qnames.append(k)
        v_unq = unquote(v)
        if v_unq.lower().startswith(("http://", "https://", "//")):
            embedded.append(v_unq if v_unq.lower().startswith("http") else "https:" + v_unq)
        if len(v) > 200:
            long_values += 1
        qvals.setdefault(k, []).append(REDACTED if k.lower() in SENSITIVE_PARAM_NAMES else v[:200])

    # Inspect URL fragment for client-side redirect targets (Weakness 6: #redirect=https://..., #url=..., etc.)
    frag_raw = parts.fragment or ""
    fragment_redirect = False
    if frag_raw:
        frag_unq = unquote(frag_raw.lstrip("#!/"))
        for fk, fv in parse_qsl(frag_unq, keep_blank_values=True):
            fv_unq = unquote(fv).strip()
            if fk.lower() in _FRAG_REDIR_KEYS or fv_unq.lower().startswith(("http://", "https://", "//")):
                fragment_redirect = True
                if fv_unq.lower().startswith(("http://", "https://", "//")):
                    target_u = fv_unq if fv_unq.lower().startswith("http") else "https:" + fv_unq
                    if target_u not in embedded:
                        embedded.append(target_u)
        if not fragment_redirect:
            for m_u in URL_IN_TEXT.findall(frag_unq):
                fragment_redirect = True
                if m_u not in embedded:
                    embedded.append(m_u)

    is_ip = False
    special = False
    ip_version = None
    reason = ""
    try:
        ip = ipaddress.ip_address(host)
        is_ip = True
        ip_version = ip.version
        special = bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                       or ip.is_multicast or ip.is_unspecified)
        if special:
            reason = "loopback" if ip.is_loopback else "private/documentation/reserved range"
    except ValueError:
        if host in {"localhost"} or host.endswith((".local", ".internal", ".localhost", ".lan", ".home.arpa")):
            special, reason = True, "local or internal hostname"
        elif host and "." not in host and scheme in {"http", "https", ""}:
            special, reason = True, "single-label (intranet-style) hostname"
    unicode_host = any(ord(c) > 127 for c in host)
    punycode = any(l.startswith("xn--") for l in host.split("."))
    decoded_host = host
    if punycode:
        try:
            decoded_host = host.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            decoded_host = host
    mixed = False
    for label in decoded_host.split("."):
        scripts = {sc for sc in (_script_of(c) for c in label) if sc}
        if len(scripts) > 1:
            mixed = True
    hp = split_host(host) if host and not is_ip else None
    out.update(
        scheme=scheme, scheme_missing=scheme_missing, host=host, port=port,
        path=parts.path[:500], query=qvals, query_names=qnames, param_count=len(params),
        long_param_values=long_values, fragment=(parts.fragment or "")[:200],
        fragment_redirect=fragment_redirect,
        userinfo_present=bool(parts.username or parts.password),
        is_ip=is_ip, ip_version=ip_version, special_host=special, special_reason=reason,
        obfuscated_ip=(not is_ip) and _is_obfuscated_ip(host),
        punycode=punycode or unicode_host, decoded_host=decoded_host, mixed_script=mixed,
        registrable=hp.registrable if hp else "", sld=hp.sld if hp else "",
        subdomains=hp.subdomains if hp else [], embedded_urls=embedded[:5],
    )
    return out


def find_urls(text: str, limit: int = 5) -> list[dict[str, Any]]:
    return [parse_url(u.rstrip(".,);]")) for u in URL_IN_TEXT.findall(text or "")[:limit]]


def clean_phone(p: str) -> str:
    p = (p or "").strip()
    lead = "+" if p.startswith("+") else ""
    return lead + re.sub(r"\D", "", p)


def phone_valid(p: str) -> bool:
    digits = re.sub(r"\D", "", p or "")
    return 3 <= len(digits) <= 15 and bool(re.fullmatch(r"\+?[\d\s().-]+", p or ""))


def safe_text(s: str, limit: int = 500) -> str:
    return redact_otp_text((s or "")[:limit])


__all__ = [n for n in dir() if not n.startswith("_")]
