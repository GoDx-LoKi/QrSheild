"""Per-type payload normalizers. Each returns a :class:`Payload` with structured, redacted fields."""
from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from ..classifier.classify import classify
from ..models import Payload, PayloadType
from ..redaction import REDACTED, SENSITIVE_PARAM_NAMES, redact_payload_raw
from ..rules import ReferenceData
from .common import (
    EMAIL_IN_TEXT, EMAIL_RE, PHONE_IN_TEXT, clean_phone, find_urls, has_hidden_chars, parse_url,
    phone_valid, safe_text, tokenize_escaped, unescape,
)

VPA_RE = re.compile(r"^[A-Za-z0-9._\-]{2,256}@[A-Za-z][A-Za-z0-9]{1,63}$")
ISO4217 = {"356": "INR", "840": "USD", "978": "EUR", "826": "GBP", "392": "JPY", "036": "AUD", "124": "CAD", "702": "SGD"}
_GUEST_TOKEN_VAL_RE = re.compile(r"^(?:guest|public|anon|anonymous|table|menu|view|demo)[_\-]?\d*$", re.I)


def crc16_ccitt(data: str) -> str:
    crc = 0xFFFF
    for b in data.encode("ascii", "ignore"):
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return f"{crc:04X}"


def parse_emv_tlv(s: str) -> dict[str, str] | None:
    tags: dict[str, str] = {}
    i = 0
    try:
        while i < len(s):
            tag, ln = s[i:i + 2], int(s[i + 2:i + 4])
            val = s[i + 4:i + 4 + ln]
            if len(val) != ln:
                return None
            tags[tag] = val
            i += 4 + ln
    except ValueError:
        return None
    return tags


def _amount(val: str | None) -> tuple[str | None, bool]:
    """Return (normalised amount string, valid?)."""
    if val is None or val == "":
        return None, True
    try:
        d = Decimal(val.strip())
        if not d.is_finite():
            return None, False
        return format(d.normalize(), "f"), True
    except InvalidOperation:
        return None, False


def _redact_params(params: list[tuple[str, str]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for k, v in params:
        out.setdefault(k, []).append(REDACTED if k.lower() in SENSITIVE_PARAM_NAMES else v[:200])
    return out


# ------------------------------------------------------------------ URL
def _normalize_url(raw: str, ref: ReferenceData) -> Payload:
    u = parse_url(raw)
    p = Payload(type=PayloadType.URL, raw=raw, normalized_fields=u, action="open_web_resource",
                parse_ok=u.get("parse_ok", True))
    if u.get("host"):
        p.entities.append({"role": "host", "value": u["host"]})
        p.destinations.append({"kind": "url", "value": u["url_redacted"]})
    if u.get("scheme") in {"javascript", "data", "file", "vbscript"}:
        p.action = "execute_or_open_local_resource"
    return p


# ------------------------------------------------------------------ Wi-Fi
def _normalize_wifi(raw: str, ref: ReferenceData) -> Payload:
    body = raw.strip()[5:]
    fields: dict[str, str] = {}
    for tok in tokenize_escaped(body, ";"):
        if ":" in tok:
            k, v = tok.split(":", 1)
            v = unescape(v)
            if len(v) >= 2 and v[0] == v[-1] == '"':
                v = v[1:-1]
            fields.setdefault(k.strip().upper(), v)
    t = fields.get("T", "").strip()
    auth_raw = t.upper()
    if auth_raw in {"", "NOPASS", "NONE"}:
        auth = "open"
    elif auth_raw in {"SAE", "WPA3"}:
        auth = "WPA3"
    elif auth_raw in {"WPA", "WPA2", "WPA/WPA2", "WPA2-PSK"}:
        auth = auth_raw if auth_raw != "WPA2-PSK" else "WPA2"
    elif "EAP" in auth_raw:
        auth = "WPA-Enterprise (EAP)"
    elif auth_raw == "WEP":
        auth = "WEP"
    else:
        auth = auth_raw
    ssid = fields.get("S", "")
    ok = "S" in fields
    nf = {
        "ssid": ssid, "auth_type": auth, "auth_declared": t, "password_present": bool(fields.get("P")),
        "hidden": fields.get("H", "").lower() in {"true", "1"}, "eap_method": fields.get("E"),
        "ssid_bytes": len(ssid.encode("utf-8", "ignore")),
        "ssid_has_control_chars": has_hidden_chars(ssid),
    }
    p = Payload(type=PayloadType.WIFI, raw=raw, normalized_fields=nf, action="join_network", parse_ok=ok)
    if ok:
        p.entities.append({"role": "ssid", "value": ssid})
        p.destinations.append({"kind": "ssid", "value": ssid})
    else:
        p.notes.append("Payload could not be safely normalized: no SSID field.")
    return p


# ------------------------------------------------------------------ Payment
def _normalize_payment(raw: str, ref: ReferenceData) -> Payload:
    s = raw.strip()
    low = s.lower()
    scheme_m = re.match(r"^([a-z][a-z0-9+.\-]*):", low)
    scheme = scheme_m.group(1) if scheme_m else ""
    nf: dict[str, Any] = {}
    ok = True
    if s.startswith("000201"):
        tags = parse_emv_tlv(s)
        if tags is None:
            return Payload(type=PayloadType.PAYMENT, raw=raw, parse_ok=False,
                           notes=["Payload could not be safely normalized: malformed EMV TLV."], action="financial_transaction")
        crc_ok = False
        if s[-8:-4] == "6304":
            crc_ok = crc16_ccitt(s[:-4]) == s[-4:].upper()
        recipient = None
        acct: dict[str, Any] = {}
        for t in range(26, 52):
            tg = f"{t:02d}"
            if tg in tags:
                sub = parse_emv_tlv(tags[tg]) or {}
                acct[tg] = sub
                for v in sub.values():
                    if "@" in v and not recipient:
                        recipient = v
        amt, amt_ok = _amount(tags.get("54"))
        nf = {
            "scheme": "emvco_merchant_qr", "rail": "EMVCo merchant-presented", "recipient": recipient,
            "payee_name": tags.get("59"), "merchant_city": tags.get("60"), "country": tags.get("58"),
            "amount": amt, "amount_valid": amt_ok, "currency": ISO4217.get(tags.get("53", ""), tags.get("53")),
            "merchant_category_code": tags.get("52"), "initiation": {"11": "static", "12": "dynamic"}.get(tags.get("01", ""), tags.get("01")),
            "crc_valid": crc_ok, "ancillary_url": None, "transaction_note": None, "unrecognized_params": [],
            "merchant_account_info_tags": sorted(acct.keys()),
        }
    elif scheme in {"bitcoin", "litecoin", "ethereum", "monero", "dogecoin", "bitcoincash"}:
        rest = s[len(scheme) + 1:].lstrip("/")
        addr, _, q = rest.partition("?")
        addr = addr.split("@")[0]
        params = parse_qsl(q, keep_blank_values=True)
        pd = {k.lower(): v for k, v in params}
        amt, amt_ok = _amount(pd.get("amount") or pd.get("value"))
        known = {"amount", "value", "label", "message", "chain_id"}
        nf = {
            "scheme": scheme, "rail": "cryptocurrency", "recipient": addr, "payee_name": pd.get("label"),
            "amount": amt, "amount_valid": amt_ok, "currency": scheme.upper(), "transaction_note": pd.get("message"),
            "ancillary_url": None, "unrecognized_params": sorted(set(pd) - known),
            "recipient_format_valid": bool(re.fullmatch(r"[A-Za-z0-9]{20,100}", addr)),
        }
    else:  # UPI and UPI-intent application schemes
        parts = urlsplit(s)
        params = parse_qsl(parts.query, keep_blank_values=True)
        pd = {k.lower(): v for k, v in params}
        amt, amt_ok = _amount(pd.get("am"))
        known = {"pa", "pn", "am", "cu", "tn", "tr", "tid", "mc", "url", "mode", "purpose", "orgid", "sign", "ver", "mam", "cum", "qrmedium", "gstin", "invoiceno", "invoicedate", "invoicename", "gstbrkup", "query"}
        vpa = pd.get("pa")
        nf = {
            "scheme": "upi" if scheme == "upi" else f"upi_intent:{scheme}", "rail": "UPI", "recipient": vpa,
            "payee_name": pd.get("pn"), "amount": amt, "amount_valid": amt_ok,
            "currency": (pd.get("cu") or "INR").upper(), "currency_declared": "cu" in pd,
            "transaction_note": pd.get("tn"), "transaction_ref": pd.get("tr"), "merchant_code": pd.get("mc"),
            "ancillary_url": pd.get("url"), "mode": pd.get("mode"),
            "recipient_format_valid": bool(vpa and VPA_RE.match(vpa)),
            "unrecognized_params": sorted(set(pd) - known),
            "has_signature": "sign" in pd,
        }
        if not vpa:
            ok = False
    nf["amount_fixed"] = nf.get("amount") is not None
    if nf.get("ancillary_url"):
        nf["ancillary_url_parsed"] = parse_url(nf["ancillary_url"])
    if nf.get("transaction_note"):
        nf["transaction_note"] = safe_text(nf["transaction_note"])
    p = Payload(type=PayloadType.PAYMENT, raw=raw, normalized_fields=nf, action="financial_transaction", parse_ok=ok)
    if nf.get("recipient"):
        p.entities.append({"role": "payment_recipient", "value": nf["recipient"]})
        p.destinations.append({"kind": "payment_address", "value": nf["recipient"]})
    if nf.get("payee_name"):
        p.entities.append({"role": "payee_name", "value": nf["payee_name"]})
    if nf.get("ancillary_url"):
        p.destinations.append({"kind": "url", "value": nf["ancillary_url_parsed"]["url_redacted"]})
    if not ok:
        p.notes.append("Payload could not be safely normalized: no payment address.")
    return p


# ------------------------------------------------------------------ Contact
def _unfold(text: str) -> list[str]:
    lines: list[str] = []
    for ln in re.split(r"\r\n|\n|\r", text):
        if ln[:1] in (" ", "\t") and lines:
            lines[-1] += ln[1:]
        else:
            lines.append(ln)
    return lines


def _normalize_contact(raw: str, ref: ReferenceData) -> Payload:
    s = raw.strip()
    name = org = title = address = note = None
    phones: list[str] = []
    emails: list[str] = []
    sites: list[str] = []
    fmt = "vCard"
    if s.lower().startswith("mecard:"):
        fmt = "MECARD"
        for tok in tokenize_escaped(s[7:], ";"):
            if ":" not in tok:
                continue
            k, v = tok.split(":", 1)
            k, v = k.strip().upper(), unescape(v).strip()
            if k == "N":
                name = " ".join(x for x in reversed(v.split(",", 1))) if "," in v else v
            elif k == "ORG":
                org = v
            elif k == "TITLE":
                title = v
            elif k == "TEL":
                phones.append(v)
            elif k == "EMAIL":
                emails.append(v)
            elif k in {"URL", "URI"}:
                sites.append(v)
            elif k == "ADR":
                address = ", ".join(x for x in v.split(",") if x.strip())
            elif k == "NOTE":
                note = v
    else:
        for ln in _unfold(s):
            if ":" not in ln:
                continue
            key, v = ln.split(":", 1)
            k = key.split(";")[0].strip().upper()
            v = v.strip()
            if k == "FN":
                name = v
            elif k == "N" and not name:
                comp = v.split(";")
                name = " ".join(x for x in (comp[1:2] + comp[0:1]) if x)
            elif k == "ORG":
                org = v.split(";")[0]
            elif k == "TITLE":
                title = v
            elif k == "TEL":
                phones.append(v)
            elif k == "EMAIL":
                emails.append(v)
            elif k == "URL":
                sites.append(v)
            elif k == "ADR":
                address = ", ".join(x for x in v.split(";") if x.strip())
            elif k == "NOTE":
                note = v
    parsed_sites = [parse_url(u) for u in sites[:3]]
    nf = {
        "format": fmt, "name": name, "organization": org, "title": title,
        "phones": [clean_phone(x) for x in phones], "phones_valid": [phone_valid(x) for x in phones],
        "emails": emails, "emails_valid": [bool(EMAIL_RE.match(e)) for e in emails],
        "email_domains": [e.split("@")[-1].lower() for e in emails if "@" in e],
        "websites": [u["url_redacted"] for u in parsed_sites], "websites_parsed": parsed_sites,
        "address": address, "note": safe_text(note) if note else None,
    }
    p = Payload(type=PayloadType.CONTACT, raw=raw, normalized_fields=nf, action="add_contact",
                parse_ok=bool(name or org or phones or emails))
    if org:
        p.entities.append({"role": "organization", "value": org})
    if name:
        p.entities.append({"role": "person", "value": name})
    for e in emails:
        p.destinations.append({"kind": "email", "value": e})
    for ph in nf["phones"]:
        p.destinations.append({"kind": "phone", "value": ph})
    for u in parsed_sites:
        p.destinations.append({"kind": "url", "value": u["url_redacted"]})
    if not p.parse_ok:
        p.notes.append("Payload could not be safely normalized: contact has no recognisable fields.")
    return p


# ------------------------------------------------------------------ SMS / Email
def _normalize_sms(raw: str, ref: ReferenceData) -> Payload:
    s = raw.strip()
    rest = re.sub(r"^(?i:smsto|sms|mmsto|mms):", "", s, count=1)
    body = ""
    nums = rest
    if "?" in rest:
        nums, q = rest.split("?", 1)
        body = dict((k.lower(), v) for k, v in parse_qsl(q, keep_blank_values=True)).get("body", "")
    elif re.search(r"[;&]body=", rest, re.I):
        nums, _, b = re.split(r"[;&]body=", rest, maxsplit=1, flags=re.I)[0], None, re.split(r"[;&]body=", rest, maxsplit=1, flags=re.I)[1]
        body = unquote(b)
    elif ":" in rest:
        nums, body = rest.split(":", 1)
    recipients = [clean_phone(x) for x in re.split(r"[,;]", nums) if x.strip()]
    valid = [phone_valid(x) for x in recipients]
    body = unquote(body or "")[:1000]
    nf = {
        "recipients": recipients, "recipients_valid": valid, "body": safe_text(body, 1000),
        "body_present": bool(body), "body_urls": find_urls(body), "body_has_hidden_chars": has_hidden_chars(body),
    }
    p = Payload(type=PayloadType.SMS, raw=raw, normalized_fields=nf, action="send_sms", parse_ok=bool(recipients))
    for r in recipients:
        p.destinations.append({"kind": "phone", "value": r})
        p.entities.append({"role": "sms_recipient", "value": r})
    for u in nf["body_urls"]:
        p.destinations.append({"kind": "url", "value": u["url_redacted"]})
    if not recipients:
        p.notes.append("Payload could not be safely normalized: no SMS recipient.")
    return p


def _normalize_email(raw: str, ref: ReferenceData) -> Payload:
    s = raw.strip()
    to: list[str] = []
    cc: list[str] = []
    bcc: list[str] = []
    subject = body = ""
    if s.lower().startswith("matmsg:"):
        for tok in tokenize_escaped(s[7:], ";"):
            if ":" in tok:
                k, v = tok.split(":", 1)
                k, v = k.strip().upper(), unescape(v)
                if k == "TO":
                    to = [x.strip() for x in re.split(r"[,;]", v) if x.strip()]
                elif k == "SUB":
                    subject = v
                elif k == "BODY":
                    body = v
    else:
        rest = s[7:]
        addr, _, q = rest.partition("?")
        to = [x.strip() for x in unquote(addr).split(",") if x.strip()]
        qd = {k.lower(): v for k, v in parse_qsl(q, keep_blank_values=True)}
        subject, body = qd.get("subject", ""), qd.get("body", "")
        cc = [x.strip() for x in qd.get("cc", "").split(",") if x.strip()]
        bcc = [x.strip() for x in qd.get("bcc", "").split(",") if x.strip()]
        to += [x.strip() for x in qd.get("to", "").split(",") if x.strip()]
    body, subject = body[:2000], subject[:300]
    allr = to + cc + bcc
    nf = {
        "to": to, "cc": cc, "bcc": bcc, "subject": safe_text(subject, 300), "body": safe_text(body, 2000),
        "recipients_valid": [bool(EMAIL_RE.match(r)) for r in allr],
        "recipient_domains": sorted({r.split("@")[-1].lower() for r in allr if "@" in r}),
        "body_urls": find_urls(body), "body_has_hidden_chars": has_hidden_chars(body + subject),
    }
    p = Payload(type=PayloadType.EMAIL, raw=raw, normalized_fields=nf, action="send_email", parse_ok=bool(to))
    for r in allr:
        p.destinations.append({"kind": "email", "value": r})
        p.entities.append({"role": "email_recipient", "value": r})
    for u in nf["body_urls"]:
        p.destinations.append({"kind": "url", "value": u["url_redacted"]})
    if not to:
        p.notes.append("Payload could not be safely normalized: no email recipient.")
    return p


# ------------------------------------------------------------------ Deep link
_OP_PRIORITY = ["device_linking", "account_recovery", "account_change", "payment", "authentication", "content"]


def detect_operations(tokens: list[str], names: list[str], ref: ReferenceData) -> list[str]:
    joined = " ".join(tokens)
    found: list[str] = []
    for op in _OP_PRIORITY:
        for kw in ref.operations.get(op, []):
            if kw in tokens or (len(kw) > 4 and kw in joined):
                found.append(op)
                break
    lower_names = {n.lower() for n in names}
    if {"uuid", "pub_key"} <= lower_names and "device_linking" not in found:
        found.insert(0, "device_linking")
    return found


def _normalize_deeplink(raw: str, ref: ReferenceData) -> Payload:
    s = raw.strip()
    scheme = s.split(":", 1)[0].lower()
    intent_fields: dict[str, str] = {}
    base = s
    if scheme == "intent" and "#Intent;" in s:
        base, _, frag = s.partition("#Intent;")
        for tok in frag.split(";"):
            if "=" in tok:
                k, v = tok.split("=", 1)
                intent_fields[k] = unquote(v)
    try:
        parts = urlsplit(base)
        host, path = parts.hostname or parts.netloc or "", parts.path
        params = parse_qsl(parts.query, keep_blank_values=True)
        ok = True
    except ValueError:
        host, path, params, ok = "", "", [], False
    names = [k for k, _ in params]
    embedded_urls: list[str] = []
    for _, v in params:
        v_unq = unquote(v).strip()
        if v_unq.lower().startswith(("http://", "https://", "//")):
            u_str = v_unq if v_unq.lower().startswith("http") else "https:" + v_unq
            if u_str not in embedded_urls:
                embedded_urls.append(u_str)

    # Identify benign guest/content placeholder tokens (e.g. ?token=guest_3 on /menu/view)
    host_path_tokens = [t for t in re.split(r"[^a-z0-9_\-]+", f"{host} {path}".lower()) if t]
    host_path_ops = detect_operations(host_path_tokens, [], ref)
    only_content_path = (not host_path_ops) or (host_path_ops == ["content"])
    guest_token_params: list[str] = []
    if only_content_path and not embedded_urls:
        for k, v in params:
            if k.lower() in {"token", "session", "sid"} and _GUEST_TOKEN_VAL_RE.match(unquote(v).strip()):
                guest_token_params.append(k)

    active_names = [n for n in names if n not in guest_token_params]
    tokens = [t for t in re.split(r"[^a-z0-9_\-]+", f"{host} {path} {' '.join(n.lower() for n in active_names)}".lower()) if t]
    ops = detect_operations(tokens, active_names, ref)
    reg = ref.schemes.get(scheme)
    effective_scheme = intent_fields.get("scheme", scheme if scheme != "intent" else "")
    package = intent_fields.get("package") or dict((k.lower(), v) for k, v in params).get("package") \
        or (dict((k.lower(), v) for k, v in params).get("id") if scheme == "market" else None)
    operation = ops[0] if ops else "content"
    if scheme == "otpauth":
        operation = "auth_secret"
    nf = {
        "scheme": scheme, "host": host, "path": path[:300], "params": _redact_params(params),
        "param_names": names, "guest_token_params": guest_token_params,
        "param_count": len(params), "known_scheme": reg is not None,
        "app": reg["app"] if reg else None, "app_category": reg["category"] if reg else None,
        "operations": ops, "operation": operation, "package": package,
        "intent_scheme": effective_scheme or None, "fallback_url": intent_fields.get("S.browser_fallback_url"),
        "embedded_urls": embedded_urls[:5],
        "length": len(s),
    }
    p = Payload(type=PayloadType.DEEP_LINK, raw=raw, normalized_fields=nf, action="launch_app", parse_ok=ok)
    p.entities.append({"role": "target_application", "value": nf["app"] or package or scheme})
    p.destinations.append({"kind": "app", "value": f"{scheme}://{host}{path}"[:200]})
    if nf["fallback_url"]:
        p.destinations.append({"kind": "url", "value": nf["fallback_url"]})
    if not ok:
        p.notes.append("Payload could not be safely normalized: malformed URI.")
    return p


# ------------------------------------------------------------------ Plain text
def _normalize_text(raw: str, ref: ReferenceData, reason: str) -> Payload:
    s = raw
    low = s.strip().lower()
    action, subtype = "display_text", "text"
    if low.startswith("tel:"):
        action, subtype = "initiate_call", "tel"
    elif low.startswith("geo:"):
        action, subtype = "open_map", "geo"
    nf = {
        "subtype": subtype, "text": safe_text(s, 500), "length": len(s),
        "embedded_urls": find_urls(s), "embedded_emails": EMAIL_IN_TEXT.findall(s)[:5],
        "embedded_phones": [clean_phone(x) for x in PHONE_IN_TEXT.findall(s)[:5]],
        "has_hidden_chars": has_hidden_chars(s), "classification_reason": reason,
    }
    p = Payload(type=PayloadType.PLAIN_TEXT, raw=raw, normalized_fields=nf, action=action,
                parse_ok=bool(s.strip()))
    for u in nf["embedded_urls"]:
        p.destinations.append({"kind": "url", "value": u["url_redacted"]})
    return p


# ------------------------------------------------------------------ dispatcher
def normalize(raw: str, ref: ReferenceData) -> Payload:
    """Classify and normalise a decoded payload. Malformed input is reported, never guessed at."""
    ptype, reason = classify(raw, ref)
    try:
        if ptype is PayloadType.URL:
            p = _normalize_url(raw, ref)
        elif ptype is PayloadType.WIFI:
            p = _normalize_wifi(raw, ref)
        elif ptype is PayloadType.PAYMENT:
            p = _normalize_payment(raw, ref)
        elif ptype is PayloadType.CONTACT:
            p = _normalize_contact(raw, ref)
        elif ptype is PayloadType.SMS:
            p = _normalize_sms(raw, ref)
        elif ptype is PayloadType.EMAIL:
            p = _normalize_email(raw, ref)
        elif ptype is PayloadType.DEEP_LINK:
            p = _normalize_deeplink(raw, ref)
        else:
            p = _normalize_text(raw, ref, reason)
    except Exception as exc:  # error isolation: a parser bug must not become a verdict
        p = Payload(type=PayloadType.PLAIN_TEXT, raw=raw, parse_ok=False,
                    normalized_fields={"subtype": "unparsed", "text": safe_text(raw, 200), "length": len(raw),
                                       "embedded_urls": [], "embedded_emails": [], "embedded_phones": [],
                                       "has_hidden_chars": has_hidden_chars(raw), "classification_reason": reason},
                    notes=[f"Payload could not be safely normalized ({type(exc).__name__})."])
    p.classification_reason = reason
    p.raw_redacted = redact_payload_raw(raw)
    return p
