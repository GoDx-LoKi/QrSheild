"""Payload classification from the decoded string alone (no network, no execution)."""
from __future__ import annotations

import re

from ..models import PayloadType
from ..rules import ReferenceData

_FILE_EXT = {"txt", "pdf", "doc", "docx", "xls", "xlsx", "png", "jpg", "jpeg", "gif", "zip", "csv", "json",
             "xml", "py", "js", "exe", "mp3", "mp4", "md", "log", "bak", "tmp"}
_BARE_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})(?::\d{1,5})?(?:[/?#]\S*)?$", re.I)
_CRYPTO = ("bitcoin", "litecoin", "ethereum", "monero", "dogecoin", "bitcoincash")
_WEBISH = ("http", "https", "ftp", "file", "javascript", "data", "vbscript")


def _is_emv(raw: str) -> bool:
    """EMVCo merchant-presented QR payloads start with tag 00 (payload format indicator) = "01".

    Classification is deliberately lenient: a payload that starts like an EMV QR but is malformed is
    still classified as a payment so that the normalizer can report it as "could not be safely
    normalized" instead of silently downgrading a possibly tampered payment payload to plain text.
    """
    return raw.startswith("000201") and len(raw) >= 20 and raw[:8].isdigit()


def classify(raw: str, ref: ReferenceData) -> tuple[PayloadType, str]:
    s = (raw or "").strip()
    if not s:
        return PayloadType.PLAIN_TEXT, "empty payload"
    low = s.lower()
    if low.startswith("wifi:"):
        return PayloadType.WIFI, "WIFI: prefix"
    if low.startswith(("begin:vcard", "mecard:")):
        return PayloadType.CONTACT, "vCard/MECARD structure"
    if low.startswith(("smsto:", "sms:", "mmsto:", "mms:")):
        return PayloadType.SMS, "sms/smsto URI"
    if low.startswith(("mailto:", "matmsg:")):
        return PayloadType.EMAIL, "mailto/MATMSG structure"
    scheme_m = re.match(r"^([a-z][a-z0-9+.\-]*):", low)
    scheme = scheme_m.group(1) if scheme_m else ""
    if scheme in ref.payment_app_schemes and low.startswith(scheme + "://"):
        return PayloadType.PAYMENT, f"payment application scheme '{scheme}'"
    if scheme == "upi":
        return PayloadType.PAYMENT, "UPI URI"
    if scheme in _CRYPTO:
        return PayloadType.PAYMENT, f"cryptocurrency payment URI '{scheme}'"
    if _is_emv(s):
        return PayloadType.PAYMENT, "EMVCo merchant-presented QR structure"
    if scheme in {"tel", "geo"}:
        return PayloadType.PLAIN_TEXT, f"{scheme}: URI (not a supported analyzer family)"
    if scheme in _WEBISH and (low.startswith(scheme + ":")):
        return PayloadType.URL, f"{scheme} URI"
    if scheme and (low.startswith(scheme + "://") or scheme in ref.schemes or scheme in {"otpauth"}):
        return PayloadType.DEEP_LINK, f"custom/application URI scheme '{scheme}'"
    if " " not in s and "@" not in s.split("/")[0] and _BARE_DOMAIN.match(s):
        tld = _BARE_DOMAIN.match(s).group(1).lower()
        if tld not in _FILE_EXT:
            return PayloadType.URL, "bare domain without scheme"
    return PayloadType.PLAIN_TEXT, "no structured format recognised"
