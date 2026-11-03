"""Payload-specific security analyzers. Each returns structured :class:`Evidence`; none executes anything."""
from __future__ import annotations

from ..models import Evidence, Payload, PayloadType, Source
from .common import Deps
from .contact import analyze_contact
from .deeplink import analyze_deeplink
from .messaging import analyze_email, analyze_sms
from .payment import analyze_payment
from .text import analyze_text
from .url import analyze_url_dict
from .wifi import analyze_wifi


def analyze_url(p: Payload, deps: Deps) -> list[Evidence]:
    return analyze_url_dict(p.normalized_fields, deps, field="url", action=p.action)


ANALYZERS = {
    PayloadType.URL: analyze_url,
    PayloadType.WIFI: analyze_wifi,
    PayloadType.PAYMENT: analyze_payment,
    PayloadType.CONTACT: analyze_contact,
    PayloadType.SMS: analyze_sms,
    PayloadType.EMAIL: analyze_email,
    PayloadType.DEEP_LINK: analyze_deeplink,
    PayloadType.PLAIN_TEXT: analyze_text,
}


def analyze_payload_security(p: Payload, deps: Deps) -> list[Evidence]:
    """Dispatch to the analyzer for the payload type (payload-intrinsic checks only, no context)."""
    return ANALYZERS[p.type](p, deps)


__all__ = ["Deps", "analyze_payload_security", "ANALYZERS"]
