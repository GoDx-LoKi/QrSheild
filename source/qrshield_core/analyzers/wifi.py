"""Wi-Fi payload analysis. Never connects to a network; the password value is never stored or shown."""
from __future__ import annotations

from ..models import Evidence, Payload, Severity, Source
from .common import Deps


def analyze_wifi(p: Payload, deps: Deps) -> list[Evidence]:
    reg, nf = deps.reg, p.normalized_fields
    S, A = Source.QR_PAYLOAD, "join_network"
    out: list[Evidence] = []
    ssid, auth = nf.get("ssid", ""), nf.get("auth_type", "")
    if not ssid or nf.get("ssid_bytes", 0) > 32 or nf.get("ssid_has_control_chars"):
        why = "empty" if not ssid else ("longer than 32 bytes" if nf.get("ssid_bytes", 0) > 32 else "contains control/hidden characters")
        out.append(reg.make("WIFI-005", f"The SSID is {why}.", source=S, payload_field="ssid", related_action=A))
    if auth == "open":
        out.append(reg.make("WIFI-001", "The payload declares no authentication (open network).", source=S, payload_field="auth_type", related_action=A))
    elif auth == "WEP":
        out.append(reg.make("WIFI-002", "The payload declares WEP, a deprecated and broken protocol.", source=S, payload_field="auth_type", related_action=A))
    if nf.get("hidden"):
        w3_sev = Severity.MEANINGFUL if auth in ("open", "WEP") else None
        out.append(reg.make("WIFI-003", "The network is flagged as hidden.", source=S, payload_field="hidden", related_action=A, severity=w3_sev))
    if nf.get("password_present"):
        out.append(reg.make("WIFI-004", "A password is embedded in the QR code (value redacted).", source=S, payload_field="password", related_action=A))
    return out
