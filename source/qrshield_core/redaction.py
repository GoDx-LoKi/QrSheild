"""Central redaction policy.

Everything that leaves the core engine (logs, UI, exports) passes through these helpers so that
credentials are never exposed unnecessarily. Redaction is applied at the serialisation boundary,
not case by case in analyzers.
"""
from __future__ import annotations

import logging
import re

REDACTED = "[REDACTED]"

SENSITIVE_PARAM_NAMES = {
    "token", "access_token", "id_token", "refresh_token", "session", "sessionid", "sid", "password",
    "passwd", "pwd", "pass", "secret", "client_secret", "apikey", "api_key", "key", "auth", "authorization",
    "credential", "credentials", "otp", "pin", "mpin", "cvv", "code", "passcode", "signature", "sig",
    "pub_key", "private_key",
}

_WIFI_PASS = re.compile(r"(?i)(?<=;)(P:)((?:\\.|[^;\\])*)")
_WIFI_PASS_START = re.compile(r"(?i)^(WIFI:)(P:)((?:\\.|[^;\\])*)")
_OTP_NEAR = re.compile(
    r"(?i)((?:otp|one[\s-]?time(?:\s+(?:password|pin|code))?|passcode|pin|cvv|cvc|verification\s+code|security\s+code)"
    r"[^0-9\n]{0,24})(\d{4,10})"
)
_KV_SECRET = re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|otp|pin|authorization)\b(\s*[=:]\s*)([^\s&;,]+)")
_VT_KEY = re.compile(r"(?i)(x-apikey['\"]?\s*[:=]\s*['\"]?)([A-Za-z0-9]{16,})")


def redact_wifi_raw(raw: str) -> str:
    """Mask the password field of a WIFI: payload."""
    if not raw.upper().startswith("WIFI:"):
        return raw
    out = _WIFI_PASS.sub(lambda m: m.group(1) + REDACTED, raw)
    return out


def redact_otp_text(text: str) -> str:
    """Mask digit strings that follow OTP/PIN/CVV style keywords in free text."""
    return _OTP_NEAR.sub(lambda m: m.group(1) + REDACTED, text or "")


def redact_url(url: str) -> str:
    """Mask values of credential-like query parameters and userinfo passwords."""
    def _q(m: re.Match) -> str:
        name = m.group(2)
        if name.lower() in SENSITIVE_PARAM_NAMES:
            return f"{m.group(1)}{name}={REDACTED}"
        return m.group(0)

    out = re.sub(r"([?&#;])([^=&#;\s]+)=([^&#;\s]*)", _q, url)
    out = re.sub(r"(://[^/@:\s]+:)([^@/\s]+)(@)", lambda m: m.group(1) + REDACTED + m.group(3), out)
    return out


def redact_text(text: str) -> str:
    """General-purpose redaction for log lines and free text."""
    if not text:
        return text
    t = _KV_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    t = _VT_KEY.sub(lambda m: m.group(1) + REDACTED, t)
    t = redact_otp_text(t)
    return t


def redact_payload_raw(raw: str) -> str:
    """Redacted form of a decoded payload, safe for UI and exports."""
    if raw.upper().startswith("WIFI:"):
        return redact_wifi_raw(raw)
    out = redact_url(raw) if "://" in raw or raw.lower().startswith(("http", "mailto:", "sms")) else raw
    return redact_otp_text(out)


class RedactingFilter(logging.Filter):
    """Logging filter that scrubs secrets from every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True
        record.msg = redact_text(msg)
        record.args = ()
        return True
