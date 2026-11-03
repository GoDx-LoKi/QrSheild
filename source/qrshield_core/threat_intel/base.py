"""Threat-intelligence abstraction. External results are corroborating evidence only.

Principles
* No result is not a clean result; unavailable is not malicious; one detection is not 'malicious'.
* Lookups send the URL (and only the URL) to the configured provider: this is external telemetry and is opt-in.
* Decoded URLs are never fetched by QRShield itself.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models import ThreatIntelStatus
from ..normalizer.common import EMAIL_IN_TEXT
from ..rules import ReferenceData


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ThreatIntelResult:
    provider: str
    query_type: str                   # lookup | scan | none
    url: str                          # redacted URL form
    status: ThreatIntelStatus
    message: str
    timestamp: str = field(default_factory=now_iso)
    cached: bool = False
    stats: dict[str, int] = field(default_factory=dict)
    payload_field: str | None = None
    reference_link: str | None = None


class ThreatIntelProvider(ABC):
    name = "abstract"

    @abstractmethod
    def configured(self) -> tuple[bool, str]: ...

    @abstractmethod
    def lookup(self, url: str) -> ThreatIntelResult: ...

    @abstractmethod
    def submit_scan(self, url: str) -> ThreatIntelResult: ...


class MockThreatIntelProvider(ThreatIntelProvider):
    """Deterministic test double. Results are fixtures, not real provider output, and are labelled as such."""

    name = "mock-fixture"

    def __init__(self, stats_by_host: dict[str, dict[str, int]] | None = None, default: dict[str, int] | None = None,
                 force_status: ThreatIntelStatus | None = None, threshold: int = 3):
        self.by_host = stats_by_host or {}
        self.default = default
        self.force_status = force_status
        self.threshold = threshold
        self.calls: list[tuple[str, str]] = []

    def configured(self) -> tuple[bool, str]:
        return True, "mock fixture provider (deterministic test double)"

    def _result(self, url: str, qtype: str) -> ThreatIntelResult:
        self.calls.append((qtype, url))
        if self.force_status:
            return ThreatIntelResult(self.name, qtype, url, self.force_status, f"Forced status: {self.force_status.value}")
        host = (re.sub(r"^[a-z]+://", "", url).split("/")[0]).lower()
        stats = self.by_host.get(host, self.default)
        if stats is None:
            return ThreatIntelResult(self.name, qtype, url, ThreatIntelStatus.NO_RESULT, "Fixture: no report for this URL.")
        return ThreatIntelResult(self.name, qtype, url, classify_stats(stats, self.threshold),
                                 "Fixture report (not a real provider response).", stats=dict(stats))

    def lookup(self, url: str) -> ThreatIntelResult:
        return self._result(url, "lookup")

    def submit_scan(self, url: str) -> ThreatIntelResult:
        return self._result(url, "scan")


def classify_stats(stats: dict[str, int], threshold: int) -> ThreatIntelStatus:
    mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    if mal >= threshold:
        return ThreatIntelStatus.CONFIRMED_MALICIOUS_EVIDENCE
    if mal >= 1 or sus >= 1:
        return ThreatIntelStatus.SUSPICIOUS_MIXED
    if sum(int(v) for v in stats.values()) > 0:
        return ThreatIntelStatus.NO_KNOWN_MALICIOUS_REPORT
    return ThreatIntelStatus.NO_RESULT


class ThreatIntelPolicy:
    """Privacy gate: decides whether a URL may be sent to an external provider.

    Hard blocks can never be overridden. Soft blocks (credential-like parameters, apparent personal data,
    payment auxiliary URLs) can be overridden only by an explicit user confirmation.
    """

    def __init__(self, ref: ReferenceData):
        self.ref = ref

    def check(self, parsed: dict[str, Any], *, from_payment: bool = False, override: bool = False) -> tuple[bool, str]:
        scheme, host = parsed.get("scheme"), parsed.get("host")
        if parsed.get("scheme_missing") or scheme not in ("http", "https"):
            return False, "Only complete http(s) URLs are eligible for external lookup."
        if not host:
            return False, "The URL has no host."
        if parsed.get("special_host") or (not parsed.get("is_ip") and "." not in host):
            return False, "The host is private, local or internal; it is never sent to an external service."
        if parsed.get("userinfo_present"):
            return False, "The URL embeds credentials (user:password@); it is never sent to an external service."
        soft: list[str] = []
        names = {n.lower() for n in parsed.get("query_names", [])}
        if names & set(self.ref.url_keywords["sensitive_param"]):
            soft.append("contains credential-like query parameters (token/session/key/…)")
        text = (parsed.get("url_redacted") or "")
        if EMAIL_IN_TEXT.search(text) or re.search(r"\d{10,}", text):
            soft.append("appears to contain personal data (an email address or a long number)")
        if from_payment:
            soft.append("is the auxiliary URL of a payment payload and may be a private payment callback")
        if soft and not override:
            return False, "Not sent: the URL " + "; ".join(soft) + ". An explicit user confirmation is required."
        return True, "Eligible for external lookup."


class ResultCache:
    """Small on-disk cache so repeated lookups don't re-send the same URL. Keys are hashes (no URLs stored)."""

    def __init__(self, directory: Path | None, ttl_seconds: int = 86400):
        self.dir = Path(directory) if directory else None
        self.ttl = ttl_seconds
        if self.dir:
            self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path | None:
        return self.dir / (hashlib.sha256(key.encode()).hexdigest()[:40] + ".json") if self.dir else None

    def get(self, key: str) -> dict | None:
        p = self._path(key)
        if not p or not p.is_file() or time.time() - p.stat().st_mtime > self.ttl:
            return None
        try:
            return json.loads(p.read_text())
        except (OSError, ValueError):
            return None

    def put(self, key: str, value: dict) -> None:
        p = self._path(key)
        if p:
            p.write_text(json.dumps(value))
