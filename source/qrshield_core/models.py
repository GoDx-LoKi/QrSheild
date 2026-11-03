"""Shared data model for QRShield (plain dataclasses, JSON-serialisable)."""
from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from decimal import Decimal
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"              # descriptive observation, no concern by itself
    WEAK = "weak"              # weak indicator; common in benign deployments
    MEANINGFUL = "meaningful"  # meaningful anomaly requiring verification
    STRONG = "strong"          # strong indicator (still not proof by itself)


SEVERITY_ORDER = {Severity.INFO: 0, Severity.WEAK: 1, Severity.MEANINGFUL: 2, Severity.STRONG: 3}


class Family(str, Enum):
    PAYLOAD = "PAYLOAD"
    DESTINATION = "DESTINATION"
    CONTEXT = "CONTEXT"
    IDENTITY = "IDENTITY"
    ACTION = "ACTION"
    TRANSACTION = "TRANSACTION"
    NETWORK = "NETWORK"
    COMMUNICATION = "COMMUNICATION"
    APPLICATION = "APPLICATION"
    EXTERNAL_CORROBORATION = "EXTERNAL_CORROBORATION"


class Source(str, Enum):
    QR_PAYLOAD = "QR_PAYLOAD"
    OCR = "OCR"
    USER_CONTEXT = "USER_CONTEXT"
    URL_STATIC_ANALYSIS = "URL_STATIC_ANALYSIS"
    THREAT_INTEL = "THREAT_INTEL"
    ENTITY_MATCHER = "ENTITY_MATCHER"
    ACTION_ANALYZER = "ACTION_ANALYZER"
    IMAGE_ANALYSIS = "IMAGE_ANALYSIS"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


CONF_ORDER = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


def min_conf(*cs: Confidence) -> Confidence:
    return min(cs, key=lambda c: CONF_ORDER[c])


class PayloadType(str, Enum):
    URL = "url"
    WIFI = "wifi"
    PAYMENT = "payment"
    CONTACT = "contact"
    SMS = "sms"
    EMAIL = "email"
    DEEP_LINK = "deep_link"
    PLAIN_TEXT = "plain_text"


class Sensitivity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


SENS_ORDER = {Sensitivity.LOW: 0, Sensitivity.MEDIUM: 1, Sensitivity.HIGH: 2}


class AssessmentLevel(str, Enum):
    NO_MATERIAL_CONCERN = "no_material_concern"
    NEEDS_VERIFICATION = "needs_verification"
    HIGH_CONCERN = "high_concern"
    HARMFUL_CORROBORATED = "harmful_corroborated"


LEVEL_ORDER = {
    AssessmentLevel.NO_MATERIAL_CONCERN: 0,
    AssessmentLevel.NEEDS_VERIFICATION: 1,
    AssessmentLevel.HIGH_CONCERN: 2,
    AssessmentLevel.HARMFUL_CORROBORATED: 3,
}

LEVEL_LABELS = {
    AssessmentLevel.NO_MATERIAL_CONCERN: "No material concern detected",
    AssessmentLevel.NEEDS_VERIFICATION: "Needs verification",
    AssessmentLevel.HIGH_CONCERN: "High concern",
    AssessmentLevel.HARMFUL_CORROBORATED: "Harmful / corroborated",
}


class MatchResult(str, Enum):
    MATCH = "MATCH"
    LIKELY_MATCH = "LIKELY MATCH"
    UNCERTAIN = "UNCERTAIN"
    MISMATCH = "MISMATCH"
    INSUFFICIENT_CONTEXT = "INSUFFICIENT CONTEXT"


class MismatchType(str, Enum):
    IDENTITY = "identity mismatch"
    DESTINATION = "destination mismatch"
    ACTION = "action mismatch"
    AMOUNT = "amount mismatch"
    NETWORK = "network mismatch"
    RECIPIENT = "recipient mismatch"
    DOMAIN = "domain mismatch"
    APPLICATION_TARGET = "application-target mismatch"
    PURPOSE = "purpose mismatch"
    COMMUNICATION_TARGET = "communication-target mismatch"
    INSUFFICIENT_CONTEXT = "insufficient context"
    AMBIGUOUS_IDENTITY = "ambiguous identity"


class ThreatIntelStatus(str, Enum):
    CONFIRMED_MALICIOUS_EVIDENCE = "confirmed_malicious_evidence"
    SUSPICIOUS_MIXED = "suspicious_mixed"
    NO_KNOWN_MALICIOUS_REPORT = "no_known_malicious_report"
    NO_RESULT = "no_result"
    UNAVAILABLE = "unavailable"
    RATE_LIMITED = "rate_limited"
    AUTH_FAILURE = "authentication_failure"
    NOT_QUERIED = "not_queried"


@dataclass
class Evidence:
    """One explainable finding. Every finding traces to a registered rule."""

    indicator_id: str
    title: str
    category: str
    severity: Severity
    source: Source
    observation: str
    expected: str | None
    confidence: Confidence
    rationale: str
    payload_field: str | None
    context_attribute: str | None
    related_action: str | None
    family: Family
    independent_group: str
    recommendation: str | None = None
    mismatch_type: MismatchType | None = None
    plausible_exceptions: list[str] = field(default_factory=list)
    provenance: str | None = None   # provenance of the context attribute used, if any
    layer: str = "payload"          # payload | context | action | external (used by ablations)
    notes: list[str] = field(default_factory=list)


@dataclass
class Payload:
    """P = {type, raw, normalized_fields, action, entities, destinations}."""

    type: PayloadType
    raw: str = field(metadata={"serialize": False})
    raw_redacted: str = ""
    normalized_fields: dict[str, Any] = field(default_factory=dict)
    action: str = "display_text"
    entities: list[dict[str, Any]] = field(default_factory=list)
    destinations: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    parse_ok: bool = True
    classification_reason: str = ""


@dataclass
class ContextAttribute:
    attribute: str          # organization|purpose|amount|context_type|domain|email|phone|network|service|additional
    value: str
    source: str             # ocr | user_confirmed_ocr | user_input | scenario_input
    confidence: Confidence
    raw_value: str | None = None
    bbox: list[list[int]] | None = None
    candidate_id: str | None = None


@dataclass
class Context:
    attributes: list[ContextAttribute] = field(default_factory=list)

    def get(self, name: str) -> ContextAttribute | None:
        for a in self.attributes:
            if a.attribute == name and a.value.strip():
                return a
        return None

    def get_all(self, name: str) -> list[ContextAttribute]:
        return [a for a in self.attributes if a.attribute == name and a.value.strip()]

    def is_empty(self) -> bool:
        return not any(a.value.strip() for a in self.attributes)

    def text(self) -> str:
        return " ".join(a.value for a in self.attributes if a.value.strip())


@dataclass
class MatchRecord:
    """A single entity/destination comparison made by the matching layer."""

    comparison: str          # e.g. "organization vs payment recipient"
    expected: str | None
    observed: str | None
    result: MatchResult
    rationale: str
    context_attribute: str | None = None
    payload_field: str | None = None
    provenance: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    exception_hint: str | None = None


def to_dict(obj: Any) -> Any:
    """Recursively convert dataclasses/enums/Decimals to JSON-friendly primitives."""
    if is_dataclass(obj) and not isinstance(obj, type):
        out: dict[str, Any] = {}
        for f in fields(obj):
            if f.metadata.get("serialize") is False:
                continue
            out[f.name] = to_dict(getattr(obj, f.name))
        return out
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {str(k): to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_dict(v) for v in obj]
    if isinstance(obj, Decimal):
        return str(obj)
    return obj
