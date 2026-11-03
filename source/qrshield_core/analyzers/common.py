"""Shared analyzer dependencies and the sensitive-request lexicon."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..matching.entity import Matcher
from ..models import Confidence, Evidence, Source
from ..redaction import redact_otp_text
from ..rules import ReferenceData, RuleRegistry


@dataclass
class Deps:
    reg: RuleRegistry
    ref: ReferenceData
    matcher: Matcher
    _lex: dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        lx = self.ref.lexicon
        alt = lambda xs: "|".join(re.escape(x) for x in sorted(xs, key=len, reverse=True))
        verbs = alt(lx["request_verbs"])
        self._lex = {
            "credential": re.compile(rf"\b(?:{verbs})\b[^.\n]{{0,40}}?\b(?:{alt(lx['credential_objects'])})\b", re.I),
            "credential_value": re.compile(rf"\b(?:{alt(lx['credential_objects'])})\b(?:\W{{0,8}}\[REDACTED\]|\W{{0,6}}[:=#-]\W{{0,6}}[A-Za-z0-9][A-Za-z0-9._-]{{2,}})", re.I),
            "credential_semantic": re.compile(
                r"\b(?:"
                r"(?:read|recite|share|send|reply|forward|enter|provide|text|here\s+are)\b[^.\n]{0,55}?\b(?:\d+|four|six|three|4|6|3)\s+(?:secret\s+|entry\s+|security\s+|verification\s+|one[- ]time\s+)?(?:digits?|numerals?|numbers?|codes?)\b"
                r"|(?:\d+|four|six|three|4|6|3)\s+(?:secret\s+|entry\s+|security\s+|verification\s+|one[- ]time\s+)?(?:digits?|numerals?)\b[^.\n]{0,45}?\b(?:on\s+your\s+screen|just\s+arrived|sent\s+to\s+your|back\s+of\s+(?:your\s+)?card)"
                r"|(?:restore|unlock|confirm|verify)\b[^.\n]{0,35}?\b(?:account\s+access|wallet\s+custody|seed\s+phrase|recovery\s+phrase)"
                r")\b",
                re.I,
            ),
            "benign_cred": re.compile(
                r"\b(?:"
                r"(?:reading|vip|book|member|loyalty|social|friday)\s+club\s+(?:passcode|password|pin|code)"
                r"|(?:guest|room|wifi|wi-fi|door|gate|locker|parking|visitor)\s+(?:passcode|password|pin)\b(?!\s*(?:and\s+otp|immediately|now\b))"
                r"|staff\s+checklist\b[^.\n]{0,60}?\bterminal\s+pin\s+before\s+opening\s+register"
                r")\b",
                re.I,
            ),
            "financial_obj": re.compile(rf"\b(?:{verbs})\b[^.\n]{{0,40}}?\b(?:{alt(lx['financial_objects'])})\b", re.I),
            "financial_act": re.compile(rf"\b(?:{alt(lx['financial_actions'])})\b[^.\n]{{0,30}}?(?:rs\.?\s?\d|₹\s?\d|\$\s?\d|inr\s?\d|\b\d{{3,}}\b)", re.I),
            "personal": re.compile(rf"\b(?:{verbs})\b[^.\n]{{0,60}}?\b(?:{alt(lx['personal_objects'])})\b", re.I),
            "urgency": re.compile(rf"\b(?:{alt(lx['urgency_phrases'])})\b", re.I),
            "neg": re.compile(rf"(?:{alt(lx['negations'])})\W+(?:\w+\W+){{0,7}}$", re.I),
        }

    def find_requests(self, text: str) -> dict[str, str]:
        """Return {category: matched snippet}. Negated phrasing ('do not share your OTP or PIN') and benign venue/guest codes are ignored."""
        found: dict[str, str] = {}
        t = text or ""
        is_benign_cred = bool(self._lex["benign_cred"].search(t))
        for cat, keys in (
            ("credential", ("credential", "credential_semantic", "credential_value")),
            ("financial", ("financial_obj", "financial_act")),
            ("personal", ("personal",)),
            ("urgency", ("urgency",)),
        ):
            if cat == "credential" and is_benign_cred:
                continue
            for k in keys:
                for m in self._lex[k].finditer(t):
                    if self._lex["neg"].search(t[max(0, m.start() - 75):m.start()]) and cat != "urgency":
                        continue
                    found.setdefault(cat, redact_otp_text(m.group(0))[:90])
                    break
        return found

    def request_evidence(self, text: str, *, field_name: str, related_action: str,
                         source: Source = Source.QR_PAYLOAD) -> list[Evidence]:
        out: list[Evidence] = []
        found = self.find_requests(text)
        labels = {"credential": ("COM-001", "asks the user to disclose a credential or one-time code"),
                  "financial": ("COM-002", "asks for a payment or financial details"),
                  "personal": ("COM-003", "asks for personal identity information"),
                  "urgency": ("COM-004", "uses urgency or pressure wording")}
        for cat, (rid, what) in labels.items():
            if cat in found:
                out.append(self.reg.make(rid, f"The pre-filled text {what}: “{found[cat]}”.", source=source,
                                         confidence=Confidence.MEDIUM, payload_field=field_name,
                                         related_action=related_action))
        return out
