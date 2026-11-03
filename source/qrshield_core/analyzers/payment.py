"""Payment payload analysis (UPI, EMVCo merchant QR, cryptocurrency URIs). Never initiates a payment."""
from __future__ import annotations

import re
from decimal import Decimal

from ..models import Confidence, Evidence, Payload, Severity, Source
from .common import Deps
from .url import analyze_url_dict

A = "financial_transaction"
_SUSPICIOUS_VPA_TOKEN_RE = re.compile(
    r"(?:[._\-](?:mule|personal|refund|claim|verify|agent|helpdesk|collect|payout|scam|temp)\d*|\b(?:mule|scam)\d*\b)",
    re.I,
)


def analyze_payment(p: Payload, deps: Deps) -> list[Evidence]:
    reg, ref, nf = deps.reg, deps.ref, p.normalized_fields
    S = Source.QR_PAYLOAD
    out: list[Evidence] = []
    if not p.parse_ok:
        out.append(reg.make("TXT-006", "; ".join(p.notes) or "The payment payload could not be safely normalized.",
                            source=S, related_action=A))
        return out
    rec = nf.get("recipient")
    if rec:
        out.append(reg.make("PAY-001", f"Payment recipient identifier: {rec} (scheme: {nf.get('scheme')}).", source=S, payload_field="recipient", related_action=A))
        if nf.get("recipient_format_valid") is False:
            out.append(reg.make("PAY-007", f"'{rec}' does not match the expected format for {nf.get('rail')}.", source=S, payload_field="recipient", related_action=A))
        elif "@" in rec and _SUSPICIOUS_VPA_TOKEN_RE.search(rec.split("@", 1)[0]):
            out.append(reg.make("PAY-007", f"'{rec}' contains a suspicious personal/mule/dispute token in the VPA local part.",
                                source=S, payload_field="recipient", related_action=A, severity=Severity.MEANINGFUL))
    if not nf.get("payee_name"):
        out.append(reg.make("PAY-002", "No payee/merchant name is encoded, so the recipient cannot be compared by name.", source=S, payload_field="payee_name", related_action=A))
    if nf.get("amount_valid") is False:
        out.append(reg.make("PAY-010", "The amount field is not a valid number.", source=S, payload_field="amount", related_action=A))
    elif nf.get("amount") is not None:
        amt = Decimal(nf["amount"])
        if amt <= 0:
            out.append(reg.make("PAY-010", f"The encoded amount is {amt}.", source=S, payload_field="amount", related_action=A))
        else:
            out.append(reg.make("PAY-004", f"The payload fixes the amount at {amt} {nf.get('currency') or ''}.".strip(), source=S, payload_field="amount", related_action=A))
            thr = ref.thresholds["large_amount"].get(nf.get("currency"), ref.thresholds["large_amount"]["default"])
            if amt >= Decimal(str(thr)):
                out.append(reg.make("PAY-003", f"The amount {amt} {nf.get('currency') or ''} is at or above the configured threshold ({thr}).".strip(),
                                    source=S, payload_field="amount", related_action=A, expected=f"< {thr}"))
    else:
        out.append(reg.make("PAY-011", "The QR code does not fix the amount; the payer enters it.", source=S, payload_field="amount", related_action=A))
    if nf.get("crc_valid") is False:
        out.append(reg.make("PAY-008", "The EMV payload's CRC-16 checksum does not validate.", source=S, payload_field="crc", related_action=A))
    if nf.get("unrecognized_params"):
        out.append(reg.make("PAY-006", f"Unrecognised parameter(s): {', '.join(nf['unrecognized_params'][:8])}.", source=S, payload_field="parameters", related_action=A))
    if nf.get("ancillary_url"):
        out.append(reg.make("PAY-005", "The payment payload includes an auxiliary URL.", source=S, payload_field="ancillary_url", related_action=A))
        out += analyze_url_dict(nf["ancillary_url_parsed"], deps, field="ancillary_url", action=A)
    if nf.get("transaction_note"):
        out += deps.request_evidence(nf["transaction_note"], field_name="transaction_note", related_action=A)
    return out
