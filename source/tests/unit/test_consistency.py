import pytest

from qrshield_core.models import Confidence, MatchResult, Severity
from qrshield_core.context.extract import ContextCandidate, build_context
from tests.conftest import ids

HOTEL = {"organization": "Sunrise Hotel", "context_type": "hotel", "purpose": "Scan to pay", "amount": "850"}


def ev(norm, consistency, ctx, raw, c):
    return consistency.evaluate(norm(raw), ctx(c))


def upi(pn, am="850"):
    return f"upi://pay?pa=x@okicici&pn={pn.replace(' ', '%20')}&am={am}"


def test_matching_recipient_produces_no_finding(norm, consistency, ctx):
    e, recs = ev(norm, consistency, ctx, upi("Sunrise Hotel"), HOTEL)
    assert not e and recs[0].result is MatchResult.MATCH


def test_legal_name_variation_is_not_a_mismatch(norm, consistency, ctx):
    e, _ = ev(norm, consistency, ctx, upi("Sunrise Hospitality Pvt Ltd"), HOTEL)
    assert not ids(e) & {"CTX-002", "CTX-011"}


def test_payment_processor_is_ambiguous_not_mismatch(norm, consistency, ctx):
    e, recs = ev(norm, consistency, ctx, upi("ExamplePay Merchant Services"), HOTEL)
    assert ids(e) == {"CTX-011"} and e[0].severity is Severity.WEAK and e[0].plausible_exceptions
    assert recs[0].exception_hint


def test_recipient_mismatch_is_meaningful_with_exceptions_and_typed(norm, consistency, ctx):
    e, _ = ev(norm, consistency, ctx, upi("ABC Trading"), HOTEL)
    f = e[0]
    assert f.indicator_id == "CTX-002" and f.severity is Severity.MEANINGFUL and f.mismatch_type.value == "recipient mismatch"
    assert f.expected == "Sunrise Hotel" and "ABC Trading" in f.observation and len(f.plausible_exceptions) >= 3 and f.provenance == "scenario_input"


def test_amount_mismatch_and_equal_amount(norm, consistency, ctx):
    assert "CTX-007" in ids(ev(norm, consistency, ctx, upi("Sunrise Hotel", "8500"), HOTEL)[0])
    assert "CTX-007" not in ids(ev(norm, consistency, ctx, upi("Sunrise Hotel", "850.00"), HOTEL)[0])


def test_receive_money_direction_mismatch(norm, consistency, ctx):
    e, _ = ev(norm, consistency, ctx, upi("ABC Trading", "15000"), {**HOTEL, "purpose": "Refund counter - scan QR to receive refund", "amount": ""})
    assert {"CTX-002", "CTX-009"} <= ids(e)


def test_no_context_yields_info_only(norm, consistency, ctx):
    e, recs = ev(norm, consistency, ctx, upi("ABC Trading"), {})
    assert ids(e) == {"CTX-012"} and e[0].severity is Severity.INFO and not recs


def test_context_without_comparable_attribute(norm, consistency, ctx):
    e, _ = ev(norm, consistency, ctx, "SMSTO:+910000000011:hi", {"organization": "Sunrise Hotel"})
    assert ids(e) == {"CTX-012"}


def test_url_known_brand_official_vs_lookalike(norm, consistency, ctx):
    bank = {"organization": "ABC Bank", "context_type": "bank", "purpose": "Login / Verify"}
    assert not ev(norm, consistency, ctx, "https://abcbank.example/login", bank)[0]
    e, _ = ev(norm, consistency, ctx, "http://abcbank-verify.example/login", bank)
    assert "CTX-003" in ids(e) and e[0].expected == "abcbank.example"


def test_url_unrelated_domain_severity_depends_on_organisation_type(norm, consistency, ctx):
    shop = ev(norm, consistency, ctx, "https://totally-different.example", {"organization": "Delta Mart", "context_type": "shop"})[0]
    bank = ev(norm, consistency, ctx, "https://totally-different.example", {"organization": "Delta Bank", "context_type": "bank"})[0]
    assert shop[0].severity is Severity.WEAK and bank[0].severity is Severity.MEANINGFUL


def test_displayed_domain_mismatch(norm, consistency, ctx):
    e, _ = ev(norm, consistency, ctx, "https://other.example/x", {"organization": "Delta Mart", "additional": "Visit deltamart.example"})
    assert any(x.indicator_id == "CTX-003" and x.expected == "deltamart.example" for x in e)


def test_wifi_cases(norm, consistency, ctx):
    uni = {"organization": "Greenfield University", "context_type": "university"}
    assert not ev(norm, consistency, ctx, "WIFI:T:WPA;S:Greenfield_Guest;P:x;;", {**uni, "purpose": "Guest Wi-Fi"})[0]
    assert "CTX-006" in ids(ev(norm, consistency, ctx, "WIFI:T:WPA;S:CityCafe_Free;P:x;;", {**uni, "purpose": "Guest Wi-Fi"})[0])
    e, _ = ev(norm, consistency, ctx, "WIFI:T:nopass;S:random-public;;", {**uni, "purpose": "Official campus Wi-Fi"})
    assert {"CTX-006", "CTX-013"} <= ids(e)
    assert "CTX-013" not in ids(ev(norm, consistency, ctx, "WIFI:T:nopass;S:Sunrise_Guest;;", {**HOTEL, "purpose": "Guest Wi-Fi"})[0])    # open guest network is fine
    e, _ = ev(norm, consistency, ctx, "WIFI:T:WPA;S:Sunrise_Staff;P:x;;", {**HOTEL, "context_type": "poster", "purpose": "Staff-only network - do not share"})
    assert "CTX-014" in ids(e)


def test_wifi_named_network_on_signage(norm, consistency, ctx):
    e, _ = ev(norm, consistency, ctx, "WIFI:T:WPA;S:EvilTwin;P:x;;", {"organization": "Sunrise Hotel", "network": "Network: Sunrise_Guest"})
    assert "CTX-006" in ids(e)


def test_contact_and_message_destinations(norm, consistency, ctx):
    v = "BEGIN:VCARD\nFN:A\nORG:ABC Infotech\nTEL:+910000000055\nEMAIL:help@secure-support.example\nEND:VCARD"
    assert "CTX-004" in ids(ev(norm, consistency, ctx, v, {"organization": "ABC Infotech", "purpose": "Customer support"})[0])
    assert "CTX-010" in ids(ev(norm, consistency, ctx, "SMSTO:+910000000044:hi", {**HOTEL, "purpose": "Text us", "additional": "Reception: +91 00000 00033"})[0])
    assert "CTX-010" not in ids(ev(norm, consistency, ctx, "SMSTO:+910000000033:hi", {**HOTEL, "purpose": "Text us", "additional": "Reception: +91 00000 00033"})[0])
    assert "CTX-004" in ids(ev(norm, consistency, ctx, "mailto:help@unrelated-mail.example", {"organization": "ABC Infotech", "purpose": "Email us"})[0])


def test_deeplink_context(norm, consistency, ctx):
    e, _ = ev(norm, consistency, ctx, "sgnl://linkdevice?uuid=EX&pub_key=EX", {**HOTEL, "purpose": "Scan to view menu"})
    assert {"CTX-008", "CTX-005"} <= ids(e)
    assert not ev(norm, consistency, ctx, "sgnl://linkdevice?uuid=EX&pub_key=EX", {"organization": "Signal", "purpose": "Link Signal Desktop to your phone"})[0]


def test_known_high_confidence_application_mismatch_is_meaningful(norm, consistency, ctx):
    c = build_context([ContextCandidate("c1", "organization", "Example Bank", "Example Bank", "Example Bank", Confidence.HIGH, [[0, 0], [10, 0], [10, 10], [0, 10]])],
                      auto_use_unconfirmed=True)
    e, _ = consistency.evaluate(norm("pinecrestservices://view/dashboard"), c)
    f = next(x for x in e if x.indicator_id == "CTX-008")
    assert f.severity is Severity.MEANINGFUL



def test_store_links_do_not_false_flag(norm, consistency, ctx):
    """Regression: market:// opens the store, so the organisation must be compared with the package id, not 'Google Play Store'."""
    c = {"organization": "Example Shop", "purpose": "Download our app"}
    assert not ev(norm, consistency, ctx, "market://details?id=com.exampleshop.app", c)[0]
    e, _ = ev(norm, consistency, ctx, "market://details?id=com.random.thing", c)
    assert ids(e) == {"CTX-011"} and e[0].severity is Severity.WEAK


def test_low_confidence_unconfirmed_ocr_is_capped_at_weak(norm, consistency):
    low = build_context([ContextCandidate("c1", "organization", "Sunr1se", "Sunrise Hotel", "Sunrise Hotel", Confidence.LOW, [[0, 0], [1, 0], [1, 1], [0, 1]])],
                        auto_use_unconfirmed=True)
    e, _ = consistency.evaluate(norm(upi("ABC Trading")), low)
    f = next(x for x in e if x.indicator_id == "CTX-002")
    assert f.severity is Severity.WEAK and f.provenance == "ocr" and any("low" in n for n in f.notes)


def test_unparseable_payload_skips_context_checks(norm, consistency, ctx):
    e, _ = ev(norm, consistency, ctx, "upi://pay?pn=NoAddress", HOTEL)
    assert not ids(e) - {"CTX-012"}
