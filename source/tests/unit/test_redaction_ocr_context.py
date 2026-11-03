import logging

import numpy as np
import pytest

from qrshield_core.logging_utils import configure_logging, get_logger
from qrshield_core.models import Confidence as C
from qrshield_core.context.extract import ContextCandidate, ContextDecision, build_context, context_from_scenario, extract_candidates
from qrshield_core.ocr.engine import (OCRProvider, PaddleOCRProvider, StaticOCRProvider, classify_block_type, normalize_ocr_text,
                                      parse_paddle_result, run_ocr)
from qrshield_core.redaction import redact_otp_text, redact_payload_raw, redact_text, redact_url, redact_wifi_raw

BOX = lambda x, y, w, h: [[x, y], [x + w, y], [x + w, y + h], [x, y + h]]


# ---------------------------------------------------------------- redaction
def test_wifi_password_redacted():
    assert redact_wifi_raw("WIFI:T:WPA;S:Cafe;P:hunter2;H:false;;") == "WIFI:T:WPA;S:Cafe;P:[REDACTED];H:false;;"
    assert "ss" not in redact_payload_raw("WIFI:T:WPA;S:Cafe;P:pa\\;ss;;").replace("password", "")


def test_otp_and_url_secrets_redacted():
    assert "839123" not in redact_otp_text("Send OTP 839123 now") and "4455" not in redact_otp_text("your PIN: 4455")
    assert "Table 12" == redact_otp_text("Table 12")
    u = redact_url("https://a.example/p?token=SECRET&x=1&password=pw")
    assert "SECRET" not in u and "pw" not in u.split("password=")[1][:3] and "x=1" in u
    assert "pass123" not in redact_url("https://user:pass123@a.example/")


def test_generic_text_redaction_covers_api_keys():
    assert "abcdef0123456789abcdef" not in redact_text("x-apikey: abcdef0123456789abcdef")
    assert "s3cret" not in redact_text("password=s3cret ok")


def test_log_filter_scrubs_secrets(caplog):
    configure_logging("INFO")
    lg = get_logger("test")
    lg.propagate = True
    logging.getLogger("qrshield").propagate = True
    with caplog.at_level(logging.INFO, logger="qrshield"):
        lg.info("calling with password=hunter2 and token=abc123")
    assert "hunter2" not in caplog.text and "abc123" not in caplog.text


# ---------------------------------------------------------------- OCR
def test_paddle_result_parsing_3x_and_2x_and_empty():
    r3 = [{"rec_texts": ["HOTEL", " "], "rec_scores": [0.98, 0.5], "rec_polys": [np.array(BOX(1, 2, 30, 18)), np.array(BOX(0, 0, 1, 1))]}]
    assert parse_paddle_result(r3) == [("HOTEL", 0.98, BOX(1, 2, 30, 18))]
    nested = [{"res": {"rec_texts": ["A"], "rec_scores": [0.9], "dt_polys": [BOX(0, 0, 5, 5)]}}]
    assert parse_paddle_result(nested)[0][0] == "A"
    r2 = [[[BOX(1, 2, 30, 18), ("HOTEL", 0.97)]]]
    assert parse_paddle_result(r2)[0][:2] == ("HOTEL", 0.97)
    assert parse_paddle_result(None) == [] and parse_paddle_result([None]) == [] and parse_paddle_result([[]]) == []


def test_ocr_normalisation_keeps_numbers_and_domains():
    assert normalize_ocr_text("Sunrise H0tel") == "Sunrise Hotel" and normalize_ocr_text("SUNR1SE HOTEL") == "SUNRISE HOTEL"
    for keep in ("abc1.example", "+91 98000 00001", "Rs. 850", "a1b2@x.example", "Room 101"):
        assert normalize_ocr_text(keep) == keep


@pytest.mark.parametrize("text,kind", [
    ("support@abc.example", "email"), ("Rs. 850", "amount"), ("₹15,000", "amount"), ("+91 98000 00001", "phone"), ("abcshop.example", "domain"),
    ("SCAN TO PAY", "purpose"), ("Guest Wi-Fi", "purpose"), ("Network: Sunrise_Guest", "network"), ("SUNRISE HOTEL", "organization"), ("Please scan the code", "other"),
])
def test_block_classification(ref, text, kind):
    assert classify_block_type(text, ref) == kind


def test_run_ocr_masks_qr_and_keeps_raw_vs_normalised(ref):
    seen = {}

    class Spy(StaticOCRProvider):
        def recognize(self, bgr):
            seen["masked"] = bool((bgr[260:420, 210:390] == 255).all())
            return super().recognize(bgr)
    img = np.zeros((700, 700, 3), np.uint8)
    res = run_ocr(Spy([("SUNRISE H0TEL", 0.93, BOX(50, 20, 500, 90))]), img, ref, qr_boxes=[BOX(200, 250, 200, 200)])
    assert seen["masked"] and res.masked_qr_regions == 1
    b = res.blocks[0]
    assert (b.raw_text, b.normalized_text, b.confidence, b.source) == ("SUNRISE H0TEL", "SUNRISE HOTEL", C.HIGH, "ocr")


def test_ocr_unavailable_failed_and_disabled_are_explicit_not_verdicts(ref):
    img = np.zeros((10, 10, 3), np.uint8)

    class Down(OCRProvider):
        name = "down"
        def available(self): return False, "models missing"
        def recognize(self, bgr): raise AssertionError

    class Crash(OCRProvider):
        name = "crash"
        def available(self): return True, ""
        def recognize(self, bgr): raise RuntimeError("boom")
    assert run_ocr(Down(), img, ref).status == "unavailable" and "manually" in run_ocr(Down(), img, ref).message
    assert run_ocr(Crash(), img, ref).status == "failed"
    assert run_ocr(None, img, ref).status == "disabled" and run_ocr(Down(), img, ref, enabled=False).status == "disabled"
    assert run_ocr(StaticOCRProvider([]), img, ref).status == "no_text"


def test_real_paddle_provider_reports_unavailable_when_models_cannot_load(ref, monkeypatch):
    """No network/models in CI: the adapter must degrade to an explicit 'unavailable' state instead of raising."""
    import builtins
    real_import = builtins.__import__

    def fake(name, *a, **k):
        if name == "paddleocr":
            raise ImportError("paddleocr not installed")
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake)
    res = run_ocr(PaddleOCRProvider(), np.zeros((10, 10, 3), np.uint8), ref)
    assert res.status == "unavailable" and "paddleocr" in res.message.lower()


# ---------------------------------------------------------------- context extraction & provenance
def cands(ref):
    blocks = run_ocr(StaticOCRProvider([("SUNRISE HOTEL", 0.93, BOX(50, 20, 500, 90)), ("SCAN TO PAY", 0.97, BOX(50, 140, 300, 50)),
                                        ("Rs. 850", 0.95, BOX(50, 200, 120, 40)), ("support@abc.example", 0.88, BOX(50, 500, 300, 30)),
                                        ("+91 98000 00001", 0.91, BOX(50, 540, 250, 30)), ("abcshop.example", 0.9, BOX(50, 580, 260, 30))]),
                     np.zeros((700, 700, 3), np.uint8), ref).blocks
    return extract_candidates(blocks, ref)


def test_candidate_extraction(ref):
    c = {(x.attribute, x.value) for x in cands(ref)}
    assert {("organization", "SUNRISE HOTEL"), ("purpose", "SCAN TO PAY"), ("amount", "850"), ("email", "support@abc.example"), ("domain", "abcshop.example"), ("context_type", "hotel")} <= c
    assert any(x.attribute == "phone" for x in cands(ref))


def test_ambiguous_organisation_candidates_are_flagged_and_downgraded(ref):
    blocks = run_ocr(StaticOCRProvider([("SUNRISE HOTEL", 0.95, BOX(0, 0, 400, 80)), ("GRAND PLAZA", 0.95, BOX(0, 100, 400, 80))]), np.zeros((300, 500, 3), np.uint8), ref).blocks
    orgs = [x for x in extract_candidates(blocks, ref) if x.attribute == "organization"]
    assert len(orgs) == 2 and orgs[0].confidence is C.MEDIUM and "Several" in (orgs[0].note or "") and orgs[1].confidence is not C.HIGH


def test_undecided_ocr_candidates_are_never_used(ref):
    assert build_context(cands(ref)).is_empty()                          # nothing without an explicit decision


def test_provenance_rules(ref):
    cs = cands(ref)
    org, purpose = next(c for c in cs if c.attribute == "organization"), next(c for c in cs if c.attribute == "purpose")
    amount = next(c for c in cs if c.attribute == "amount")
    ctx = build_context(cs, {org.candidate_id: ContextDecision("use"), purpose.candidate_id: ContextDecision("edit", "Pay at the bar"),
                             amount.candidate_id: ContextDecision("ignore")}, {"organization": "Manual Name"})
    by = {(a.attribute, a.source): a for a in ctx.attributes}
    assert by[("organization", "user_confirmed_ocr")].raw_value == "SUNRISE HOTEL" and by[("organization", "user_confirmed_ocr")].confidence is C.HIGH
    assert by[("purpose", "user_input")].value == "Pay at the bar" and by[("purpose", "user_input")].raw_value == "SCAN TO PAY"
    assert ("amount", "user_confirmed_ocr") not in by and ("amount", "ocr") not in by
    assert ctx.get("organization").value == "Manual Name" and ctx.get("organization").source == "user_input"      # manual entry wins


def test_unconfirmed_ocr_requires_explicit_opt_in_and_keeps_ocr_confidence(ref):
    ctx = build_context(cands(ref), auto_use_unconfirmed=True)
    assert {a.source for a in ctx.attributes} == {"ocr"} and ctx.get("organization").confidence is C.HIGH


def test_free_text_hints_are_harvested_as_user_provided_context():
    ctx = build_context(manual={"additional": "Reception +91 00000 00033, mail desk@abc.example, see abc.example"})
    assert ctx.get("phone").source == "user_input" and ctx.get("email").value == "desk@abc.example" and ctx.get("domain")


def test_scenario_context_uses_scenario_input_source():
    assert context_from_scenario({"organization": "X", "amount": ""}).attributes[0].source == "scenario_input"


def test_labelled_context_fields_are_structured_and_wrapped_values_reconstructed(ref):
    blocks = run_ocr(StaticOCRProvider([
        ("Redstone Market", 0.94, BOX(50, 20, 450, 50)),
        ("Purpose: Visit the official website", 0.94, BOX(50, 90, 500, 40)),
        ("Official Domain: —redstone-market.test", 0.92, BOX(50, 160, 520, 40)),
        ("Contact Email: contact89@pinecrest-hotels.t", 0.91, BOX(50, 230, 560, 40)),
        ("est", 0.91, BOX(50, 275, 40, 35)),
        ("Displayed Phone: +1-202-555-1071", 0.93, BOX(50, 320, 520, 40)),
        ("Amount: %1800.00", 0.90, BOX(50, 390, 300, 40)),
    ]), np.zeros((700, 900, 3), np.uint8), ref).blocks
    got = {(c.attribute, c.value) for c in extract_candidates(blocks, ref)}
    assert ("domain", "redstone-market.test") in got
    assert ("email", "contact89@pinecrest-hotels.test") in got
    assert ("phone", "+1-202-555-1071") in got
    assert ("amount", "1800.00") in got


def test_labelled_email_with_wrapped_suffix_and_ocr_spaces_is_reconstructed(ref):
    blocks = run_ocr(StaticOCRProvider([
        ("Contact Email: support84 @cedar-grove-clinic", 0.70, BOX(50, 20, 560, 40)),
        (".test", 0.52, BOX(390, 65, 60, 25)),
    ]), np.zeros((180, 800, 3), np.uint8), ref).blocks
    got = {(c.attribute, c.value) for c in extract_candidates(blocks, ref)}
    assert ("email", "support84@cedar-grove-clinic.test") in got


def test_scenario_context_aliases_are_normalised():
    ctx = context_from_scenario({
        "organization": "Example Venue",
        "official_domain": "example-venue.test",
        "contact_email": "help@example-venue.test",
        "displayed_phone": "+1-202-555-0001",
        "merchant": "Example Venue",
    })
    assert ctx.get("domain").value == "example-venue.test"
    assert ctx.get("email").value == "help@example-venue.test"
    assert ctx.get("phone").value == "+1-202-555-0001"

