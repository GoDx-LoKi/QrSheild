"""Integration: image → QR decode → payload analyzer → OCR → context → mismatch → action → decision."""
import io
import json

import numpy as np
import pytest
import qrcode
from PIL import Image

from qrshield_core.context.extract import ContextDecision, build_context, context_from_scenario
from qrshield_core.image.loader import ImageError
from qrshield_core.ocr.engine import StaticOCRProvider
from qrshield_core.pipeline import ABLATIONS, AnalysisConfig, QRShieldEngine
from qrshield_core.threat_intel.base import MockThreatIntelProvider
from qrshield_core.threat_intel.service import ThreatIntelService

SCENARIOS = {
    "PAY-S01": {
        "raw_payload": "upi://pay?pa=abctrading@okicici&pn=ABC%20Trading&am=850",
        "context": {"organization": "Sunrise Hotel", "purpose": "Scan to pay"},
    },
    "PAY-S04": {
        "raw_payload": "upi://pay?pa=abctrading@okicici&pn=ABC%20Trading&am=850",
        "context": {"organization": "Sunrise Hotel", "purpose": "Scan to pay", "amount": "850"},
    },
    "PAY-S06": {
        "raw_payload": "upi://pay?pa=abctrading@okicici&pn=ABC%20Trading&am=15000.00&cu=INR",
        "context": {"organization": "Sunrise Hotel", "context_type": "hotel", "purpose": "Refund counter - scan QR to receive refund"},
    },
    "URL-S05": {
        "raw_payload": "http://abcbank-verify.example/login?session=a1&token=b2",
        "context": {"organization": "ABC Bank"},
    },
    "WIFI-S04": {
        "raw_payload": "WIFI:T:WPA;S:CoffeeShop;P:coffee123;;",
        "context": {"organization": "Coffee Shop", "purpose": "Free WiFi"},
    },
    "SMS-S02": {
        "raw_payload": "SMSTO:+919876543210:Hello",
        "context": {"organization": "Support Desk"},
    },
    "CON-S04": {
        "raw_payload": "BEGIN:VCARD\nVERSION:3.0\nFN:John Doe\nTEL:+1234567890\nEND:VCARD",
        "context": {"organization": "Acme Corp"},
    },
    "EML-S03": {
        "raw_payload": "MATMSG:TO:test@example.com;SUB:Hello;BODY:World;;",
        "context": {"organization": "Help Desk"},
    },
    "DL-S04": {
        "raw_payload": "slack://channel?team=T123&id=C123",
        "context": {"organization": "Slack Community"},
    },
}


class MockDataset:
    version = "1.0.0"

    def by_id(self):
        return SCENARIOS


@pytest.fixture(scope="module")
def ds():
    return MockDataset()


def qr_png(text, box=8):
    q = qrcode.QRCode(box_size=box, border=4)
    q.add_data(text)
    q.make(fit=True)
    buf = io.BytesIO()
    q.make_image(fill_color="black", back_color="white").convert("RGB").save(buf, "PNG")
    return buf.getvalue()


def box(x, y, w, h):
    return [[x, y], [x + w, y], [x + w, y + h], [x, y + h]]


@pytest.mark.parametrize("sid", ["PAY-S01", "URL-S05", "WIFI-S04", "SMS-S02", "CON-S04", "EML-S03", "DL-S04"])
def test_rendered_scenario_decodes_to_exact_payload(engine, ds, sid):
    sc = ds.by_id()[sid]
    prep = engine.prepare_image(qr_png(sc["raw_payload"]), f"{sid}.png")
    assert prep.decode.count == 1 and prep.decode.codes[0].payload == sc["raw_payload"]
    assert prep.decode.codes[0].decoder.startswith("opencv")


def test_multiple_qr_codes_are_all_reported_and_not_silently_chosen(engine):
    canvas = Image.new("RGB", (900, 400), "white")
    for text, x in (("WIFI:T:WPA;S:Cafe;P:hunter2;;", 20), ("upi://pay?pa=a@b&pn=X", 460)):
        canvas.paste(Image.open(io.BytesIO(qr_png(text, 6))), (x, 40))
    buf = io.BytesIO()
    canvas.save(buf, "PNG")
    prep = engine.prepare_image(buf.getvalue(), "multi.png")
    assert prep.decode.count == 2 and {c.payload for c in prep.decode.codes} == {"WIFI:T:WPA;S:Cafe;P:hunter2;;", "upi://pay?pa=a@b&pn=X"}
    assert [c.index for c in prep.decode.codes] == [0, 1]
    r0 = engine.analyze_prepared(prep, 0, context_from_scenario({}), AnalysisConfig()).to_dict()
    r1 = engine.analyze_prepared(prep, 1, context_from_scenario({}), AnalysisConfig()).to_dict()
    assert {r0["payload"]["type"], r1["payload"]["type"]} == {"wifi", "payment"} and r0["qr"]["count"] == 2


def test_no_qr_is_reported_without_a_verdict(engine):
    buf = io.BytesIO()
    Image.new("RGB", (300, 300), "white").save(buf, "PNG")
    prep = engine.prepare_image(buf.getvalue(), "blank.png")
    assert prep.decode.count == 0 and prep.ocr.status in ("disabled", "no_text", "unavailable")


def test_invalid_images_are_rejected_with_codes(engine):
    for data, code in ((b"", "empty"), (b"GIF-not-really", "invalid_image"), (b"<svg xmlns='http://www.w3.org/2000/svg'/>", "invalid_image")):
        with pytest.raises(ImageError) as e:
            engine.prepare_image(data, "x")
        assert e.value.code == code


def test_image_to_ocr_to_context_to_decision(settings, ds):
    """The paper's central example, end to end: the image says Sunrise Hotel, the QR pays ABC Trading."""
    ocr = StaticOCRProvider([("SUNRISE H0TEL", 0.93, box(80, 40, 700, 90)), ("SCAN TO PAY", 0.97, box(250, 150, 400, 50)), ("Rs. 850", 0.95, box(330, 215, 240, 60))])
    eng = QRShieldEngine(settings, ocr_provider=ocr)
    prep = eng.prepare_image(qr_png(ds.by_id()["PAY-S04"]["raw_payload"]), "sign.png")
    assert prep.ocr.status == "ok" and {c.attribute for c in prep.candidates} >= {"organization", "purpose", "amount"}
    decisions = {c.candidate_id: ContextDecision("use") for c in prep.candidates}
    res = eng.analyze_prepared(prep, 0, build_context(prep.candidates, decisions), AnalysisConfig()).to_dict()
    assert res["assessment"]["level"] == "needs_verification"
    f = next(x for x in res["context_findings"] if x["indicator_id"] == "CTX-002")
    assert f["provenance"] == "user_confirmed_ocr" and "SUNRISE HOTEL" in f["expected"]
    assert res["ocr"]["text_blocks"][0]["raw_text"] == "SUNRISE H0TEL" and res["ocr"]["text_blocks"][0]["normalized_text"] == "SUNRISE HOTEL"
    # nothing is used unless the user confirms it: with no decisions the mismatch cannot be found
    blind = eng.analyze_prepared(prep, 0, build_context(prep.candidates, {}), AnalysisConfig()).to_dict()
    assert blind["assessment"]["level"] == "no_material_concern" and blind["assessment"]["confidence"] == "low"
    assert any("CTX-012" == x["indicator_id"] for x in blind["context_findings"])


def test_ocr_failure_never_becomes_a_verdict(settings, ds):
    class Broken(StaticOCRProvider):
        def available(self): return False, "models missing"
    eng = QRShieldEngine(settings, ocr_provider=Broken([]))
    prep = eng.prepare_image(qr_png(ds.by_id()["PAY-S06"]["raw_payload"]), "x.png")
    res = eng.analyze_prepared(prep, 0, context_from_scenario({}), AnalysisConfig()).to_dict()
    assert prep.ocr.status == "unavailable" and res["ocr"]["status"] == "unavailable"
    assert res["assessment"]["level"] == "no_material_concern" and res["assessment"]["confidence"] == "low"
    assert any("OCR engine unavailable" in l for l in res["limitations"])


def test_result_schema_matches_specification(engine):
    res = engine.analyze_payload("upi://pay?pa=a@okicici&pn=ABC%20Trading&am=850", context_from_scenario({"organization": "Sunrise Hotel", "purpose": "Scan to pay"})).to_dict()
    for key in ("analysis_id", "timestamp", "manifest", "input", "qr", "payload", "ocr", "context", "payload_findings", "context_findings", "matching_findings",
                "action_findings", "threat_intel_findings", "evidence_groups", "assessment", "explanation", "recommendations"):
        assert key in res
    assert set(res["assessment"]) >= {"level", "confidence"} and res["payload"]["type"] == "payment"
    json.dumps(res)
    ex = res["explanation"]
    for k in ("what_was_found", "why_it_matters", "where_it_came_from", "what_matched", "what_did_not_match", "what_remains_uncertain", "what_to_verify", "interpretation"):
        assert k in ex
    assert "%" not in res["assessment"]["label"] and not isinstance(res["assessment"]["level"], (int, float))
    for e in res["payload_findings"] + res["context_findings"]:
        for k in ("indicator_id", "title", "category", "severity", "source", "observation", "expected", "confidence", "rationale",
                  "payload_field", "context_attribute", "related_action", "independent_group", "recommendation", "family"):
            assert k in e


def test_manifest_supports_reproducibility(engine):
    m = engine.analyze_payload("Table 12", None, AnalysisConfig()).to_dict()["manifest"]
    for k in ("qrshield_version", "analyzer_version", "rule_version", "reference_data_version", "ocr", "threat_intel", "environment", "analysis_config"):
        assert k in m
    assert m["environment"]["python"] and m["rule_version"] == engine.reg.version


def test_threat_intel_is_corroboration_and_local_analysis_survives_failure(engine):
    url, bank = "http://abcbank-verify.example/login?session=a1&token=b2", {"organization": "ABC Bank", "context_type": "bank", "purpose": "Login / Verify"}
    full = AnalysisConfig("full", threat_intel_mode="lookup", ti_override=True)

    def run(provider):
        return engine.analyze_payload(url, context_from_scenario(bank), full, ti_service=ThreatIntelService(provider, engine.policy)).to_dict()
    local = engine.analyze_payload(url, context_from_scenario(bank), AnalysisConfig("full")).to_dict()
    assert local["assessment"]["level"] == "high_concern"
    assert run(MockThreatIntelProvider(default={"malicious": 7, "harmless": 50})).get("assessment")["level"] == "harmful_corroborated"
    assert run(MockThreatIntelProvider(default={"malicious": 1, "harmless": 50}))["assessment"]["level"] == "high_concern"
    assert run(MockThreatIntelProvider(default=None))["assessment"]["level"] == "high_concern"
    unavailable = run(None)
    assert unavailable["assessment"]["level"] == "high_concern" and any("Threat intelligence unavailable" in l for l in unavailable["limitations"])


def test_external_and_local_evidence_are_kept_separate(engine):
    res = engine.analyze_payload("http://abcbank-verify.example/x", context_from_scenario({"organization": "ABC Bank"}),
                                 AnalysisConfig("full", threat_intel_mode="lookup", ti_override=True),
                                 ti_service=ThreatIntelService(MockThreatIntelProvider(default={"malicious": 7}), engine.policy)).to_dict()
    assert all(e["layer"] != "external" for e in res["payload_findings"] + res["context_findings"] + res["action_findings"])
    assert res["threat_intel_findings"] and all(e["layer"] == "external" and e["family"] == "EXTERNAL_CORROBORATION" for e in res["threat_intel_findings"])


@pytest.mark.parametrize("name", list(ABLATIONS))
def test_ablation_configs_use_only_their_layers(engine, ds, name):
    sc = ds.by_id()["PAY-S06"]
    res = engine.analyze_payload(sc["raw_payload"], context_from_scenario(sc["context"]), ABLATIONS[name]).to_dict()
    cfg = ABLATIONS[name]
    assert bool(res["payload_findings"]) is cfg.use_payload and bool(res["context_findings"]) is cfg.use_context and bool(res["action_findings"]) is cfg.use_action
    assert (res["context"] is not None) is cfg.use_context


def test_paper_core_claim_is_visible_in_ablation(engine, ds):
    """Refund-counter scam: payload-only sees an ordinary payment; context makes the inconsistency visible."""
    sc = ds.by_id()["PAY-S06"]
    lv = {n: engine.analyze_payload(sc["raw_payload"], context_from_scenario(sc["context"]), c).to_dict()["assessment"]["level"] for n, c in ABLATIONS.items()}
    order = ["no_material_concern", "needs_verification", "high_concern", "harmful_corroborated"]
    assert lv["payload_only"] == "no_material_concern"
    assert order.index(lv["payload_context"]) > order.index(lv["payload_only"])
    assert order.index(lv["payload_context_action"]) >= order.index(lv["payload_context"]) and lv["full"] != "harmful_corroborated"
    assert lv["context_only"] != "no_material_concern"


def test_analysis_is_deterministic(engine, ds):
    sc = ds.by_id()["URL-S05"]
    a = engine.analyze_payload(sc["raw_payload"], context_from_scenario(sc["context"]), AnalysisConfig(), analysis_id="x").to_dict()
    b = engine.analyze_payload(sc["raw_payload"], context_from_scenario(sc["context"]), AnalysisConfig(), analysis_id="x").to_dict()
    for k in ("assessment", "payload_findings", "context_findings", "evidence_groups", "recommendations", "explanation"):
        assert a[k] == b[k]
