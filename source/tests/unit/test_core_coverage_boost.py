"""Comprehensive unit tests covering edge cases across qrshield_core modules."""
from __future__ import annotations

import types
import numpy as np
import pytest

from qrshield_core.analyzers.common import Deps
from qrshield_core.analyzers.deeplink import analyze_deeplink
from qrshield_core.analyzers.messaging import analyze_email, analyze_sms
from qrshield_core.config import Settings, _bool, _int, _load_dotenv
from qrshield_core.context.extract import (
    _join_wrapped_pieces,
    extract_candidates,
    is_explicit_label_or_watermark,
)
from qrshield_core.decoder.qr import DecodeResult, DetectedQR, _collect, _zxing, detect_and_decode
from qrshield_core.matching.entity import Matcher
from qrshield_core.models import Confidence, Payload, PayloadType
from qrshield_core.normalizer.common import _is_obfuscated_ip, _script_of, parse_url
from qrshield_core.ocr.engine import (
    OCRBlock,
    PaddleOCRProvider,
    TesseractOCRProvider,
    parse_paddle_result,
)
from qrshield_core.reporting.export import finding_rows, findings_csv, to_json_bytes
from qrshield_core.rules import ReferenceData, RuleRegistry


def _make_deps() -> Deps:
    s = Settings.from_env()
    reg = RuleRegistry(s.rules_dir)
    ref = ReferenceData.load(s.rules_dir, include_synthetic=True)
    return Deps(reg=reg, ref=ref, matcher=Matcher(ref))


def test_reporting_export_functions():
    sample = {
        "analysis_id": "test1234",
        "payload_findings": [
            {
                "layer": "payload",
                "family": "url",
                "indicator_id": "URL-001",
                "severity": "meaningful",
                "confidence": "high",
                "source": "qr_payload",
                "mismatch_type": None,
                "title": "Test title",
                "observation": "Test obs",
                "expected": None,
                "payload_field": "host",
                "context_attribute": None,
                "provenance": "rule",
                "independent_group": "g1",
            }
        ],
        "context_findings": [],
        "action_findings": [],
        "threat_intel_findings": [],
    }
    jb = to_json_bytes(sample)
    assert b"test1234" in jb
    rows = finding_rows(sample)
    assert len(rows) == 1
    assert rows[0]["indicator_id"] == "URL-001"
    csv_bytes = findings_csv(sample)
    assert b"URL-001" in csv_bytes


def test_config_dotenv_and_helpers(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("# comment\n\nINVALID_LINE\nTEST_DOTENV_KEY='hello_val'\n", encoding="utf-8")
    monkeypatch.delenv("TEST_DOTENV_KEY", raising=False)
    _load_dotenv(env_file)
    assert _bool("TEST_DOTENV_KEY", True) is False
    monkeypatch.setenv("TEST_INT_BAD", "not_an_int")
    assert _int("TEST_INT_BAD", 42) == 42


def test_deeplink_and_messaging_edge_cases():
    deps = _make_deps()
    bad_dl = Payload(
        raw="bad://",
        raw_redacted="bad://",
        type=PayloadType.DEEP_LINK,
        parse_ok=False,
        notes=["malformed deep link"],
    )
    res_bad_dl = analyze_deeplink(bad_dl, deps)
    assert any(e.indicator_id == "TXT-006" for e in res_bad_dl)

    custody_dl = Payload(
        raw="wallet://approve",
        raw_redacted="wallet://approve",
        type=PayloadType.DEEP_LINK,
        parse_ok=True,
        normalized_fields={
            "scheme": "wallet",
            "known_scheme": False,
            "operation": "authentication",
            "operations": ["authentication"],
            "param_names": ["grant_custody", "token", "secret", "p4", "p5", "p6", "p7", "p8", "p9"],
            "param_count": 9,
            "fallback_url": "https://example.com/fb",
            "embedded_urls": ["https://example.com/cb"],
        },
    )
    res_cust = analyze_deeplink(custody_dl, deps)
    ids = {e.indicator_id for e in res_cust}
    assert {"DL-001", "DL-002", "DL-003", "DL-004", "DL-005"} <= ids

    bad_sms = Payload(raw="smsto:", raw_redacted="smsto:", type=PayloadType.SMS, parse_ok=False, notes=[])
    assert analyze_sms(bad_sms, deps)[0].indicator_id == "TXT-006"

    rich_sms = Payload(
        raw="smsto:12345:hi",
        raw_redacted="smsto:12345:hi",
        type=PayloadType.SMS,
        parse_ok=True,
        normalized_fields={
            "recipients": ["12345", "bad_num"],
            "recipients_valid": [True, False],
            "body_present": True,
            "body": "Visit http://198.51.100.1/login\u200b",
            "body_has_hidden_chars": True,
            "body_urls": [parse_url("http://198.51.100.1/login")],
        },
    )
    sms_ids = {e.indicator_id for e in analyze_sms(rich_sms, deps)}
    assert {"SMS-001", "SMS-002", "SMS-003", "TXT-001"} <= sms_ids

    bad_eml = Payload(raw="mailto:", raw_redacted="mailto:", type=PayloadType.EMAIL, parse_ok=False, notes=[])
    assert analyze_email(bad_eml, deps)[0].indicator_id == "TXT-006"

    rich_eml = Payload(
        raw="mailto:a@b",
        raw_redacted="mailto:a@b",
        type=PayloadType.EMAIL,
        parse_ok=True,
        normalized_fields={
            "to": ["user@gmail.com"],
            "cc": [],
            "bcc": ["audit@paypa1.com"],
            "recipients_valid": [True, False],
            "recipient_domains": ["gmail.com", "paypa1.com"],
            "subject": "Urgent",
            "body": "Check http://198.51.100.1/verify",
            "body_has_hidden_chars": True,
            "body_urls": [parse_url("http://198.51.100.1/verify")],
        },
    )
    eml_ids = {e.indicator_id for e in analyze_email(rich_eml, deps)}
    assert {"EML-001", "EML-002", "EML-003", "EML-004", "TXT-001"} <= eml_ids


def test_normalizer_common_edge_cases():
    assert _script_of("1") is None
    assert _script_of("A") == "LATIN"
    assert _is_obfuscated_ip("127.0.0.1") is False
    assert _is_obfuscated_ip("0x7f.0.0.1") is True
    assert _is_obfuscated_ip("example.com") is False
    assert _is_obfuscated_ip("0x99999999999999") is False

    u1 = parse_url("https://example.com/app#redirect=//evil.example/phish&foo=bar")
    assert u1["fragment_redirect"] is True
    assert "https://evil.example/phish" in u1["embedded_urls"]

    u2 = parse_url("https://example.com/app#click_here_https://evil.example/landing")
    assert u2["fragment_redirect"] is True
    assert "https://evil.example/landing" in u2["embedded_urls"]

    u3 = parse_url("https://example.com/path?long=" + ("a" * 250))
    assert u3["long_param_values"] == 1

    u_bad_port = parse_url("http://example.com:99999/test")
    assert u_bad_port["parse_ok"] is False


def test_ocr_parsers_and_providers(monkeypatch):
    assert parse_paddle_result(None) == []
    res_3x = [
        None,
        {"rec_texts": None},
        {
            "rec_texts": ["  ", "Sunrise Hotel"],
            "rec_scores": [0.5, 0.96],
            "dt_polys": [np.zeros((4, 2)), np.array([[0, 0], [10, 0], [10, 10], [0, 10]])],
        },
    ]
    parsed_3x = parse_paddle_result(res_3x)
    assert len(parsed_3x) == 1 and parsed_3x[0][0] == "Sunrise Hotel"

    res_2x = [[
        ["malformed_entry"],
        [[[0, 0], [10, 0], [10, 10], [0, 10]], ("Scan to pay", 0.91)],
    ]]
    parsed_2x = parse_paddle_result(res_2x)
    assert len(parsed_2x) == 1 and parsed_2x[0][0] == "Scan to pay"

    p_prov = PaddleOCRProvider()
    fake_paddle = types.SimpleNamespace(
        __version__="3.0.0",
        PaddleOCR=lambda **kw: types.SimpleNamespace(
            predict=lambda bgr: [{"rec_texts": ["Hello"], "rec_scores": [0.95], "rec_polys": [np.zeros((4, 2))]}]
        ),
    )
    __import__("sys").modules["paddleocr"] = fake_paddle
    ok, err = p_prov.available()
    assert ok is True and err == ""
    out = p_prov.recognize(np.zeros((32, 32, 3), dtype=np.uint8))
    assert len(out) == 1 and out[0][0] == "Hello"

    t_prov = TesseractOCRProvider()
    fake_pyt = types.SimpleNamespace(
        Output=types.SimpleNamespace(DICT="dict"),
        get_tesseract_version=lambda: "5.3.0",
        image_to_data=lambda img, lang, config, output_type: {
            "text": ["", "Merchant", "BadConf"],
            "conf": ["-1", "92.0", "invalid"],
            "block_num": [1, 1, 1],
            "par_num": [1, 1, 1],
            "line_num": [1, 1, 2],
            "left": [0, 10, 10],
            "top": [0, 20, 40],
            "width": [0, 80, 50],
            "height": [0, 20, 20],
        },
    )
    __import__("sys").modules["pytesseract"] = fake_pyt
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/tesseract")
    tok, terr = t_prov.available()
    assert tok is True and terr == ""
    tout = t_prov.recognize(np.zeros((64, 64, 3), dtype=np.uint8))
    assert len(tout) >= 1 and tout[0][0] == "Merchant"


def test_decoder_edge_cases():
    dr = DecodeResult(codes=[
        DetectedQR(0, True, "https://a.example", [[0, 0], [1, 0], [1, 1], [0, 1]], "opencv", "original"),
        DetectedQR(1, False, None, [[0, 0], [1, 0], [1, 1], [0, 1]], "opencv", "original"),
    ])
    assert dr.count == 2
    assert len(dr.decoded_codes) == 1
    assert _collect(False, None, None) == []
    assert _zxing(np.zeros((32, 32, 3), dtype=np.uint8)) == []

    res_budget = detect_and_decode(np.zeros((64, 64, 3), dtype=np.uint8), time_budget_s=-1.0)
    assert "time budget exhausted" in res_budget.attempts


def test_context_extract_edge_cases():
    assert is_explicit_label_or_watermark("") is False
    assert is_explicit_label_or_watermark("SYNTHETIC TEST SCENARIO") is True
    assert is_explicit_label_or_watermark("Official Domain: example.com") is True
    assert _join_wrapped_pieces([], "email") == ""
    assert _join_wrapped_pieces(["Hello", "World"], "purpose") == "Hello World"
    assert _join_wrapped_pieces(["support@alderwood", "org"], "email") == "support@alderwood.org"

    s = Settings.from_env()
    ref = ReferenceData.load(s.rules_dir, include_synthetic=True)
    box1 = [[10, 10], [200, 10], [200, 30], [10, 30]]
    box2 = [[10, 35], [200, 35], [200, 55], [10, 55]]
    box3 = [[10, 80], [200, 80], [200, 100], [10, 100]]
    blocks = [
        OCRBlock("b0", "SYNTHETIC TEST SCENARIO", "SYNTHETIC TEST SCENARIO", 0.99, Confidence.HIGH, box1),
        OCRBlock("b1", "Contact Email:", "Contact Email:", 0.45, Confidence.LOW, box1),
        OCRBlock("b2", "help@alderwoodcafe.org", "help@alderwoodcafe.org", 0.95, Confidence.HIGH, box2),
        OCRBlock("b3", "Operated by Alderwood Holdings", "Operated by Alderwood Holdings", 0.92, Confidence.HIGH, box3),
    ]
    cands = extract_candidates(blocks, ref)
    attrs = {c.attribute: c.value for c in cands}
    assert attrs.get("email") == "help@alderwoodcafe.org"
    assert "organization" in attrs
