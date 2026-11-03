"""Unit tests for the research image runner and failure isolation."""
from __future__ import annotations

import io
from pathlib import Path

import pytest
import qrcode
from evaluation.failures import FailureCode, is_evaluable
from evaluation.image_runner import RESEARCH_CONFIG, ItemResult, preflight_ocr, run_image
from PIL import Image
from qrshield_core.config import Settings
from qrshield_core.ocr.engine import StaticOCRProvider
from qrshield_core.pipeline import QRShieldEngine

BOX = lambda x, y, w, h: [[x, y], [x + w, y], [x + w, y + h], [x, y + h]]


def _create_qr_image(payload: str) -> bytes:
    q = qrcode.QRCode(box_size=6, border=4)
    q.add_data(payload)
    q.make(fit=True)
    img = q.make_image().convert("RGB")
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def _create_multi_qr_image(p1: str, p2: str) -> bytes:
    canvas = Image.new("RGB", (800, 400), "white")
    for text, x in ((p1, 20), (p2, 420)):
        q = qrcode.QRCode(box_size=6, border=4)
        q.add_data(text)
        q.make(fit=True)
        canvas.paste(q.make_image().convert("RGB"), (x, 20))
    buf = io.BytesIO()
    canvas.save(buf, "PNG")
    return buf.getvalue()


@pytest.fixture
def mock_engine(tmp_path):
    s = Settings.from_env()
    s.load_synthetic_reference = True
    s.artifacts_dir = tmp_path
    ocr = StaticOCRProvider([
        ("Sunrise Hotel", 0.95, BOX(10, 10, 200, 40)),
        ("Scan to pay", 0.92, BOX(10, 60, 200, 40)),
    ])
    return QRShieldEngine(s, ocr_provider=ocr)


def test_research_config_invariants():
    assert RESEARCH_CONFIG.threat_intel_mode == "off"
    assert RESEARCH_CONFIG.use_payload is True
    assert RESEARCH_CONFIG.use_context is True
    assert RESEARCH_CONFIG.use_action is True
    assert RESEARCH_CONFIG.ti_override is False


def test_preflight_ocr(mock_engine):
    ok, why = preflight_ocr(mock_engine)
    assert ok is True

    # When OCR provider is None
    engine_no_ocr = QRShieldEngine(mock_engine.settings, use_default_ocr=False)
    engine_no_ocr.ocr_provider = None
    ok, why = preflight_ocr(engine_no_ocr)
    assert ok is False
    assert "OCR is disabled" in why


def test_run_image_missing_file(mock_engine, tmp_path):
    missing_path = tmp_path / "does_not_exist.png"
    res = run_image(mock_engine, "item_01", "base", missing_path)
    assert res.failure_code == FailureCode.IMAGE_LOAD_ERROR
    assert not res.evaluable


def test_run_image_no_qr(mock_engine, tmp_path):
    blank = tmp_path / "blank.png"
    Image.new("RGB", (200, 200), "white").save(blank, "PNG")
    res = run_image(mock_engine, "item_blank", "base", blank)
    assert res.failure_code == FailureCode.QR_DETECT_ERROR
    assert not res.evaluable
    assert res.qr_detected is False


def test_run_image_multiple_qr_ambiguous(mock_engine, tmp_path):
    multi_path = tmp_path / "multi.png"
    multi_path.write_bytes(_create_multi_qr_image("https://example.com/a", "https://example.com/b"))
    res = run_image(mock_engine, "item_multi", "base", multi_path)
    assert res.failure_code == FailureCode.MULTIPLE_QR_AMBIGUOUS
    assert not res.evaluable
    assert res.qr_count == 2


def test_run_image_valid_single_qr(mock_engine, tmp_path):
    qr_path = tmp_path / "valid.png"
    qr_path.write_bytes(_create_qr_image("https://example.com/login"))
    res = run_image(mock_engine, "item_valid", "base", qr_path)
    assert res.failure_code == FailureCode.SUCCESS
    assert res.evaluable
    assert res.qr_detected is True
    assert res.qr_count == 1
    assert res.qr_decode_success is True
    assert res.raw_result is not None
    assert res.payload_type == "url"
    assert res.assessment_level is not None
    # OCR candidates were auto-accepted
    assert res.context_accepted_count is not None
    assert res.context_accepted_count >= 1
