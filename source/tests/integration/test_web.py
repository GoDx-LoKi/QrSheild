"""Web layer: FastAPI + Jinja2 + HTMX flows (OCR is a clearly-labelled test double; real PaddleOCR is not required)."""
import io
import re

import pytest
import qrcode
from fastapi.testclient import TestClient
from PIL import Image

from app.main import create_app
from app.state import AppState
from qrshield_core.ocr.engine import StaticOCRProvider
from qrshield_core.pipeline import QRShieldEngine

BOX = lambda x, y, w, h: [[x, y], [x + w, y], [x + w, y + h], [x, y + h]]


def make_qr_png(payload: str = "upi://pay?pa=abctrading@okicici&pn=ABC%20Trading&am=850") -> bytes:
    q = qrcode.QRCode(box_size=6, border=4)
    q.add_data(payload)
    q.make(fit=True)
    img = q.make_image().convert("RGB")
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


@pytest.fixture()
def client(settings, tmp_path):
    s = type(settings)(**{**settings.__dict__, "artifacts_dir": tmp_path})
    ocr = StaticOCRProvider([
        ("SUNRISE H0TEL", 0.93, BOX(80, 40, 700, 90)),
        ("SCAN TO PAY", 0.97, BOX(250, 150, 400, 50)),
        ("Rs. 850", 0.95, BOX(330, 215, 240, 60)),
    ])
    return TestClient(create_app(AppState(s, QRShieldEngine(s, ocr_provider=ocr))))


def prepare(client, payload: str = "upi://pay?pa=abctrading@okicici&pn=ABC%20Trading&am=850"):
    r = client.post("/analyze/prepare", files={"image": ("sign.png", make_qr_png(payload), "image/png")})
    assert r.status_code == 200
    return r, re.search(r'name="analysis_id" value="([a-f0-9]{32})"', r.text).group(1)


@pytest.mark.parametrize("path", [
    "/",
    "/research",
    "/settings",
    "/health",
    "/api/v1/rules",
    "/static/css/app.css",
    "/static/js/htmx.min.js",
    "/static/js/app.js",
])
def test_pages_load(client, path):
    assert client.get(path).status_code == 200


def test_primary_navigation_links_are_present_and_target_their_pages(client):
    for path in ("/", "/research", "/settings"):
        response = client.get(path)
        assert response.status_code == 200
        assert 'href="/research"' in response.text
        assert 'href="/settings"' in response.text
        assert f'<a href="{path}" aria-current="page">' in response.text


def test_old_evaluation_lab_and_dataset_removed(client):
    assert client.get("/evaluation").status_code == 404
    assert client.get("/dataset").status_code == 404


def test_security_headers_and_no_inline_code(client):
    for path in ("/", "/research", "/settings"):
        r = client.get(path)
        csp = r.headers["content-security-policy"]
        assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp and "frame-ancestors 'none'" in csp
        assert r.headers["x-content-type-options"] == "nosniff" and r.headers["referrer-policy"] == "no-referrer" and r.headers["cache-control"] == "no-store"
        assert " style=" not in r.text and "onclick=" not in r.text and not re.search(r"<script(?![^>]*\bsrc=)", r.text)
        assert "http://" not in r.text.replace("http://www.w3.org", "") and "cdn." not in r.text


def test_upload_review_analyze_export_flow(client):
    r, aid = prepare(client)
    assert "QR #1" in r.text and "upi://pay?pa=abctrading@okicici" in r.text
    assert 'value="ignore" checked' in r.text
    assert "OCR read:" in r.text and "confidence: high" in r.text
    form = {"analysis_id": aid, "qr_index": "0", "cand_c1": "use", "cand_c2": "use", "cand_c3": "use"}
    r = client.post("/analyze/run", data=form)
    assert r.status_code == 200 and "Needs verification" in r.text and "CTX-002" in r.text and "user_confirmed_ocr" in r.text
    assert "not a probability" in r.text and "Possible legitimate explanations" in r.text and "External threat intelligence" in r.text
    rid = re.search(r'id="r-([a-f0-9]{32})"', r.text).group(1)
    j = client.get(f"/results/{rid}.json")
    assert j.status_code == 200 and j.json()["assessment"]["level"] == "needs_verification" and "attachment" in j.headers["content-disposition"]
    csv = client.get(f"/results/{rid}.csv")
    assert csv.status_code == 200 and csv.text.startswith("analysis_id,layer,family,indicator_id") and "CTX-002" in csv.text
    assert client.get(f"/results/{rid}").status_code == 200 and client.get(f"/image/{aid}").headers["content-type"] == "image/png"


def test_no_numeric_risk_score_is_ever_displayed(client):
    _, aid = prepare(client)
    html = client.post("/analyze/run", data={"analysis_id": aid, "qr_index": "0", "organization": "Sunrise Hotel", "purpose": "Scan to pay"}).text
    assert not re.search(r"\b\d{1,3}\s?%|\b\d(\.\d+)?\s?/\s?10\b|risk score|probability of", html.replace("not a probability", ""), re.I)


def test_qr_selection_is_required_when_multiple(client):
    canvas = Image.new("RGB", (900, 400), "white")
    for text, x in (("WIFI:T:WPA;S:Cafe;P:hunter2;;", 20), ("upi://pay?pa=a@b&pn=X", 460)):
        q = qrcode.QRCode(box_size=6, border=4)
        q.add_data(text)
        q.make(fit=True)
        canvas.paste(q.make_image().convert("RGB"), (x, 40))
    buf = io.BytesIO()
    canvas.save(buf, "PNG")
    r = client.post("/analyze/prepare", files={"image": ("m.png", buf.getvalue(), "image/png")})
    aid = re.search(r'name="analysis_id" value="([a-f0-9]{32})"', r.text).group(1)
    assert "QR #2" in r.text and "will not choose one silently" in r.text and "hunter2" not in r.text
    assert client.post("/analyze/run", data={"analysis_id": aid}).status_code == 400
    both = client.post("/analyze/run", data={"analysis_id": aid, "qr_index": "all"})
    assert both.status_code == 200 and both.text.count('class="result"') == 2


def test_error_handling_never_becomes_a_verdict(client):
    assert client.post("/analyze/prepare", files={"image": ("x.png", b"not an image", "image/png")}).status_code == 400
    assert client.post("/analyze/run", data={"analysis_id": "0" * 32, "qr_index": "0"}).status_code == 410
    buf = io.BytesIO()
    Image.new("RGB", (200, 200), "white").save(buf, "PNG")
    r = client.post("/analyze/prepare", files={"image": ("blank.png", buf.getvalue(), "image/png")})
    assert "No QR code detected" in r.text and "not a security verdict" in r.text


def test_oversized_upload_is_rejected(settings, tmp_path):
    s = type(settings)(**{**settings.__dict__, "artifacts_dir": tmp_path, "max_image_size_mb": 1})
    c = TestClient(create_app(AppState(s, QRShieldEngine(s, use_default_ocr=False))))
    r = c.post("/analyze/prepare", files={"image": ("big.png", b"\x89PNG" + b"0" * (1024 * 1024 + 10), "image/png")})
    assert r.status_code == 400 and "limit" in r.text


def test_fresh_scan_requires_explicit_confirmation(client):
    assert client.post("/results/" + "a" * 32 + "/scan", data={}).status_code == 400


def test_json_api(client):
    r = client.post("/api/v1/analyze-payload", json={
        "payload": "upi://pay?pa=a@okicici&pn=ABC%20Trading&am=850",
        "context": {"organization": "Sunrise Hotel", "purpose": "Scan to pay"}
    })
    assert r.status_code == 200 and r.json()["assessment"]["level"] == "needs_verification" and r.json()["context"]["attributes"][0]["source"] == "user_input"
    assert client.post("/api/v1/analyze-payload", json={"payload": "x" * 5000}).status_code == 422
    assert client.post("/api/v1/analyze-payload", json={"payload": "Table 12", "ablation": "bogus"}).status_code == 422
    img = client.post("/api/v1/analyze", files={"image": ("s.png", make_qr_png("upi://pay?pa=a@okicici&pn=ABC&am=100"), "image/png")}, data={"organization": "Sunrise Hotel", "purpose": "Scan to pay"})
    assert img.status_code == 200
    assert client.post("/api/v1/analyze", files={"image": ("x.png", b"junk", "image/png")}).status_code == 400
    rules = client.get("/api/v1/rules").json()
    assert rules["rules"] and all(k in rules["rules"][0] for k in ("id", "rationale", "severity", "family"))


def test_research_tests_ui_and_routes(client, tmp_path, monkeypatch):
    # Case 1: without dataset
    non_existent = tmp_path / "does_not_exist"
    import app.routes.research as rr
    monkeypatch.setattr(rr, "discover_dataset_root", lambda: non_existent)
    r = client.get("/research")
    assert r.status_code == 200
    assert "Research Tests" in r.text
    assert "qrs_bench_ind" in r.text
    assert "Previous runs" in r.text

    # Validation route
    v = client.post("/research/validate")
    assert v.status_code == 200
    assert "Research dataset" in v.text

    # Run without dataset returns graceful error partial
    run_err = client.post("/research/run", data={"suite": "base"})
    assert run_err.status_code == 200
    assert "not found" in run_err.text.lower() or "dataset" in run_err.text.lower()

    # Invalid suite
    invalid = client.post("/research/run", data={"suite": "nonexistent"})
    assert invalid.status_code == 200
    assert "Invalid suite" in invalid.text

    # Case 2: with mock dataset detected
    from tests.evaluation.test_research_dataset import _create_mock_dataset
    mock_ds = _create_mock_dataset(tmp_path / "qrs_bench_ind")
    import app.routes.research as rr
    monkeypatch.setattr(rr, "discover_dataset_root", lambda: mock_ds)
    r2 = client.get("/research")
    assert r2.status_code == 200
    assert "Test type" in r2.text
    assert "Base" in r2.text
    assert "Counterfactual" in r2.text
    assert "Robustness" in r2.text


def test_settings_page_never_shows_secrets(settings, tmp_path):
    s = type(settings)(**{**settings.__dict__, "artifacts_dir": tmp_path, "virustotal_api_key": "SUPERSECRETKEY1234567890"})
    c = TestClient(create_app(AppState(s, QRShieldEngine(s, use_default_ocr=False))))
    t = c.get("/settings").text
    assert "SUPERSECRETKEY" not in t and "Configured" in t
    assert "SUPERSECRETKEY" not in c.get("/api/v1/rules").text


@pytest.mark.parametrize(("provider_name", "display_name"), [("tesseract", "Tesseract"), ("paddleocr", "PaddleOCR")])
def test_ocr_status_reports_the_selected_provider(client, provider_name, display_name):
    class UnavailableProvider:
        name = provider_name

        def available(self):
            return False, "backend not installed"

    client.app.state.qs.engine.ocr_provider = UnavailableProvider()
    response = client.post("/settings/check-ocr")
    assert response.status_code == 200
    assert f"{display_name} is unavailable: backend not installed" in response.text


def test_ui_ux_components_and_partial_csp_compliance(client):
    """Verify upgraded UI/UX components, accessibility attributes, and zero inline styles across pages and HTMX partials."""
    home = client.get("/")
    assert home.status_code == 200
    assert 'class="workflow-steps' in home.text
    assert 'class="dropzone"' in home.text
    assert 'data-action="toggle-theme"' in home.text
    assert 'aria-label="Primary"' in home.text

    prep_resp, aid = prepare(client)
    assert 'data-action="copy-payload"' in prep_resp.text
    assert 'data-action="use-confident"' in prep_resp.text
    assert 'data-action="reset-ignore"' in prep_resp.text
    assert " style=" not in prep_resp.text and "onclick=" not in prep_resp.text

    run_resp = client.post("/analyze/run", data={"analysis_id": aid, "qr_index": "0", "cand_c1": "use", "cand_c2": "use", "cand_c3": "use"})
    assert run_resp.status_code == 200
    assert 'data-filter-sev="strong"' in run_resp.text
    assert 'data-evidence-search' in run_resp.text
    assert 'data-action="print-report"' in run_resp.text
    assert " style=" not in run_resp.text and "onclick=" not in run_resp.text
