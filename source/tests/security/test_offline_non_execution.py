"""Security tests verifying the strict offline non-execution invariant (AC-4, F-09)."""
from __future__ import annotations

import ast
import socket
from pathlib import Path
from typing import Any

import httpx
import pytest

from qrshield_core.config import Settings
from qrshield_core.models import Confidence, Context, ContextAttribute
from qrshield_core.pipeline.engine import AnalysisConfig, QRShieldEngine
from qrshield_core.threat_intel.virustotal import VirusTotalProvider


def _make_ctx() -> Context:
    return Context(
        attributes=[
            ContextAttribute("organization", "State Bank of India", "user_input", Confidence.HIGH),
            ContextAttribute("domain", "sbi.co.in", "user_input", Confidence.HIGH),
        ]
    )


def test_threat_intel_offline_does_not_instantiate_httpx_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """When threat_intel_mode='off' or threat_intel_enabled=False, httpx.Client must never be instantiated."""
    client_instantiated = False

    class ForbiddenClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            nonlocal client_instantiated
            client_instantiated = True
            raise AssertionError("httpx.Client should never be instantiated in offline mode!")

    monkeypatch.setattr(httpx, "Client", ForbiddenClient)

    # Even if VirusTotalProvider is constructed with an API key, constructing it must NOT instantiate httpx.Client
    vt = VirusTotalProvider("dummy-key-never-used")
    assert vt._client is None
    assert client_instantiated is False

    settings_offline = Settings(
        threat_intel_enabled=False,
        load_synthetic_reference=False,
        ocr_enabled=False,
    )
    engine = QRShieldEngine(settings_offline, use_default_ocr=False)
    assert engine.ti_provider is None
    res = engine.analyze_payload(
        "https://secure-login-update-account.com/verify",
        _make_ctx(),
        AnalysisConfig(threat_intel_mode="off"),
    )
    assert res.level in ("no_material_concern", "needs_verification", "high_concern", "confirmed_malicious_evidence")
    assert client_instantiated is False


def test_offline_pipeline_never_calls_socket_connect_or_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify full pipeline execution across all 8 payload families never touches network sockets or DNS."""
    def forbidden_socket(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Network socket creation attempted during offline QRShield analysis!")

    def forbidden_getaddrinfo(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("DNS resolution (getaddrinfo) attempted during offline QRShield analysis!")

    monkeypatch.setattr(socket, "socket", forbidden_socket)
    monkeypatch.setattr(socket, "create_connection", forbidden_socket)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden_getaddrinfo)

    settings = Settings(
        threat_intel_enabled=False,
        load_synthetic_reference=False,
        ocr_enabled=False,
    )
    engine = QRShieldEngine(settings, use_default_ocr=False)
    cfg = AnalysisConfig(threat_intel_mode="off")
    ctx = _make_ctx()

    sample_payloads = [
        "https://sbi.co.in/login",
        "upi://pay?pa=merchant@okaxis&pn=Merchant&am=250.00&cu=INR",
        "WIFI:T:WPA;S:CorpNet;P:Secret123;;",
        "BEGIN:VCARD\nVERSION:3.0\nFN:Alice Smith\nTEL:+919876543210\nEMAIL:alice@example.org\nEND:VCARD",
        "MATMSG:TO:support@bank.com;SUB:Urgent PIN verify;BODY:Send 6 digit OTP;;",
        "SMSTO:+919876543210:SIM SWAP 123456",
        "tel:*21*9876543210#",
        "myapp://wallet/transfer?amount=5000&to=0xdeadbeef",
        "Plain text membership card ID 998877",
    ]
    for payload in sample_payloads:
        result = engine.analyze_payload(payload, ctx, cfg)
        assert result.level is not None


def test_static_ast_no_subprocess_or_os_system_in_qrshield_core() -> None:
    """Verify via AST inspection that qrshield_core contains no os.system, subprocess.Popen/run/call, or webbrowser calls."""
    core_dir = Path(__file__).resolve().parents[2] / "qrshield_core"
    forbidden_modules = {"subprocess", "webbrowser"}
    forbidden_os_calls = {
        "system", "popen", "spawnl", "spawnle", "spawnlp", "spawnlpe",
        "spawnv", "spawnve", "spawnvp", "spawnvpe", "execl", "execle",
        "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
    }

    violations: list[str] = []
    for py_file in sorted(core_dir.rglob("*.py")):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in forbidden_modules:
                        violations.append(f"{py_file.name}:{node.lineno} imports {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in forbidden_modules:
                    violations.append(f"{py_file.name}:{node.lineno} imports from {node.module}")
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    if node.func.value.id == "os" and node.func.attr in forbidden_os_calls:
                        violations.append(f"{py_file.name}:{node.lineno} calls os.{node.func.attr}")
                elif isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                    violations.append(f"{py_file.name}:{node.lineno} calls {node.func.id}()")

    assert violations == [], f"Forbidden execution primitives found in qrshield_core: {violations}"
