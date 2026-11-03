"""Regression tests for filesystem containment, remote authentication and API input bounds."""
from __future__ import annotations

import io
import json
from pathlib import Path

import qrcode
from fastapi.testclient import TestClient
from PIL import Image

from app.main import create_app
from app.state import AppState
from evaluation.dataset_loader import BENCHMARK_CATEGORIES, discover_dataset_root, load_research_dataset
from evaluation.validator import validate_dataset
from qrshield_core.pipeline import QRShieldEngine


def _qr_bytes(payload: str = "https://example.com/login") -> bytes:
    qr = qrcode.QRCode(box_size=6, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    buf = io.BytesIO()
    qr.make_image().convert("RGB").save(buf, format="PNG")
    return buf.getvalue()


def _test_client(settings, tmp_path, *, host: str = "127.0.0.1", allowed_hosts=None, access_token="", env="test"):
    overrides = {**settings.__dict__, "artifacts_dir": tmp_path / "artifacts", "env": env,
                 "access_token": access_token}
    if allowed_hosts is not None:
        overrides["allowed_hosts"] = allowed_hosts
    custom = type(settings)(**overrides)
    return TestClient(create_app(AppState(custom, QRShieldEngine(custom, use_default_ocr=False))), base_url=f"http://{host}")


def test_dataset_manifest_cannot_escape_via_parent_traversal(tmp_path):
    from evaluation.dataset_loader import _resolve_image
    root = tmp_path / "dataset"
    (root / "base").mkdir(parents=True)
    outside = tmp_path / "outside.png"
    outside.write_bytes(b"not an image")
    try:
        _resolve_image("../outside.png", root / "base", root)
    except ValueError as exc:
        assert "traversal" in str(exc).lower()
    else:
        raise AssertionError("Parent traversal was accepted")


def test_dataset_manifest_cannot_follow_image_symlink_outside_root(tmp_path):
    root = tmp_path / "dataset"
    base = root / "base"
    base.mkdir(parents=True)
    outside = tmp_path / "outside.png"
    outside.write_bytes(b"not an image")
    (base / "escape.png").symlink_to(outside)
    (base / "manifest.json").write_text(json.dumps([{
        "id": "BASE_001", "image": "escape.png", "payload_type": "url"
    }]), encoding="utf-8")
    try:
        load_research_dataset(root)
    except ValueError as exc:
        assert "escapes the dataset root" in str(exc).lower()
    else:
        raise AssertionError("Symlink outside the dataset root was accepted")


def test_validator_enforces_exact_research_benchmark_counts(settings):
    root = discover_dataset_root()
    validation = validate_dataset(load_research_dataset(root))
    assert validation.ok, validation.errors
    assert validation.counts == {
        "base": 640,
        "counterfactual_images": 400,
        "counterfactual_pairs": 160,
        "counterfactual_negative_control_pairs": 40,
        "counterfactual_total_pairs": 200,
        "robustness": 240,
        "total": 1280,
    }
    assert all(validation.per_payload.get(kind) == 80 for kind in BENCHMARK_CATEGORIES)
    assert len(validation.image_inventory_hash) == 64


def test_json_api_rejects_negative_and_out_of_range_qr_indices(settings, tmp_path):
    client = _test_client(settings, tmp_path)
    image = _qr_bytes()
    for index in (-1, 1):
        response = client.post(
            "/api/v1/analyze",
            files={"image": ("one.png", image, "image/png")},
            data={"qr_index": str(index)},
        )
        assert response.status_code == 422
        assert response.json()["error"] == "select_qr"


def test_json_api_requires_explicit_qr_choice_for_multiple_codes(settings, tmp_path):
    canvas = Image.new("RGB", (800, 400), "white")
    for payload, x in (("https://one.example/", 20), ("https://two.example/", 420)):
        qr = qrcode.QRCode(box_size=6, border=4)
        qr.add_data(payload)
        qr.make(fit=True)
        canvas.paste(qr.make_image().convert("RGB"), (x, 20))
    buf = io.BytesIO()
    canvas.save(buf, "PNG")

    client = _test_client(settings, tmp_path)
    response = client.post("/api/v1/analyze", files={"image": ("two.png", buf.getvalue(), "image/png")})
    assert response.status_code == 422
    assert response.json()["error"] == "select_qr"


def test_remote_hosts_fail_closed_without_a_strong_access_token(settings, tmp_path):
    client = _test_client(settings, tmp_path, host="qrshield.example", allowed_hosts=["qrshield.example"],
                          access_token="", env="development")
    assert client.get("/health").status_code == 200
    response = client.get("/")
    assert response.status_code == 503
    assert response.json()["error"] == "remote_access_not_configured"


def test_remote_hosts_require_token_and_accept_bearer_or_basic(settings, tmp_path):
    token = "qrshield-test-access-token-32-characters-minimum"
    client = _test_client(settings, tmp_path, host="qrshield.example", allowed_hosts=["qrshield.example"],
                          access_token=token, env="development")
    assert client.get("/").status_code == 401
    assert client.get("/api/v1/rules", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    import base64
    basic = base64.b64encode(f"research:{token}".encode()).decode()
    assert client.get("/", headers={"Authorization": f"Basic {basic}"}).status_code == 200


def test_research_artifacts_cannot_be_served_through_directory_symlinks(settings, tmp_path):
    client = _test_client(settings, tmp_path)
    artifacts = client.app.state.qs.settings.artifacts_dir
    runs = artifacts / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    run_id = "20261021T000000Z-base-abcdef"
    outside = tmp_path / "private"
    outside.mkdir()
    (outside / "secret.json").write_text('{"secret":true}', encoding="utf-8")
    (runs / run_id).symlink_to(outside, target_is_directory=True)
    response = client.get(f"/research/runs/{run_id}/secret.json")
    assert response.status_code == 404


def test_research_artifact_file_symlink_cannot_escape_run(settings, tmp_path):
    client = _test_client(settings, tmp_path)
    artifacts = client.app.state.qs.settings.artifacts_dir
    run_id = "20261021T000000Z-base-abcdef"
    run_dir = artifacts / "runs" / run_id
    run_dir.mkdir(parents=True)
    outside = tmp_path / "secret.json"
    outside.write_text('{"secret":true}', encoding="utf-8")
    (run_dir / "secret.json").symlink_to(outside)
    response = client.get(f"/research/runs/{run_id}/secret.json")
    assert response.status_code == 404


def test_loopback_only_deployment_rejects_remote_peer_even_with_local_host_header(settings, tmp_path):
    custom = type(settings)(**{
        **settings.__dict__, "artifacts_dir": tmp_path / "artifacts", "env": "development",
        "allowed_hosts": ["127.0.0.1", "localhost", "[::1]"], "access_token": "",
    })
    app = create_app(AppState(custom, QRShieldEngine(custom, use_default_ocr=False)))
    client = TestClient(app, base_url="http://localhost", client=("203.0.113.20", 12345))
    response = client.get("/", headers={"Host": "localhost"})
    assert response.status_code == 403
    assert response.json()["error"] == "remote_access_disabled"


def test_evaluation_cli_validate_only_passes_without_ocr(capsys):
    from evaluation.__main__ import main
    root = discover_dataset_root()
    result = main(["--mode", "validate-only", "--dataset", str(root)])
    captured = capsys.readouterr()
    assert result == 0
    report = json.loads(captured.out)
    assert report["valid"] is True
    assert report["counts"]["total"] == 1280
    assert len(report["image_inventory_hash"]) == 64


def test_standalone_robustness_orchestration_generates_base_baseline_first(monkeypatch, tmp_path):
    import app.routes.research as research
    from evaluation.run_manager import results_jsonl_path, RunProgress

    class Item:
        def __init__(self, item_id):
            self.item_id = item_id
            self.ground_truth = {}

    class Dataset:
        base_items = [Item("BASE-001")]
        robustness_items = [Item("ROB-001")]
        counterfactual_items = []

        def all_items(self):
            return self.base_items + self.robustness_items

    calls = []

    def fake_suite(engine, ds, suite, items, run_id, artifacts_dir, manifest, *, finalize=True):
        calls.append((suite, [item.item_id for item in items], finalize))
        path = results_jsonl_path(artifacts_dir, run_id, suite)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"item_id": items[0].item_id, "evaluable": True}) + "\n", encoding="utf-8")
        (path.parent / "summary.json").write_text("{}", encoding="utf-8")
        RunProgress(run_id, suite, len(items), len(items), 0, "2026-01-01T00:00:00+00:00", "running").save(artifacts_dir)
        return True

    monkeypatch.setattr(research, "_run_suite_thread", fake_suite)
    monkeypatch.setattr(research, "_write_overall_report", lambda *args, **kwargs: None)
    ds = Dataset()
    run_id = "20261021T000000Z-robustness-abcdef"
    research._run_robustness_with_baseline_thread(None, ds, run_id, tmp_path, {"started_utc": "2026-01-01T00:00:00+00:00"})
    assert [call[0] for call in calls] == ["base", "robustness"]
    assert all(call[2] is False for call in calls)
    progress = RunProgress.load(tmp_path, run_id)
    assert progress is not None and progress.status == "done" and progress.total == 2 and progress.completed == 2
