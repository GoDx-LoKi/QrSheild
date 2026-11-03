# API & SDK Reference (`docs/API_REFERENCE.md`)

This document provides the complete technical reference for **QRShield `1.0.0`**:
1. **Programmatic JSON REST API** (`/api/v1/*` and `/health`)
2. **Interactive Web Application Routes** (`/`, `/analyze/*`, `/results/*`, `/research/*`, `/settings/*`)
3. **Python SDK** (`qrshield_core.pipeline.QRShieldEngine`)
4. **Command-Line Interface** (`python3 -m evaluation`)

---

## 1. Authentication & Security Headers

- **Loopback Mode (Default)**: When `ALLOWED_HOSTS` contains only loopback addresses (`127.0.0.1,localhost,[::1]`), requests from loopback peers require no authentication token. Connections from non-loopback IPs are rejected with `403 Forbidden` (`{"error": "remote_access_disabled"}`).
- **Remote Mode**: When `ALLOWED_HOSTS` includes a non-loopback hostname or `*`, `QRSHIELD_ACCESS_TOKEN` must be set to a secret of at least `32` characters. Supply the token via either:
  - `Authorization: Bearer <QRSHIELD_ACCESS_TOKEN>` (recommended for API clients), or
  - HTTP Basic Auth (`Authorization: Basic <base64(user:QRSHIELD_ACCESS_TOKEN)>`).
- **Interactive OpenAPI Documentation**: Available at `GET /api/docs` when the server is running.

---

## 2. Programmatic JSON REST API (`/api/v1`)

### 2.1 `POST /api/v1/analyze-payload`
Analyzes a raw QR payload string alongside structured context attributes.

- **Content-Type**: `application/json`
- **Request Body Schema (`AnalyzePayloadRequest` in `source/app/schemas.py`)**:
  ```json
  {
    "payload": "https://pay-portal.example.com/checkout?redirect=https://evil.org",
    "context": {
      "organization": "Metro Transit Authority",
      "context_type": "transit",
      "purpose": "Buy single-ride ticket",
      "amount": "2.50",
      "domain": "metrotransit.org",
      "email": "",
      "phone": "",
      "network": "",
      "additional": ""
    },
    "ablation": "full",
    "threat_intel": false
  }
  ```
  - `payload` (`string`, required, `1..4096` chars): Raw decoded QR string.
  - `context` (`ContextInput`, optional): Displayed signage context attributes.
  - `ablation` (`"full"` | `"payload_only"` | `"no_context"` | `"no_action"`, default `"full"`): Pipeline layer configuration.
  - `threat_intel` (`boolean`, default `false`): Whether to query configured external Threat Intelligence (`lookup` mode).

- **Response (`200 OK`, `application/json`)**: Full `AnalysisResult.to_dict()` object:
  ```json
  {
    "analysis_id": "a1b2c3d4...",
    "timestamp_utc": "2026-11-02T18:00:00+00:00",
    "engine_version": "1.0.0",
    "rule_version": "1.0.0",
    "reference_data_version": "1.0.0",
    "ablation": "full",
    "qr_decode": {"decoded": true, "count": 1, "selected_index": 0},
    "ocr": {"status": "skipped", "message": "Direct payload analysis", "engine": "none", "blocks": []},
    "context": {"attributes": [...], "ocr_status": "skipped", "completeness": "complete"},
    "payload": {
      "raw": "...",
      "canonical": "...",
      "payload_type": "url",
      "classification_confidence": "high",
      "action_sensitivity": "high",
      "fields": {...},
      "extracted_urls": [...]
    },
    "payload_findings": [...],
    "context_findings": [...],
    "action_findings": [...],
    "threat_intel_findings": [...],
    "evidence_groups": [...],
    "assessment": {
      "level": "high_concern",
      "label": "Suspicious",
      "firing_rule": "R2",
      "action_sensitivity": "high",
      "summary": "...",
      "precautions": [...],
      "contributing_indicators": ["URL-016", "CTX-003"],
      "context_incomplete": false,
      "context_status": "complete",
      "threat_intel_status": "disabled"
    },
    "timings_ms": {"normalize": 0.4, "payload": 1.1, "context": 0.8, "decision": 0.3, "total": 2.6}
  }
  ```

---

### 2.2 `POST /api/v1/analyze`
Uploads an image file, runs multi-pass QR decoding and local OCR, merges optional manual context fields, and returns the `AnalysisResult` JSON.

- **Content-Type**: `multipart/form-data`
- **Form Fields**:
  - `image` (`file`, required): PNG, JPEG, WebP, BMP, or GIF image (`<= MAX_IMAGE_SIZE_MB`).
  - `organization` (`string`, optional): Manual organization override.
  - `context_type` (`string`, optional): Venue/context type (`hotel`, `restaurant`, `bank`, `transit`, etc.).
  - `purpose` (`string`, optional): Stated purpose on signage.
  - `amount` (`string`, optional): Displayed monetary amount.
  - `additional` (`string`, optional): Additional signage text.
  - `qr_index` (`integer`, optional): 0-based index of the QR code to analyze when multiple QR codes are present.
  - `use_unconfirmed_ocr` (`boolean`, default `false`): Automatically accept OCR-extracted context candidates without interactive review.

- **Status Codes**:
  - `200 OK`: Analysis completed (`AnalysisResult` JSON).
  - `400 Bad Request`: Invalid image format, corrupted bytes, or image exceeds size/pixel limits (`{"error": "<code_name>", "detail": "..."}`).
  - `422 Unprocessable Entity`:
    - `{"error": "no_qr_found", "detail": "No QR code was detected. This is not a security verdict.", "ocr_status": "..."}`
    - `{"error": "select_qr", "detail": "N QR codes found; explicitly pass qr_index.", "count": N}`

---

### 2.3 `GET /api/v1/rules`
Returns all `87` loaded rules from `source/rules/*_rules.yaml` along with rule and reference data versions.

- **Response (`200 OK`)**:
  ```json
  {
    "rule_version": "1.0.0",
    "reference_data_version": "1.0.0",
    "rules": [
      {
        "id": "ACT-001",
        "title": "Action sensitivity",
        "category": "action",
        "severity": "info",
        "family": "action_sensitivity",
        "layer": "action",
        "applicability": ["url", "wifi", "payment", "contact", "sms", "email", "deep_link", "plain_text"],
        "rationale": "..."
      }
    ]
  }
  ```

---

### 2.4 `GET /health`
Lightweight container and service liveness probe.
- **Response (`200 OK`)**: `{"status": "ok", "version": "1.0.0"}`

---

## 3. Web UI & HTMX Endpoints (`source/app/routes/`)

| Method & Path | Handler Module | Description |
| :--- | :--- | :--- |
| `GET /` | `routes/analyze.py::index` | Renders the main interactive QR analysis page (`analyze.html`). |
| `POST /analyze/prepare` | `routes/analyze.py::prepare` | Decodes uploaded image, runs 2-pass OCR, caches sanitized PNG, and returns `partials/prepared.html` for candidate review. |
| `POST /analyze/run` | `routes/analyze.py::run` | Builds `Context` from confirmed/edited OCR candidates + manual inputs, runs `analyze_prepared`, and renders `partials/results.html`. |
| `GET /results/{rid}` | `routes/analyze.py::result_page` | Permalink HTML view for a saved analysis result (`result_page.html`). |
| `GET /results/{rid}.json` | `routes/analyze.py::result_json` | Downloads the full `AnalysisResult` as `qrshield-{rid[:8]}.json`. |
| `GET /results/{rid}.csv` | `routes/analyze.py::result_csv` | Downloads the findings ledger as `qrshield-{rid[:8]}-findings.csv`. |
| `POST /results/{rid}/scan` | `routes/analyze.py::explicit_scan` | Triggers a fresh external VirusTotal URL scan after explicit `confirm=yes` user consent. |
| `GET /image/{aid}` | `routes/analyze.py::image` | Serves the sanitized PNG image (`image/png`) for a prepared session. |
| `GET /research` | `routes/research.py::research_page` | Renders the Research Benchmark Runner workspace (`research.html`). |
| `POST /research/validate` | `routes/research.py::validate_dataset_route` | Validates `qrs_bench_ind/` structure and semantic links (`partials/research_status.html`). |
| `POST /research/run` | `routes/research.py::start_research_run` | Starts a background benchmark run (`suite` in `base`, `counterfactual`, `robustness`, `all`). |
| `GET /research/progress/{run_id}` | `routes/research.py::research_progress` | Polls live progress or returns completed artifact links (`partials/research_results.html`). |
| `GET /research/runs/{run_id}/{path}` | `routes/research.py::run_artifact` | Serves generated `.json`, `.jsonl`, `.csv`, or `.html` run reports with strict path traversal protection. |
| `GET /settings` | `routes/settings.py::settings_page` | Displays current configuration, rule count, and provider status (`settings.html`). |
| `POST /settings/check-ocr` | `routes/settings.py::check_ocr` | Tests whether the configured local OCR engine initializes cleanly (`partials/status.html`). |

---

## 4. Python SDK Reference (`source/qrshield_core/`)

### `QRShieldEngine` (`qrshield_core.pipeline.engine.QRShieldEngine`)
```python
class QRShieldEngine:
    def __init__(
        self,
        settings: Settings | None = None,
        ocr_provider: OCRProvider | None = None,
        ti_provider: ThreatIntelProvider | None = None,
        *,
        use_default_ocr: bool = True,
    ) -> None: ...

    def prepare_image(self, data: bytes, filename: str | None = None) -> PreparedImage:
        """Stage 1 + Stage 3: Validate image, decode QR codes (10 passes), run 2-pass OCR, and extract candidates."""

    def analyze_prepared(
        self,
        prep: PreparedImage,
        qr_index: int = 0,
        context: Context | None = None,
        config: AnalysisConfig = AnalysisConfig(),
        ocr_override: OCRResult | None = None,
        analysis_id: str | None = None,
    ) -> AnalysisResult:
        """Run Stages 2, 4, 5, 6, and 7 on a previously prepared image and selected QR code index."""

    def analyze_payload(
        self,
        raw: str,
        context: Context | None = None,
        config: AnalysisConfig = AnalysisConfig(),
        *,
        analysis_id: str | None = None,
        qr_info: dict[str, Any] | None = None,
        ocr: OCRResult | None = None,
        candidates: list[ContextCandidate] | None = None,
    ) -> AnalysisResult:
        """Analyze a decoded QR payload string directly with optional structured Context."""
```
