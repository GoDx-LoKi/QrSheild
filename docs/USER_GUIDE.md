# User Guide (`docs/USER_GUIDE.md`)

This guide explains how to operate **QRShield `1.0.0`** through the local Web UI, the Command-Line Interface (CLI), and the Research Benchmark Runner, and how to interpret QRShield's 4-level ordinal security assessments.

---

## 1. Starting the Local Web Interface

From the repository root, start the FastAPI web server on loopback:
```bash
OCR_PROVIDER=paddleocr PYTHONPATH=source uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Navigate to `http://127.0.0.1:8000` in your browser. The navigation bar provides three workspaces:
1. **Analyze (`/`)**: Interactive two-step QR image inspection with human-in-the-loop context review.
2. **Research Tests (`/research`)**: Automated dataset validation and execution of the `QRS-Bench-Ind` benchmark suites (`base`, `counterfactual`, `robustness`, `all`).
3. **Settings (`/settings`)**: Read-only inspection of active configuration, loaded rule counts (`87` rules), OCR engine health check, and Threat Intelligence status.

---

## 2. Interactive Analysis Workflow (`/`)

QRShield's interactive workflow is intentionally designed around **two stages** so that OCR errors or multiple QR codes on a poster never produce silent misclassifications:

### Step 1: Upload & Prepare (`POST /analyze/prepare`)
1. Upload a PNG, JPEG, WebP, BMP, or GIF image (up to `10 MB` / `40 MP`).
2. QRShield sanitizes the image, runs the **10-pass QR decoder**, masks out the QR bounding box, and runs **2-pass local OCR** on the surrounding signage.
3. The UI displays:
   - **Detected QR Code(s)**: If an image contains multiple QR codes, you can select a specific code or choose **Analyze All**. Safe, non-clickable payload previews are shown.
   - **Extracted Context Candidates**: Each OCR-detected candidate for `organization`, `purpose`, `amount`, `domain`, `email`, `phone`, and `network` is displayed with its confidence badge (`high`, `medium`, `low`) and three radio actions:
     - **`Use`**: Confirm the OCR value as trusted signage context.
     - **`Edit`**: Correct a typo in the OCR text before running consistency checks.
     - **`Ignore`**: Discard a noisy OCR artifact.
   - **Manual Context Fields**: Supply or override `Organization / venue`, `Context type` (e.g., `restaurant`, `bank`, `transit`, `parking`, `clinic`), `Stated purpose`, `Displayed amount`, or `Additional text`.
   - **Threat Intelligence Toggle**: When `THREAT_INTEL_ENABLED=true` and `VIRUSTOTAL_API_KEY` is configured, an explicit checkbox lets you opt in to querying existing VirusTotal URL reports.

### Step 2: Run Analysis & Inspect Evidence (`POST /analyze/run`)
Click **Run Security Analysis** to execute Stages 2–7 of the engine. The result card presents:
1. **Ordinal Risk Assessment Badge (`L0`–`L3`)** and the exact **Firing Decision Rule** (e.g., `R2`, `R4`, `R0a`, `R0`).
2. **Plain-Language Executive Summary** explaining *why* the assessment was reached and what action the QR code attempts to trigger.
3. **Context Provenance Banner** (`complete`, `partial`, `missing`, `unconfirmed_ocr`, or `ocr_unavailable`).
4. **Grouped Evidence Ledger**: Findings organized by evidence family (`payload_structure`, `destination_identity`, `context_consistency`, `sensitive_request`, `network_security`, `payment_integrity`, `action_sensitivity`, `threat_intelligence`), sorted from `STRONG` to `INFO`.
5. **Recommended Precautions**: Actionable user guidance tailored to the payload family and triggered indicators.
6. **One-Click Exports**: Download the full structured report as JSON (`/results/{rid}.json`) or the findings table as CSV (`/results/{rid}.csv`).

---

## 3. Interpreting Assessment Levels (`L0`–`L3`)

| Level | Internal Value | UI Badge | Meaning & Recommended Action |
| :---: | :--- | :--- | :--- |
| **`L0`** | `no_material_concern` | **Low Risk / No Material Concern** | The QR payload is structurally sound and consistent with the surrounding signage context. Proceed with normal caution. |
| **`L1`** | `needs_verification` | **Verify Before Proceeding** | An ambiguity or unverified dependency exists — for example, a URL shortener hides the final domain (`R0b`), a known third-party payment/booking processor is used (`R0a`), or signage context is incomplete (`R0d`, `R0e`). Verify the destination or merchant with staff before completing the action. |
| **`L2`** | `high_concern` | **Suspicious / High Concern** | Strong local evidence of deception or a direct contradiction between the signage and the QR payload (e.g., payee mismatch `CTX-002`, payment amount mismatch `CTX-007`, outbound OTP/PIN exfiltration `COM-001`, or lookalike brand domain `URL-004`). **Do not proceed.** |
| **`L3`** | `harmful_corroborated` | **High-Risk Indicators (Corroborated)** | Either an external Threat Intelligence provider confirmed malicious detections (`R1`) or a strong intrinsic payload attack is corroborated by a strong cross-modal context mismatch (`R2`). **Do not scan, pay, or enter credentials.** |

---

## 4. Command-Line Interface (`python3 -m evaluation`)

The `evaluation` package provides a versatile CLI (`source/evaluation/__main__.py`) for headless inspection, red-team batch testing, decoder evaluation, and benchmark reproduction.

### 4.1 Single-Image End-to-End Inspection (`--single-image`)
Decodes the image, runs local OCR, auto-accepts extracted context candidates (`auto_use_unconfirmed=True`), and prints the complete `AnalysisResult` JSON to stdout:
```bash
PYTHONPATH=source python3 -m evaluation \
  --single-image qrs_bench_ind/splits/test_locked/core_scenes/url/test_locked_core_scenes_0001.png
```

### 4.2 Batch JSONL Scenario Evaluation (`--batch-jsonl`)
Evaluates a newline-delimited JSON file of `{case_id, payload, ctx_attrs}` records and outputs newline-delimited predictions (`case_id`, `predicted_level`, `firing_rule`, `indicators`):
```bash
PYTHONPATH=source python3 -m evaluation \
  --batch-jsonl release/evidence/redteam_208_scenarios.jsonl
```

### 4.3 Multi-Pass QR Decoder Directory Evaluation (`--decode-images-dir`)
Runs QRShield's 10-pass QR decoder (`qrshield_core.decoder.qr.detect_and_decode`) over every `.png` image in a directory tree and outputs per-image decode results as JSONL:
```bash
PYTHONPATH=source python3 -m evaluation \
  --decode-images-dir qrs_bench_ind/splits/test_locked/robustness_variants
```

### 4.4 Full Benchmark Suite Evaluation (`--suite`)
Validates `qrs_bench_ind/` and executes `base`, `counterfactual`, `robustness`, or `all`:
```bash
PYTHONPATH=source python3 -m evaluation \
  --suite all \
  --dataset qrs_bench_ind \
  --output-dir /tmp/qrshield_runs
```
Other useful CLI flags:
- `--validate-only`: Validate dataset directory structure, image hashes, and semantic links without running OCR/inference.
- `--ablation-study`: Run all 4 local layer ablation configurations (`payload_only`, `context_only`, `payload_context`, `payload_context_action`) across the benchmark.
- `--holdout-benchmark`: Run the 70-scenario out-of-distribution holdout suite with `load_synthetic_reference=False`.
