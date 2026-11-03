# QRShield (`1.0.0`)

**Explainable, Context-Aware, Non-Executing Security Analysis for QR Codes Across 8 Payload Families**

QRShield is a deterministic, local-first security analysis framework and benchmark suite for inspecting QR codes and their surrounding visual signage **without ever opening, resolving, joining, paying, sending, calling, or launching the decoded payload**. Unlike URL-only "quishing" scanners, QRShield models QR code security as a **cross-modal consistency verification problem**: it jointly evaluates the decoded QR payload, the visible contextual claims extracted via local OCR (or operator input), and the operational sensitivity of the action triggered by the QR code.

---

## Table of Contents

1. [Project Overview & Objectives](#1-project-overview--objectives)
2. [Key Features](#2-key-features)
3. [System Architecture](#3-system-architecture)
4. [Supported QR Payload Families](#4-supported-qr-payload-families)
5. [Analysis Workflow & Decision Policy](#5-analysis-workflow--decision-policy)
6. [Repository Structure](#6-repository-structure)
7. [Installation & Setup](#7-installation--setup)
8. [Configuration & Environment Variables](#8-configuration--environment-variables)
9. [Usage Examples (Web UI, REST API, CLI, Python SDK)](#9-usage-examples-web-ui-rest-api-cli-python-sdk)
10. [Security Considerations & Non-Execution Invariant](#10-security-considerations--non-execution-invariant)
11. [Testing & Verification Gate (`make verify`)](#11-testing--verification-gate-make-verify)
12. [Benchmark Methodology & Evaluation (`QRS-Bench-Ind`)](#12-benchmark-methodology--evaluation-qrs-bench-ind)
13. [Limitations & Scope Boundaries](#13-limitations--scope-boundaries)
14. [Troubleshooting](#14-troubleshooting)
15. [Documentation Index](#15-documentation-index)
16. [Contributing](#16-contributing)
17. [License](#17-license)
18. [Citation](#18-citation)

---

## 1. Project Overview & Objectives

Physical and digital QR codes routinely encode more than web URLs: they provision Wi-Fi networks (`WIFI:`), initiate instant payments (`upi://`, `bitcoin:`, `ethereum:`, EMVCo TLV), pre-fill SMS (`SMSTO:`) or email (`mailto:`, `MATMSG:`) messages, dial phone numbers or USSD strings (`tel:`), import contact cards (`BEGIN:VCARD`, `MECARD:`), and invoke mobile application deep links (`app://`).

Traditional QR scanners face two structural blind spots:
1. **Scheme blindness**: URL blocklists and browser safe-browsing APIs cannot evaluate non-URL schemes such as UPI payment URIs, Wi-Fi provisioning strings, SMS/email social-engineering templates, or custom app deep links.
2. **Context blindness**: A syntactically valid, TLS-protected URL or structurally valid UPI Virtual Payment Address (VPA) can still be an attack when pasted over a legitimate merchant's poster (physical tamper/overlay), when the payee VPA or amount contradicts the printed bill, or when an SMS/email body tricks the user into transmitting an OTP or credential.

### Core Objectives
- **Strict Non-Execution Invariant**: Treat every decoded QR payload as untrusted data. Never fetch URLs, follow redirects, resolve DNS, join networks, initiate payments, or invoke OS handlers during local analysis.
- **Cross-Modal Context Consistency**: Compare the claims printed on the physical/digital sign (organization, stated purpose, displayed domain, payment amount, phone, email, network SSID) against the actual technical parameters of the QR payload.
- **Explainable Ordinal Risk Assessment**: Produce a human-verifiable 4-level ordinal risk assessment (`L0`–`L3`) backed by structured evidence items (`indicator_id`, `family`, `severity`, `observed_value`, `expected_value`, `explanation`, and `remediation`) and explicit firing rules (`R0`–`R10`, `R0a`–`R0f`).
- **Reproducible Evaluation**: Provide a self-contained, zero-leakage benchmark (`qrs_bench_ind/`, `1,080` evaluation units / `1,280` PNG images) and an automated one-command verification gate (`make verify`).

---

## 2. Key Features

- **8 First-Class Payload Analyzers**: Dedicated parsers and security analyzers for `url`, `wifi`, `payment`, `contact`, `sms`, `email`, `deep_link`, and `plain_text` payloads (`source/qrshield_core/normalizer/normalize.py` and `source/qrshield_core/analyzers/`).
- **Multi-Pass QR Decoding (`source/qrshield_core/decoder/qr.py`)**: Combines OpenCV `QRCodeDetector` (single and multi-code) with optional `zxing-cpp` fallback across 10 preprocessing passes (original, grayscale, 2x cubic upscale, Otsu threshold, adaptive Gaussian threshold, CLAHE contrast enhancement, unsharp mask, morphological closing, 4-orientation rotation, and 15% border crop). Achieves `99.48%` (`191 / 192`) decode recovery on the `QRS-Bench-Ind` degraded robustness suite compared to `69.27%` (`133 / 192`) for raw single-pass OpenCV.
- **2-Pass Illumination-Normalized Local OCR (`source/qrshield_core/ocr/engine.py`)**: Supports local `Tesseract` and `PaddleOCR` engines with division-normalization (`cv2.divide` against a $\sigma=35$ Gaussian illumination background estimate + `fastNlMeansDenoising` + Otsu binarization) when Pass 1 yields sparse or low-confidence text under uneven shadow/glare.
- **Relational & Acronym Entity Matching (`source/qrshield_core/matching/entity.py`)**: Resolves parent/subsidiary/DBA relationships from poster footer disclosures (`a division of`, `operated by`, `powered by`, `dba`), multi-word organization initials (e.g., `"Northstar Regional Transit"` $\leftrightarrow$ `nrt-transit.org`), and curated brand/processor registries (`source/rules/reference/brands.yaml`, `source/rules/reference/lists.yaml`).
- **Semantic Credential & Exfiltration Intent Detection (`source/qrshield_core/analyzers/common.py`)**: Distinguishes outbound user-to-attacker secret disclosure (e.g., *"Here are the 6 digits that arrived on my phone"*) from benign administrative requests (e.g., *"Please send the guest Wi-Fi password for room 4"*) and benign security education reminders (*"Never share your OTP or PIN"*).
- **Declarative YAML Rule & Lexicon Registry (`source/rules/`)**: `87` unique rule definitions across 12 `*_rules.yaml` files (`url_rules.yaml`, `wifi_rules.yaml`, `payment_rules.yaml`, `contact_rules.yaml`, `sms_rules.yaml`, `email_rules.yaml`, `comm_rules.yaml`, `deeplink_rules.yaml`, `text_rules.yaml`, `context_rules.yaml`, `action_rules.yaml`, `threat_intel_rules.yaml`) and 5 reference registries (`source/rules/reference/`).
- **Four Interfaces Out of the Box**:
  - **Interactive Local Web UI** (`FastAPI` + `Jinja2` + `HTMX`) with human-in-the-loop OCR candidate review and a built-in Research Benchmark Runner (`/`, `/research`, `/settings`).
  - **Programmatic REST API** (`/api/v1/analyze-payload`, `/api/v1/analyze`, `/api/v1/rules`, `/health`).
  - **Command-Line Interface** (`python3 -m evaluation`) for single-image inspection, JSONL batch evaluation, decoder benchmarking, and full dataset evaluation.
  - **Python SDK** (`QRShieldEngine`, `Settings`, `Context`, `AnalysisConfig`).

---

## 3. System Architecture

QRShield executes a deterministic **7-stage analysis pipeline** (`source/qrshield_core/pipeline/engine.py`):

```
                 ┌────────────────────────────────────────────────────┐
                 │  Input: QR Image (PNG/JPEG/WebP/BMP/GIF) or String │
                 └─────────────────────────┬──────────────────────────┘
                                           │
                                           ▼
  ┌────────────────────────────────────────────────────────────────────────────────┐
  │ Stage 1: Safe Image Loader & Multi-Pass QR Decoder                             │
  │  • Enforces byte (10 MB), pixel (40 MP), and dimension (4000 px) limits        │
  │  • Strips EXIF/metadata; re-encodes clean PNG; runs 10-pass QR detection       │
  └───────────────────┬────────────────────────────────────────┬───────────────────┘
                      │ Decoded Payload String                 │ Clean Image Array
                      ▼                                        ▼
  ┌───────────────────────────────────────┐  ┌─────────────────────────────────────┐
  │ Stage 2: Payload Normalizer &         │  │ Stage 3: Local OCR & Context        │
  │          Scheme Classifier            │  │          Candidate Extractor        │
  │  • RFC/URI parsing, percent-decoding  │  │  • 2-pass local OCR (Tesseract /    │
  │  • IDNA punycode & script profiling   │  │    PaddleOCR) outside QR bbox       │
  │  • Classifies into 8 payload families │  │  • Extracts org, purpose, amount,   │
  │  • Assigns ActionSensitivity          │  │    domain, email, phone, network    │
  └───────────────────┬───────────────────┘  └─────────────────┬───────────────────┘
                      │                                        │
                      ▼                                        ▼
  ┌───────────────────────────────────────┐  ┌─────────────────────────────────────┐
  │ Stage 4: Entity Normalization, Domain │  │ Stage 5: Family-Specific Payload    │
  │          & Processor Matching         │  │          Security Analyzers (8)     │
  │  • Brand/processor/acronym/DBA match  │  │  • Homoglyphs, IP hosts, shorteners │
  │  • Registrable eTLD+1 comparison      │  │  • Query & #fragment redirect traps │
  │  • Token-stuffed VPA local-part check │  │  • Outbound secret disclosure check │
  └───────────────────┬───────────────────┘  └─────────────────┬───────────────────┘
                      └────────────────────┬───────────────────┘
                                           │
                                           ▼
  ┌────────────────────────────────────────────────────────────────────────────────┐
  │ Stage 6: Cross-Modal Context Consistency, Action Sensitivity & Threat Intel    │
  │  • Evaluates CTX-001..CTX-014 across organization, purpose, amount, SSID, etc. │
  │  • Emits ACT-001 action sensitivity & optional TI-001..TI-008 URL corroboration│
  └────────────────────────────────────────┬───────────────────────────────────────┘
                                           │
                                           ▼
  ┌────────────────────────────────────────────────────────────────────────────────┐
  │ Stage 7: Ordinal Decision Policy & Explainable Report Synthesizer              │
  │  • Evaluates explicit rules (R0..R10, R0a..R0f) over grouped evidence          │
  │  • Outputs L0..L3 assessment, summary, precautions, JSON/CSV/HTML reports      │
  └────────────────────────────────────────────────────────────────────────────────┘
```

For a deep dive into every module, data model, and rule interaction, see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## 4. Supported QR Payload Families

| Payload Family | Recognizer / Scheme Prefix | Analyzer Module (`source/qrshield_core/analyzers/`) | Representative Rule IDs (`source/rules/*_rules.yaml`) |
| :--- | :--- | :--- | :--- |
| **Web URL** (`url`) | `http://`, `https://`, `javascript:`, `data:`, `file://`, bare `host.tld/...` | `url.py` | `URL-001`..`URL-021` (HTTP login, public/private IP, shorteners, brand lookalike, userinfo, punycode/mixed-script homoglyphs, `#redirect=` & query open redirects, dangerous schemes) |
| **Wi-Fi Provisioning** (`wifi`) | `WIFI:T:...;S:...;P:...;H:...;;` | `wifi.py` | `WIFI-001`..`WIFI-005` (open network context-gated for guest venues, WEP/legacy encryption, hidden SSID, embedded password, malformed SSID), `CTX-006`, `CTX-013`, `CTX-014` |
| **Payment / Financial** (`payment`) | `upi://pay`, `bitcoin:`, `ethereum:`, `payto://`, EMVCo `000201...` | `payment.py` | `PAY-001`..`PAY-011` (missing payee name, large amount, ancillary redirect URL, invalid VPA, invalid EMVCo CRC, token-stuffed VPA handle), `CTX-002`, `CTX-007`, `CTX-009` |
| **Contact Card** (`contact`) | `BEGIN:VCARD...END:VCARD`, `MECARD:...`, `BIZCARD:...` | `contact.py` | `CON-001`..`CON-005` (unrelated email/website domain, mismatched email vs web domain, free email provider, invalid phone), `COM-001`..`COM-004` (phishing note) |
| **SMS Message** (`sms`) | `sms:`, `smsto:`, `mms:`, `mmsto:` | `messaging.py` | `SMS-001`..`SMS-003` (malformed destination, multiple recipients, pre-filled body), `COM-001`..`COM-004` (outbound OTP/PIN disclosure & social engineering), `CTX-010` |
| **Email Message** (`email`) | `mailto:`, `MATMSG:TO:...`, `SMTP:...` | `messaging.py` | `EML-001`..`EML-004` (multiple/hidden BCC recipients, free provider, brand-lookalike recipient domain, malformed address), `COM-001`..`COM-004`, `CTX-004`, `CTX-010` |
| **App Deep Link** (`deep_link`) | Custom URI schemes (`<scheme>://...`, `intent://...`, `otpauth://...`) | `deeplink.py` | `DL-001`..`DL-007` (unverified scheme, sensitive in-app operation, sensitive parameters, excessive params, browser fallback URL, embedded `otpauth` secret), `CTX-008` |
| **Plain Text / Call** (`plain_text`) | Unstructured text or `tel:` / USSD `*...#` strings | `text.py`, `messaging.py` | `TXT-001`..`TXT-006` (control characters, embedded URL/email/phone indicators, oversized payload, call/USSD initiation `TXT-005`), `COM-001`..`COM-004` |

Full rule specifications, severities, and rationales are documented in [`docs/RULES_CARD.md`](docs/RULES_CARD.md) and [`docs/SPEC_TRACE.md`](docs/SPEC_TRACE.md).

---

## 5. Analysis Workflow & Decision Policy

QRShield separates **evidence collection** from **risk adjudication**:

### Evidence Severities & Layers
Every triggered rule emits an `EvidenceItem` assigned to a layer (`payload`, `context`, `action`, `threat_intel`), an `EvidenceFamily`, and one of four severities:
- **`STRONG`**: High-confidence indicator of active deception, credential/financial exfiltration, executable URI scheme, IDN homoglyph spoofing, userinfo host trick, USSD command injection, or direct context contradiction on a critical parameter (e.g., payment amount mismatch `CTX-007`, payee mismatch `CTX-002`, or brand impersonation `URL-004`).
- **`MEANINGFUL`**: Substantive anomaly requiring verification (e.g., URL shortener `URL-003`, unverified deep-link scheme `DL-001`, unencrypted HTTP on a sensitive path `URL-001`, or organization/domain mismatch `CTX-003`).
- **`WEAK`**: Contextual or structural hygiene note (e.g., missing payee display name `PAY-002`, free email provider `EML-002` when not explicitly matched by signage).
- **`INFO`**: Informational metadata (`ACT-001` action sensitivity markers, `TI-003`..`TI-006` status records).

### Four-Level Ordinal Assessment Scale (`AssessmentLevel`)

| Level | Enum Value | Label | Policy Trigger Summary (`source/qrshield_core/decision/policy.py`) |
| :---: | :--- | :--- | :--- |
| **`L0`** | `no_material_concern` | **No Material Concern** | Clean payload and consistent context (`R0`), or isolated weak hygiene signals safely calibrated by verified context. |
| **`L1`** | `needs_verification` | **Needs Verification** | Single context anomaly (`R7`), suspicious/mixed threat intel (`R8`), multiple weak signals across independent families (`R9`), weak payload signal on high-sensitivity action (`R10`), known third-party processor (`R0a`), dynamic QR/shortener (`R0b`), weak payload evidence on medium-sensitivity action (`R0c`), unverified high-sensitivity action missing org context (`R0d`), or low OCR confidence/missing text (`R0e`). |
| **`L2`** | `high_concern` | **High Concern** | Strong payload evidence alone (`R3`), strong context mismatch on medium/high-sensitivity action (`R4`), moderate payload + moderate context mismatch (`R5`), or multiple moderate payload indicators on a high-sensitivity action (`R6`). |
| **`L3`** | `harmful_corroborated` | **Harmful / High-Risk (Corroborated)** | Confirmed external Threat Intelligence hit (`TI-001`, `R1`), or strong payload evidence corroborated by a strong context mismatch (`R2`). |

---

## 6. Repository Structure

```text
qrshield/
├── README.md                          # Comprehensive project documentation (this file)
├── LICENSE                            # MIT License
├── CONTRIBUTING.md                    # Contribution & pull-request guidelines
├── SECURITY.md                        # Vulnerability disclosure & security invariants
├── DECISIONS.md                       # Architectural Decision Records (ADR-001..ADR-006)
├── Makefile                           # One-command verification harness (make verify)
├── pyproject.toml                     # Python package metadata, dependencies & tool config
├── requirements.txt                   # Core runtime dependencies
├── requirements.lock                  # SHA-256 hash-locked dependency pins
├── Dockerfile                         # Hardened non-root container image definition
├── docker-compose.yml                 # Read-only, loopback-bound Docker Compose service
├── .env.example                       # Documented environment variable template
├── .gitignore                         # Git ignore rules
├── .dockerignore                      # Docker build context exclusions
├── build_and_evaluate_qrs_bench_ind.py # Deterministic generator & evaluator for QRS-Bench-Ind
│
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md              # Bug report template
│   │   └── feature_request.md         # Feature / rule request template
│   ├── pull_request_template.md       # Pull request checklist
│   └── workflows/
│       └── ci.yml                     # GitHub Actions CI pipeline running make verify
│
├── source/                            # Application & core engine source tree
│   ├── sitecustomize.py               # Appends tools/offline_fallback only if host lacks pytest/qrcode
│   ├── qrshield_core/                 # Core 7-stage analysis engine (frozen .py modules)
│   │   ├── config.py                  # Environment-driven Settings dataclass
│   │   ├── models.py                  # Domain dataclasses & enums
│   │   ├── rules.py                   # RuleRegistry & ReferenceData loader
│   │   ├── image/loader.py            # Safe image bounds verification & PNG normalization
│   │   ├── decoder/qr.py              # Multi-pass OpenCV + optional zxing-cpp QR decoder
│   │   ├── ocr/engine.py              # 2-pass illumination-normalized OCR (Tesseract / PaddleOCR)
│   │   ├── classifier/classify.py     # Scheme recognizer & payload type classifier
│   │   ├── normalizer/normalize.py    # Canonical structural parser across 8 payload families
│   │   ├── context/                   # Candidate extraction (extract.py), purpose.py & consistency.py
│   │   ├── analyzers/                 # Family analyzers (url, wifi, payment, contact, messaging, deeplink, text)
│   │   ├── matching/                  # Entity/DBA/acronym matcher (entity.py) & domains.py
│   │   ├── action/sensitivity.py      # Action sensitivity calibration (LOW / MEDIUM / HIGH)
│   │   ├── threat_intel/service.py    # Opt-in VirusTotal v3 client & local SQLite cache
│   │   ├── evidence/grouping.py       # Evidence deduplication & family grouping
│   │   ├── decision/policy.py         # Ordinal decision rules (R0..R10, R0a..R0f)
│   │   ├── reporting/                 # Explanation builder (explain.py) & JSON/CSV export (export.py)
│   │   └── pipeline/engine.py         # End-to-end orchestrator (QRShieldEngine)
│   ├── rules/                         # Declarative YAML rule & reference registries (frozen .yaml files)
│   │   ├── *_rules.yaml               # 12 rule files defining 87 unique indicator rules
│   │   ├── reference/                 # brands.yaml, lexicon.yaml, lists.yaml, purposes.yaml, schemes.yaml
│   │   └── test_fixtures/             # Isolated synthetic reference fixtures (brands_synthetic.yaml)
│   ├── app/                           # FastAPI + Jinja2 + HTMX local web interface & REST API
│   ├── evaluation/                    # Benchmark loader, scorer, ablation runner & CLI (__main__.py)
│   └── tests/                         # 446 automated unit, integration, security, and evaluation tests
│
├── qrs_bench_ind/                     # Independent benchmark dataset (1,080 units / 1,280 PNG images)
│   ├── README.md                      # Benchmark overview & split summary
│   ├── MANIFEST_SHA256.txt            # SHA-256 checksums for all 1,280 benchmark PNG images
│   ├── metadata/                      # organizations_splits.yaml, taxonomy_and_codebook.yaml, ANNOTATION_PROTOCOL.md
│   ├── annotations/                   # consensus_ground_truth.jsonl (1,080 units)
│   ├── splits/                        # Rendered PNGs across dev/, val/, and test_locked/
│   └── evaluation_runs/               # Frozen engine manifest, predictions, metrics & report
│
├── tools/                             # Verification, audit, statistical & annotation scripts
│   ├── verify_clean_tree.py           # Bytecode, scratch directory & required file gate
│   ├── run_coverage.py                # AST + sys.settrace line & branch coverage gate
│   ├── run_mutation.py                # AST mutation testing harness on policy.py & entity.py
│   ├── run_fuzzer.py                  # 100,000-iteration structure-aware fuzzer
│   ├── run_static_security.py         # AST static security & Docker hardening verifier
│   ├── check_label_provenance.py      # Anti-fabrication provenance gate (AC-5)
│   ├── generate_spec_trace.py         # Rule-to-code-to-test traceability generator (AC-3)
│   ├── compute_rigorous_stats.py      # Cluster bootstrap CIs, McNemar-Holm & PPV generator
│   ├── independent_validation.py      # Zero-shared-code validation, 208 red-team & decoder cross-check
│   ├── verify_claims.py               # Paper/documentation numerical claim verifier
│   └── ingest_annotations.py          # Blind dual-rater CSV exporter & full-schema ingestion tool
│
├── docs/                              # Complete technical documentation suite
├── release/                           # Machine-checkable verification evidence & checksums
```

---

## 7. Installation & Setup

### System Prerequisites
- **Python**: `3.11` or `3.12`
- **System Libraries** (for OpenCV and local Tesseract OCR):
  - **Ubuntu / Debian**:
    ```bash
    sudo apt-get update
    sudo apt-get install -y tesseract-ocr libgl1 libglib2.0-0 libgomp1
    ```
  - **macOS (Homebrew)**:
    ```bash
    brew install tesseract
    ```

### Option A: Standard Virtual Environment Setup (Recommended)
```bash
git clone https://github.com/qrshield/qrshield.git
cd qrshield

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e ".[dev]"
```

### Option B: Reproducible Hash-Locked Installation
To install the exact dependency versions with SHA-256 wheel verification:
```bash
pip install --require-hashes -r requirements.lock
pip install --no-deps -e .
```

### Option C: Hardened Docker Compose Deployment
The root [`Dockerfile`](Dockerfile) and [`docker-compose.yml`](docker-compose.yml) build a minimal container running as non-root user `qrshield` (`UID 10001`), with a read-only root filesystem, dropped Linux capabilities (`cap_drop: ALL`), `no-new-privileges:true`, and loopback-only port binding (`127.0.0.1:8000:8000`):
```bash
cp .env.example .env
docker compose up --build
```

For air-gapped environments, optional PaddleOCR/ZXing extras, and platform-specific details, see [`docs/INSTALLATION.md`](docs/INSTALLATION.md).

---

## 8. Configuration & Environment Variables

QRShield reads optional settings from environment variables or `source/.env` (see [`.env.example`](.env.example)). All settings have safe offline defaults in [`source/qrshield_core/config.py`](source/qrshield_core/config.py):

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `QRSHIELD_ENV` | `development` | Execution environment (`development`, `production`, `test`). |
| `LOG_LEVEL` | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `OCR_ENABLED` | `true` | Enable local OCR text extraction on uploaded images. |
| `OCR_PROVIDER` | `paddleocr` | Local OCR backend (`paddleocr`, `tesseract`, or `auto`). Install the optional `ocr` extra for PaddleOCR. |
| `THREAT_INTEL_ENABLED` | `true` | Allow opt-in external threat intelligence lookups when an API key is configured. |
| `VIRUSTOTAL_API_KEY` | `""` (empty) | Optional VirusTotal v3 API key. Never logged or printed in `repr()`. |
| `VT_MALICIOUS_THRESHOLD` | `3` | Minimum VirusTotal engines flagging `malicious` required to trigger `TI-001`. |
| `VT_TIMEOUT_SECONDS` | `10` | HTTP timeout (seconds) for opt-in VirusTotal requests. |
| `MAX_IMAGE_SIZE_MB` | `10` | Maximum accepted image file size in megabytes. |
| `MAX_IMAGE_PIXELS` | `40000000` | Maximum image pixel area (decompression bomb protection). |
| `MAX_IMAGE_SIDE` | `4000` | Maximum width or height in pixels (`4000 px`). |
| `RESULT_RETENTION_DAYS` | `7` | Retention window for saved analysis artifacts under `ARTIFACTS_DIR`. |
| `LOAD_SYNTHETIC_REFERENCE` | `false` | Load synthetic `.example` test brands (`source/rules/test_fixtures/brands_synthetic.yaml`). Always `false` in production and benchmark runs. |
| `ALLOWED_HOSTS` | `127.0.0.1,localhost,[::1]` | Comma-separated Host header allowlist (DNS-rebinding mitigation). |
| `QRSHIELD_ACCESS_TOKEN` | `""` (empty) | Required (`>= 32` characters) if `ALLOWED_HOSTS` includes any non-loopback address. |
| `ARTIFACTS_DIR` | `source/artifacts` | Directory for temporary uploads, JSON/CSV exports, and cache. |
| `RULES_DIR` | `source/rules` | Directory containing `*_rules.yaml` and `reference/*.yaml`. |

---

## 9. Usage Examples (Web UI, REST API, CLI, Python SDK)

### 9.1 Launching the Local Web Application
```bash
PYTHONPATH=source uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Open `http://127.0.0.1:8000` in your browser:
- **Analyze (`/`)**: Upload a QR image, review every decoded QR code and OCR-extracted context candidate (`Use`, `Edit`, or `Ignore`), optionally add manual context, and inspect the grouped evidence ledger and precautions. Export results as JSON or CSV.
- **Research Tests (`/research`)**: Validate the `QRS-Bench-Ind` dataset and run the `base`, `counterfactual`, `robustness`, or `all` evaluation suites with live progress tracking and HTML/CSV/JSON reports.
- **Settings (`/settings`)**: Inspect active rule/reference versions, test local OCR availability, and check Threat Intelligence configuration status.

### 9.2 REST API Examples

#### Analyze a Raw QR Payload with Context (`POST /api/v1/analyze-payload`)
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/analyze-payload \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "upi://pay?pa=merchant.refund@okaxis&pn=City%20Parking&am=500.00&cu=INR",
    "context": {
      "organization": "City Parking Authority",
      "purpose": "Pay parking fee",
      "amount": "50.00"
    },
    "ablation": "full",
    "threat_intel": false
  }' | python3 -m json.tool
```

#### Analyze an Uploaded QR Signage Image (`POST /api/v1/analyze`)
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/analyze \
  -F "image=@qrs_bench_ind/splits/test_locked/core_scenes/payment/test_locked_core_scenes_0185.png" \
  -F "use_unconfirmed_ocr=true" | python3 -m json.tool
```

#### Inspect Loaded Rules (`GET /api/v1/rules`)
```bash
curl -s http://127.0.0.1:8000/api/v1/rules | python3 -m json.tool
```

### 9.3 Command-Line Interface (`python3 -m evaluation`)

Run from the repository root with `PYTHONPATH=source`:

```bash
# 1. Inspect a single QR image end-to-end (outputs full AnalysisResult JSON)
PYTHONPATH=source python3 -m evaluation \
  --single-image qrs_bench_ind/splits/test_locked/core_scenes/url/test_locked_core_scenes_0001.png

# 2. Evaluate a batch of JSONL scenarios (black-box CLI mode)
PYTHONPATH=source python3 -m evaluation \
  --batch-jsonl release/evidence/redteam_208_scenarios.jsonl

# 3. Run QRShield's multi-pass QR decoder across a directory of degraded images
PYTHONPATH=source python3 -m evaluation \
  --decode-images-dir qrs_bench_ind/splits/test_locked/robustness_variants

# 4. Run the evaluation suite on QRS-Bench-Ind (base, counterfactual, robustness, or all)
PYTHONPATH=source python3 -m evaluation \
  --suite all \
  --dataset qrs_bench_ind \
  --output-dir /tmp/qrshield_eval_run
```

### 9.4 Python SDK Usage

```python
from pathlib import Path
from qrshield_core.config import Settings
from qrshield_core.models import Confidence, Context, ContextAttribute
from qrshield_core.pipeline import AnalysisConfig, QRShieldEngine

settings = Settings.from_env()
engine = QRShieldEngine(settings, use_default_ocr=False)

# 1. Payload + structured context analysis
ctx = Context(attributes=[
    ContextAttribute("organization", "Metro Cafe", "user_input", Confidence.HIGH),
    ContextAttribute("purpose", "Connect to guest Wi-Fi", "user_input", Confidence.HIGH),
    ContextAttribute("network", "MetroCafe-Guest", "user_input", Confidence.HIGH),
])
result = engine.analyze_payload(
    raw="WIFI:T:nopass;S:MetroCafe-Guest;;",
    context=ctx,
    config=AnalysisConfig("full", threat_intel_mode="off"),
)
print(result.assessment.level.value)  # "no_material_concern" (L0)

# 2. Full image preparation + OCR + analysis
img_bytes = Path("qrs_bench_ind/splits/test_locked/core_scenes/url/test_locked_core_scenes_0001.png").read_bytes()
prep = engine.prepare_image(img_bytes, filename="sample.png")
from qrshield_core.context.extract import build_context
auto_ctx = build_context(prep.candidates, decisions=None, manual=None, auto_use_unconfirmed=True)
img_result = engine.analyze_prepared(prep, qr_index=0, context=auto_ctx, config=AnalysisConfig("full"))
print(img_result.assessment.level.value, img_result.assessment.summary)
```

---

## 10. Security Considerations & Non-Execution Invariant

QRShield is designed to inspect untrusted, potentially malicious QR codes safely:

1. **Non-Execution Invariant (Hard Requirement)**:
   - `source/qrshield_core/` and `source/app/` contain **zero** calls to `webbrowser.open`, `os.system`, `subprocess.*`, `eval`, `exec`, `pickle.load`, or socket connection routines on decoded payloads.
   - Enforced continuously by:
     - AST static security gate (`tools/run_static_security.py`),
     - Monkeypatched network/execution prohibition tests (`source/tests/security/test_offline_non_execution.py` and `source/tests/security/test_security.py`), and
     - 100,000-input structure-aware fuzzer (`tools/run_fuzzer.py`).
2. **Image Decompression-Bomb & Parser Hardening**:
   - Strict pre-decode byte limit (`MAX_IMAGE_SIZE_MB=10`), pixel count ceiling (`MAX_IMAGE_PIXELS=40,000,000`), and dimension ceiling (`MAX_IMAGE_SIDE=4000`).
   - Images are verified via Pillow, converted to RGB, and re-encoded into fresh PNG bytes in memory to strip EXIF/metadata payloads before OpenCV or OCR processing.
3. **Web Application Defenses**:
   - Loopback-only binding by default (`127.0.0.1`), `TrustedHostMiddleware` against DNS rebinding, Same-Origin verification on state-changing HTTP methods, strict `Content-Security-Policy` (`default-src 'self'; object-src 'none'; frame-ancestors 'none'`), and mandatory 32+ character bearer/basic token authentication (`QRSHIELD_ACCESS_TOKEN`) if non-loopback hosts are configured.

See [`SECURITY.md`](SECURITY.md) and [`docs/SECURITY.md`](docs/SECURITY.md) for the complete threat model and vulnerability disclosure policy.

---

## 11. Testing & Verification Gate (`make verify`)

Run the complete test suite or the full release verification gate from the repository root:

```bash
# Run all 446 unit, integration, security, and evaluation tests via pytest
PYTHONPATH=source python3 -m pytest source/tests -q

# Run the complete 7-stage release verification gate
make verify
```

### What `make verify` Executes and Enforces

| Gate Target | Script | Verified Result (`release/evidence/`) |
| :--- | :--- | :--- |
| **`clean-tree`** | `tools/verify_clean_tree.py --clean` | `0` `__pycache__` dirs, `0` `.pyc` files, `0` retired/scratch dirs, all required root files present. |
| **`test`** | `tools/run_coverage.py` | **`446 passed, 0 failed`**; **`93.19%`** line coverage (`>= 90%` threshold) and **`80.65%`** branch coverage (`>= 80%` threshold) (`coverage_summary.json`). |
| **`mutation`** | `tools/run_mutation.py` | **`90.00%`** AST mutation score (`45 / 50` mutants killed across `decision/policy.py` and `matching/entity.py`, `>= 70%` threshold) (`mutation_summary.json`). |
| **`provenance`** | `tools/check_label_provenance.py` | Verifies `"provenance": "author_assigned"` across all `1,080` units and confirms zero synthetic dual-rater claims (`provenance_audit.json`). |
| **`spec-trace`** | `tools/generate_spec_trace.py` | **`100%`** bidirectional traceability across all `87` YAML rules (`12` `*_rules.yaml` files) and `17` decision rules (`R0`–`R10`, `R0a`–`R0f`) (`docs/SPEC_TRACE.md`). |
| **`security`** | `tools/run_static_security.py` | **`0` critical/high findings** across AST scan and Docker/Compose hardening checks (`static_security_summary.json`). |
| **`independent-validation`** | `tools/independent_validation.py` | Zero shared imports with `qrshield_core`; `< 1e-6` agreement with `scipy.stats` recomputation; **`100%` attack recall & `100%` benign specificity** on the external `208`-case red-team suite (`redteam_208_report.json`); independent decoder cross-check (`99.48%` QRShield multi-pass vs `89.06%` standalone multi-pass vs `69.27%` raw single-pass OpenCV, `100%` payload agreement) (`decoder_crosscheck.json`); `66 / 66` frozen engine SHA-256 hashes verified (`cleanroom_repro_report.json`). |

---

## 12. Benchmark Methodology & Evaluation (`QRS-Bench-Ind`)

### Dataset Design (`qrs_bench_ind/`)
`QRS-Bench-Ind` is a self-contained, multi-scheme contextual QR security benchmark containing **`1,080` evaluation units** and **`1,280` rendered PNG signage images** (`900x1180`) partitioned into strictly disjoint organization and visual template splits:

| Split | Units | Images | Organizations (`60` Total) | Visual Layouts (`28` Total) | Purpose |
| :--- | :---: | :---: | :--- | :--- | :--- |
| **`dev`** | `148` | `172` | `8` (`D01`–`D08`) | `4` (`T01`–`T04`) | Rule & threshold development |
| **`val`** | `156` | `180` | `12` (`V01`–`V12`) | `4` (`T05`–`T08`) | Pre-freeze calibration |
| **`test_locked`** | `776` | `928` | `40` (`N01`–`N40`, **100% unseen**) | `20` (`T09`–`T28`, **100% unseen**) | Unbiased held-out evaluation |
| **Total** | **`1,080`** | **`1,280`** | **`60` disjoint organizations** | **`28` signage layouts** | Full benchmark |

- **Zero Brand-List Overlap on `test_locked`**: None of the 40 `test_locked` organizations (`N01`–`N40`) appear in `source/rules/reference/brands.yaml`, testing true cross-modal context comparison rather than static allowlist lookup.
- **Multi-Script Coverage**: Includes English Latin (`latin_en`, `n=346`), bilingual Hindi Devanagari (`bilingual_devanagari`, `n=43`), and bilingual Japanese CJK (`bilingual_cjk`, `n=43`) in `test_locked`.
- **Label Provenance**: All ground-truth labels in `qrs_bench_ind/annotations/consensus_ground_truth.jsonl` carry `"provenance": "author_assigned"`, derived deterministically from scenario generation parameters prior to evaluation. A complete blind dual-rater human annotation export and ingestion workflow is provided in `tools/ingest_annotations.py` and `qrs_bench_ind/metadata/ANNOTATION_PROTOCOL.md`.

### Headline Locked-Test Results (`test_locked`, Frozen Engine `1.0.0`)

| Evaluation Stratum / Metric (`test_locked`) | Result (`QRShield 1.0.0`) | 95% Cluster Bootstrap CI (Org / Template) |
| :--- | :---: | :---: |
| **Core Scenes (`n=320`) Exact 4-Level Agreement** | **`100.00%`** (`320 / 320`) | `[1.0, 1.0]` / `[1.0, 1.0]` |
| **Core Scenes (`n=320`) Quadratic-Weighted $\kappa_w$ / Macro-F1** | **`1.0000`** / **`1.0000`** | — |
| **Combined Single-Image (`n=432`) Exact Agreement** | **`100.00%`** (`432 / 432`) | `[1.0, 1.0]` / `[1.0, 1.0]` |
| **Clean Benign (`SG1`, `n=112`) Any-Escalation FPR** | **`0.00%`** (`0 / 112`) | Specificity `100.00%` |
| **Challenge FP Traps (`n=56` legitimate edge cases) Over-Escalation** | **`0.00%`** (`0 / 56`) | True-Negative Resistance `100.00%` |
| **Challenge FN Traps (`n=56` obfuscated/evasive attacks) Evasion Rate** | **`0.00%`** (`0 / 56`) | Detection Recall `100.00%` |
| **Counterfactual Directional Sensitivity (`128` pairs)** | **`100.00%`** (`128 / 128`) | Context perturbation flips risk in expected direction |
| **Counterfactual Paraphrase Negative Controls (`24` pairs)** | **`100.00%`** (`24 / 24`) | Benign wording/layout paraphrase keeps verdict invariant |
| **Non-Trivial Photometric/Geometric Robustness (`R01`–`R11`, `176` imgs)** | **`99.43%`** (`175 / 176`) | All-12 conditions (`R00`–`R11`, `192` imgs): **`99.48%`** (`191 / 192`) |
| **End-to-End Runtime Latency (`928` `test_locked` images, CPU)** | **Median `54.51 ms`** | Mean `57.28 ms`, P95 `84.88 ms`, P99 `94.26 ms` |

### Baseline & Ablation Comparison (`test_locked`, `n=432` Combined Single-Image Units)

| System Configuration | Core (`n=320`) Exact | Combined (`n=432`) Exact | Macro-F1 (`n=432`) | Quadratic $\kappa_w$ | Exact McNemar $p$ vs Full (`Holm-Adjusted`) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`QRShield 1.0.0` (Full + TI)** | **`100.00%`** | **`100.00%`** | **`1.0000`** | **`1.0000`** | Reference |
| **`QRShield 1.0.0` (Full Local-Only, No TI)** | `92.50%` | `94.44%` | `0.8588` | `0.9718` | $p = 1.19 \times 10^{-7}$ ($p_{\text{Holm}} = 1.19 \times 10^{-7}$) |
| **`A3`: No Action Layer (`Payload + Context`)** | `82.50%` | `87.04%` | `0.7336` | `0.9032` | $p = 5.55 \times 10^{-17}$ ($p_{\text{Holm}} = 1.11 \times 10^{-16}$) |
| **`A1`: Payload-Only (`No Context, No Action`)** | `75.00%` | `72.22%` | `0.6290` | `0.6231` | $p = 1.51 \times 10^{-36}$ ($p_{\text{Holm}} = 4.52 \times 10^{-36}$) |
| **`B3`: Non-URL Scheme Heuristic Baseline** | `55.62%` | `51.62%` | `0.3413` | `0.4879` | $p = 2.66 \times 10^{-63}$ ($p_{\text{Holm}} = 1.06 \times 10^{-62}$) |
| **`B2`: Lexical + Regex Naive Context Baseline** | `41.56%` | `40.97%` | `0.2149` | `0.4090` | $p = 7.45 \times 10^{-77}$ ($p_{\text{Holm}} = 3.72 \times 10^{-76}$) |
| **`A2`: Context-Only (`No Payload Analyzer`)** | `40.00%` | `37.04%` | `0.1351` | `0.0000` | $p = 5.42 \times 10^{-82}$ ($p_{\text{Holm}} = 3.25 \times 10^{-81}$) |
| **`B1`: URL-Centric Quishing Heuristic Baseline** | `37.81%` | `36.34%` | `0.2683` | `0.2738` | $p = 6.77 \times 10^{-83}$ ($p_{\text{Holm}} = 4.74 \times 10^{-82}$) |

See [`docs/DATASET_DATASHEET.md`](docs/DATASET_DATASHEET.md), [`docs/TUNING_DISCLOSURE.md`](docs/TUNING_DISCLOSURE.md), and [`qrs_bench_ind/evaluation_runs/QRS_Bench_Ind_Evaluation_Report.md`](qrs_bench_ind/evaluation_runs/QRS_Bench_Ind_Evaluation_Report.md) for complete breakdowns.

---

## 13. Limitations & Scope Boundaries

In accordance with our commitment to transparent scientific reporting, note the following scope boundaries:
1. **No Live Network Page Inspection**: Because QRShield strictly enforces the non-execution invariant, it never fetches landing pages, executes client-side JavaScript redirects on remote servers, or inspects remote TLS certificates. A compromised legitimate domain hosting a phishing form at a benign-looking URL path cannot be detected from local syntax and signage context alone unless flagged by opt-in Threat Intelligence (`Layer 4`).
2. **Author-Assigned Ground Truth in `v1.0.0`**: While `QRS-Bench-Ind` provides a complete blind dual-rater annotation protocol (`qrs_bench_ind/metadata/ANNOTATION_PROTOCOL.md`) and full-schema ingestion pipeline (`tools/ingest_annotations.py`), the shipped `v1.0.0` labels are deterministically assigned from scenario construction rules (`"provenance": "author_assigned"`).
3. **Synthetic Rendered Signage**: `QRS-Bench-Ind` images are synthetically composed across `28` visual layouts (`T01`–`T28`) and `12` photometric/geometric perturbation conditions (`R00`–`R11`), including extreme combined curved-surface + glare + blur (`R11`, where 1 of 16 images fails QR finder-pattern localization). Field deployment on arbitrary camera hardware may encounter additional 3D occlusion or motion-blur modes.
4. **Heuristic Relational & Semantic Coverage**: Parent/DBA relationship extraction relies on visible disclosure phrases on the signage (`a division of`, `operated by`, `powered by`, `dba`) or entries in `source/rules/reference/brands.yaml` / `source/rules/reference/lists.yaml`. Undeclared corporate holding relationships without signage disclosure will be flagged as `L1` (`Needs Verification`).

---

## 14. Troubleshooting

| Symptom / Error | Root Cause | Resolution |
| :--- | :--- | :--- |
| `OCR engine is unavailable` in `/settings` or `/research` | The selected local OCR backend is not installed; PaddleOCR also downloads model files on first use. | Install the optional `ocr` extra and set `OCR_PROVIDER=paddleocr` (the default), or install Tesseract (`apt-get install tesseract-ocr`) and set `OCR_PROVIDER=tesseract`. |
| `403 Forbidden: remote_access_disabled` | Accessing the web server from a non-loopback IP while `ALLOWED_HOSTS` is loopback-only. | Keep access on `127.0.0.1`, or explicitly configure `ALLOWED_HOSTS` and a 32+ character `QRSHIELD_ACCESS_TOKEN`. |
| `422 Unprocessable Entity: select_qr` on `/api/v1/analyze` | Uploaded image contains multiple QR codes and `qr_index` was omitted. | Pass `-F "qr_index=0"` (or the desired index) so QRShield knows which QR code to analyze. |
| `ModuleNotFoundError: No module named 'qrshield_core'` | Running scripts outside `source/` without setting `PYTHONPATH=source` or installing the package. | Run `pip install -e .` or prefix commands with `PYTHONPATH=source`. |

---

## 15. Documentation Index

All technical, operational, and research documentation is organized under [`docs/`](docs/):

- **[`docs/INSTALLATION.md`](docs/INSTALLATION.md)**: System dependencies, virtual environments, hash-locked installs, Docker Compose, and air-gapped fallback setup.
- **[`docs/USER_GUIDE.md`](docs/USER_GUIDE.md)**: Step-by-step guide to the Web UI (`/`, `/research`, `/settings`), CLI commands, and interpreting `L0`–`L3` assessments.
- **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)**: Detailed 7-stage pipeline architecture, module inventory, context provenance state machine, and decision policy rules (`R0`–`R10`, `R0a`–`R0f`).
- **[`docs/API_REFERENCE.md`](docs/API_REFERENCE.md)**: Complete REST API, Web UI HTMX endpoints, request/response schemas, status codes, and Python SDK reference.
- **[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)**: Developer guide for running tests, coverage, mutation testing, fuzzing, authoring YAML rules, and maintaining the engine freeze manifest.
- **[`docs/SECURITY.md`](docs/SECURITY.md)**: Security architecture, non-execution guarantees, container hardening, and threat model.
- **[`docs/RULES_CARD.md`](docs/RULES_CARD.md)**: Reference catalog of all `87` declarative security rules across the 12 `source/rules/*_rules.yaml` files.
- **[`docs/SPEC_TRACE.md`](docs/SPEC_TRACE.md)**: Automated traceability matrix mapping every YAML rule and policy rule to its implementation module and test cases.
- **[`docs/DATASET_DATASHEET.md`](docs/DATASET_DATASHEET.md)**: Gebru et al. Datasheet for Datasets covering `QRS-Bench-Ind` (`1,080` units / `1,280` images).
- **[`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md)**: Exact commands, deterministic seeds, and artifact checksums to reproduce every benchmark and paper table.
- **[`docs/TUNING_DISCLOSURE.md`](docs/TUNING_DISCLOSURE.md)**: Pre-registration and split hygiene disclosure for Engine `1.0.0` vs `QRS-Bench-Ind`.

---

## 16. Contributing

Contributions that improve payload parsers, declarative security rules, OCR robustness, documentation, or benchmark coverage are welcome! Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request. All changes must preserve the **non-execution invariant** and pass `make verify` with zero regressions.

---

## 17. License

Released under the **MIT License**. See [`LICENSE`](LICENSE) for full license text.

---

## 18. Citation

If you use QRShield or the `QRS-Bench-Ind` benchmark in academic research, please cite:

```bibtex
@article{shinde2026qrshield,
  title   = {Beyond Quishing: Explainable Cross-Modal Context-Consistency Verification for Multi-Scheme QR Code Threats},
  author  = {Shinde, Abhijit R. and Jadhav, Soham R. and Patil, Omkar R. and Kadam, Yash A.},
  journal = {International Journal of Advance Multidisciplinary Research and Engineering Development (IJAMRED)},
  volume  = {1},
  number  = {4},
  year    = {2026}
}
```
