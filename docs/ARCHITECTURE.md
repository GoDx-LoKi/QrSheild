# System Architecture (`docs/ARCHITECTURE.md`)

This document details the internal architecture, module boundaries, data flow, context provenance state machine, relational entity matcher, and ordinal decision policy of **QRShield `1.0.0`**.

---

## 1. Architectural Principles

1. **Strict Separation of Core Engine and Presentation Layers**:
   - All security logic resides in `source/qrshield_core/` (pure Python domain engine with zero web framework dependencies).
   - `source/app/` (FastAPI + Jinja2 + HTMX) and `source/evaluation/` (benchmark runner & CLI) are thin callers of `QRShieldEngine`.
2. **Passive Data-Only Processing (Non-Execution Invariant)**:
   - Every decoded string is parsed strictly as passive text/URI structures. No network sockets, DNS resolvers, browser engines, or OS intent handlers are ever invoked on decoded payloads during local analysis.
3. **Declarative Rule & Reference Separation**:
   - All `87` security indicators (`source/rules/*_rules.yaml`) and reference registries (`source/rules/reference/*.yaml`) are loaded and validated at startup by `RuleRegistry` and `ReferenceData` (`source/qrshield_core/rules.py`).

---

## 2. Seven-Stage Pipeline Walkthrough

### Stage 1: Safe Image Loading & Multi-Pass QR Decoding
- **Image Loader (`source/qrshield_core/image/loader.py`)**:
  - Enforces byte size (`max_bytes = 10 MB`), pixel count (`max_pixels = 40,000,000`), and side length (`max_side = 4000 px`) ceilings before decoding pixel buffers.
  - Verifies image integrity with Pillow, converts to RGB, and re-encodes a clean in-memory PNG (`LoadedImage.png_bytes`) to strip EXIF/metadata payloads.
- **Multi-Pass QR Decoder (`source/qrshield_core/decoder/qr.py`)**:
  - Runs up to **10 preprocessing passes** (`original`, `grayscale`, `upscale_2x`, `otsu_threshold`, `adaptive_threshold`, `clahe`, `sharpen`, `morph_close`, `rotate_90/180/270`, and `crop_border_15pct`) using OpenCV `QRCodeDetector` (`detectAndDecodeMulti` + `detectAndDecode` + `detectAndDecodeCurved`) and optional `zxing-cpp` fallback.
  - Records bounding polygon points (`bbox`) and the exact pass name (`preprocess_used`) that decoded each QR code.

### Stage 2: Scheme Classification & Canonical Payload Normalization
- **Classifier (`source/qrshield_core/classifier/classify.py`)** & **Normalizer (`source/qrshield_core/normalizer/normalize.py`)**:
  - Strips invisible control characters while recording their presence (`has_control_chars`), performs bounded percent-decoding, normalizes IDNA punycode hostnames, and classifies payloads into 8 families (`url`, `wifi`, `payment`, `contact`, `sms`, `email`, `deep_link`, `plain_text`).
  - Extracts structured fields into `NormalizedPayload.fields`:
    - **URLs**: `scheme`, `host`, `AsciiHost`, `UnicodeHost`, `etld1`, `subdomain`, `port`, `userinfo`, `path`, `query_params`, `redirect_targets` (from both query params and `#redirect=` / `#url=` / `#next=` / `#continue=` client-side fragments), `is_ip`, `is_private_ip`, `is_shortener`, `is_dynamic_qr`, `script_profile`.
    - **Wi-Fi**: `auth` (`WPA`/`WPA2`/`WPA3`/`WEP`/`nopass`), `ssid`, `password_present`, `hidden`, `eap_method`, `phase2`, `anon_identity`.
    - **Payments**: `scheme` (`upi`, `emvco`, `crypto`, `payto`), `payee_address` (VPA or wallet address), `payee_name`, `amount`, `currency`, `reference_url`, `crc_valid`.
    - **Contacts / SMS / Email / Deep Links**: structured recipients, subjects, bodies, embedded URLs, operation paths, and query keys.

### Stage 3: QR-Masked Local OCR & Candidate Context Extraction
- **Two-Pass Illumination-Normalized OCR (`source/qrshield_core/ocr/engine.py`)**:
  - Masks the detected QR code bounding box (with padding) to prevent QR finder patterns from generating garbage OCR tokens.
  - **Pass 1**: Runs local `Tesseract` (`--oem 3 --psm 6`) or `PaddleOCR` on the masked scene image.
  - **Pass 2 (Illumination-Normalized Fallback)**: Triggered automatically when Pass 1 yields `< 2` valid text blocks or mean confidence `< 0.72`. Estimates uneven background illumination via $\sigma=35$ Gaussian blur, normalizes via `cv2.divide(gray, bg, scale=255)`, denoises (`cv2.fastNlMeansDenoising`), and applies Otsu thresholding before re-running OCR and merging unique blocks.
- **Candidate Context Extractor (`source/qrshield_core/context/extract.py`, `source/qrshield_core/context/purpose.py`)**:
  - Parses OCR blocks into typed `ContextCandidate` records for `organization`, `organization_secondary` (parent/DBA/operator disclosures such as `"a division of ..."`, `"operated by ..."`, `"powered by ..."`, `"dba ..."`), `purpose`, `amount`, `domain`, `email`, `phone`, `network` (SSID), and `context_type`.

### Stage 4: Relational, Acronym & Processor Entity Matching
- **Entity Matcher (`source/qrshield_core/matching/entity.py`, `source/qrshield_core/matching/domains.py`)**:
  - Normalizes legal suffixes (`Pvt Ltd`, `LLC`, `Inc`, `Corp`) and generic descriptors (`cafe`, `hotel`, `clinic`, `bank`).
  - Evaluates identity alignment across five mechanisms:
    1. **Known Brand Registry Match** (`source/rules/reference/brands.yaml`): exact domain, VPA handle, SSID prefix, or deep-link scheme match against a registered brand, plus lookalike detection (Levenshtein edit distance `<= 2` or skeleton homoglyph match).
    2. **Direct Token & Contiguous Stem Match**: distinctive organization tokens appearing in the registrable domain (`eTLD+1`), VPA local-part, or SSID.
    3. **Multi-Token Acronym Match**: initials of `>= 2` distinctive organization tokens matching the domain prefix or hyphenated stem (e.g., `"Northstar Regional Transit"` $\rightarrow$ `nrt-transit.org`, `"Harborview Bay Group"` $\rightarrow$ `hb-group.com`).
    4. **Secondary / Parent / DBA Match**: matches against `organization_secondary` extracted from signage footer disclosures.
    5. **Known Third-Party Processor Delegation** (`source/rules/reference/lists.yaml::payment_processors`): recognizes legitimate payment, ticketing, form, and scheduling processors (`razorpay.com`, `stripe.com`, `paytm.com`, `Eventbrite`, `Toast`, `OpenTable`, etc.) and returns `MatchKind.KNOWN_PROCESSOR` so policy rule `R0a` can surface a calibrated `L1` verification notice rather than a false `L2` impersonation alarm.

### Stage 5: Family-Specific Intrinsic Payload Security Analyzers
- Located in `source/qrshield_core/analyzers/`:
  - `url.py`: Evaluates `URL-001`..`URL-021`, including recursive inspection of embedded redirect targets in query strings and URL `#fragments`.
  - `payment.py`: Evaluates `PAY-001`..`PAY-011`, including VPA local-part token-stuffing inspection (detecting suspicious suffixes like `.refund`, `.verify`, `.claim`, `.mule`, `.personal` appended to merchant names).
  - `wifi.py`: Evaluates `WIFI-001`..`WIFI-005` (`open` network, `WEP`, hidden SSID, embedded password).
  - `contact.py`: Evaluates `CON-001`..`CON-005` and inspects `NOTE` fields for social-engineering lures (`COM-001`..`COM-004`).
  - `messaging.py`: Evaluates `SMS-001`..`SMS-003`, `EML-001`..`EML-004`, `TXT-005` (USSD / call initiation), and semantic credential disclosure (`COM-001`..`COM-004`).
  - `deeplink.py`: Evaluates `DL-001`..`DL-007` across `42` sensitive operations and `45` sensitive parameter tokens (`source/rules/reference/schemes.yaml`) plus embedded callback URLs.
  - `text.py`: Evaluates `TXT-001`..`TXT-006` and embedded URLs/phones/credential requests.
  - `common.py`: Implements `request_evidence()` with outbound secret-disclosure syntax patterns, negation window filtering (`"never share your OTP"`), and benign physical-access context suppression (`"guest Wi-Fi password"`, `"reading club passcode"`, `"terminal PIN"`).

### Stage 6: Cross-Modal Context Consistency, Action Sensitivity & Threat Intel
- **Consistency Engine (`source/qrshield_core/context/consistency.py`)**:
  - Evaluates `CTX-001`..`CTX-014` by comparing extracted signage attributes (`organization`, `purpose`, `amount`, `domain`, `email`, `phone`, `network`) against the normalized payload fields.
  - Tracks **Context Provenance** (`complete`, `partial`, `missing`, `unconfirmed_ocr`, `ocr_unavailable`) so missing or degraded OCR never silently downgrades a medium/high-sensitivity action to `L0`.
- **Action Sensitivity (`source/qrshield_core/action/sensitivity.py`)**:
  - Assigns `ActionSensitivity.LOW`, `MEDIUM`, or `HIGH` and emits `ACT-001`.
- **Threat Intelligence Service (`source/qrshield_core/threat_intel/service.py`)**:
  - Extracts up to `MAX_URLS = 5` candidate HTTP/HTTPS URLs from any payload family (including URLs embedded in SMS/email bodies, vCards, payment `url=` params, or deep-link callbacks) and queries VirusTotal v3 (`TI-001`..`TI-008`) when explicitly enabled.

### Stage 7: Evidence Grouping & Constrained Ordinal Decision Policy
- **Evidence Grouping (`source/qrshield_core/evidence/grouping.py`)**:
  - Deduplicates findings by `(indicator_id, observed_value)` and organizes them into 8 `EvidenceFamily` buckets.
- **Decision Policy (`source/qrshield_core/decision/policy.py`)**:
  - Evaluates deterministic rules `R1`..`R10`, `R0a`..`R0f`, and `R0` in strict priority order to produce an `Assessment` (`level`, `label`, `firing_rule`, `summary`, `precautions`, `contributing_indicators`).
