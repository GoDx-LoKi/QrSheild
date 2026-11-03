# QRShield Specification Traceability Matrix (`SPEC_TRACE.md`)

This machine-generated traceability matrix links every paper claim, architectural stage, YAML reference count, threshold, decision policy rule, and indicator code to its exact implementation in `source/qrshield_core/` and verification tests in `source/tests/` (`AC-9`, `F-05`, `F-06`).

## 1. Stage 1–7 Architecture Crosswalk (`F-05` Resolution)

| Paper Stage | Functional Responsibility | Implementation Module(s) | Verification Test Suite |
|---|---|---|---|
| **Stage 1** | Image Loader & Multi-Pass QR Decode | `qrshield_core/image/loader.py` (`load_image`) + `qrshield_core/decoder/qr.py` (`detect_and_decode`) | `source/tests/integration/test_pipeline.py` |
| **Stage 2** | Payload Classification & Canonical Normalization | `qrshield_core/classifier/classify.py` + `qrshield_core/normalizer/normalize.py` (`normalize`) | `source/tests/unit/test_normalizer.py` |
| **Stage 3** | Multi-Pass Scene OCR & Candidate Context Extraction | `qrshield_core/ocr/engine.py` (`run_ocr`) + `qrshield_core/context/extract.py` (`extract_candidates`) | `source/tests/unit/test_redaction_ocr_context.py` |
| **Stage 4** | Entity Normalization, Domain & Processor Relation Matching | `qrshield_core/matching/entity.py` (`Matcher`) + `qrshield_core/matching/domains.py` | `source/tests/unit/test_matching.py` |
| **Stage 5** | Family-Specific Structural & Semantic Payload Analysis (8 Analyzers) | `qrshield_core/analyzers/__init__.py` (`analyze_payload_security`) + `url.py`, `payment.py`, `wifi.py`, `contact.py`, `messaging.py` (SMS & Email/Call), `deeplink.py`, `text.py` | `source/tests/unit/test_analyzers.py` |
| **Stage 6** | Cross-Modal Context Consistency, Action Sensitivity & Threat Intel | `qrshield_core/context/consistency.py` (`ConsistencyEngine`) + `qrshield_core/action/sensitivity.py` (`assess_action`) + `qrshield_core/threat_intel/service.py` (`ThreatIntelService`) | `source/tests/unit/test_consistency.py`, `source/tests/unit/test_threat_intel.py` |
| **Stage 7** | Evidence Grouping, Constrained Decision Policy & Structured Explanation | `qrshield_core/evidence/grouping.py` (`group_evidence`) + `qrshield_core/decision/policy.py` (`decide`) + `qrshield_core/reporting/explain.py` (`build_explanation`) | `source/tests/unit/test_policy.py` |

## 2. Exact YAML Lexicon & Reference Counts (`F-06` Resolution)

| YAML Parameter / Lexicon | Source File | Exact Production Count | Notes |
|---|---|---|---|
| `entity_lexicon.generic_descriptors` | `source/rules/reference/lists.yaml` | `63` | Generic business/venue tokens excluded from distinctive org identity |
| `entity_lexicon.legal_suffixes` | `source/rules/reference/lists.yaml` | `20` | Corporate suffixes (`pvt`, `private`, `ltd`, `limited`, `llp`, `llc`, `inc`, etc.) |
| `entity_lexicon.wifi_generic` | `source/rules/reference/lists.yaml` | `30` | Generic Wi-Fi SSID tokens (`wifi`, `guest`, `free`, `public`, etc.) |
| `payment_processors` | `source/rules/reference/lists.yaml` | `20` | Recognized payment/form/ticketing processors |
| `shorteners.url_shortener` | `source/rules/reference/lists.yaml` | `20` | Public link shortener domains (`bit.ly`, `tinyurl.com`, etc.) |
| `shorteners.dynamic_qr_redirector` | `source/rules/reference/lists.yaml` | `6` | Production dynamic QR platforms (`qrco.de`, `qr.ae`, `l.ead.me`, `qrcodes.pro`, `scan.page`, `qrfy.com`); synthetic `go.example.invalid` isolated in `test_fixtures/` |
| `email_providers` | `source/rules/reference/lists.yaml` | `17` | Consumer webmail domains |
| `brands` (public registry) | `source/rules/reference/brands.yaml` | `26` | Production brand entries (synthetic `.example`/`.test` brands isolated in `source/rules/test_fixtures/brands_synthetic.yaml`) |
| Payload Family Analyzers | `source/qrshield_core/analyzers/` | `8` | 8 logical payload analyzers across `url.py`, `payment.py`, `wifi.py`, `contact.py`, `messaging.py` (SMS & Email/Call), `deeplink.py`, `text.py` |

## 3. Threshold Configuration (`source/rules/reference/lists.yaml::thresholds`)

```yaml
thresholds:
  large_amount:
    INR: 10000
    USD: 500
    EUR: 500
    GBP: 400
    default: 1000
  max_url_length: 1000
  max_payload_length: 2000
  max_query_params: 10
  max_subdomain_depth: 3
```

## 4. Decision Policy Rules (`R0`–`R10`, `R0a`–`R0f`)

| Rule ID | Condition Summary | Implementation Symbol | Output Level | Verification Test |
|---|---|---|---|---|
| **R1** | Confirmed External Threat Intel -> L3 | `decision/policy.py::decide` (Rule R1) | `high_risk_Indicators (L3)` | `source/tests/unit/test_policy.py` |
| **R2** | Strong Payload + Strong Context Mismatch (Corroborated -> L3, Local -> L2) | `decision/policy.py::decide` (Rule R2) | `L3 / L2` | `source/tests/unit/test_policy.py` |
| **R3** | Strong Payload Evidence Alone -> L2 | `decision/policy.py::decide` (Rule R3) | `suspicious (L2)` | `source/tests/unit/test_policy.py` |
| **R4** | Strong Context Mismatch + High/Medium Action Sensitivity -> L2 | `decision/policy.py::decide` (Rule R4) | `suspicious (L2)` | `source/tests/unit/test_policy.py` |
| **R5** | Moderate Payload + Moderate Context Mismatch -> L2 | `decision/policy.py::decide` (Rule R5) | `suspicious (L2)` | `source/tests/unit/test_policy.py` |
| **R6** | Moderate Payload + High Action Sensitivity (>=2 mod indicators) -> L2, else L1 | `decision/policy.py::decide` (Rule R6) | `L2 / L1` | `source/tests/unit/test_policy.py` |
| **R7** | Strong/Moderate Context Anomaly -> L1 | `decision/policy.py::decide` (Rule R7) | `verify_before_proceeding (L1)` | `source/tests/unit/test_policy.py` |
| **R8** | Suspicious/Mixed Threat Intel -> L1/L2 | `decision/policy.py::decide` (Rule R8) | `L1 / L2` | `source/tests/unit/test_policy.py` |
| **R9** | Multiple Weak Signals across Independent Families -> L1 | `decision/policy.py::decide` (Rule R9) | `verify_before_proceeding (L1)` | `source/tests/unit/test_policy.py` |
| **R10** | Weak Payload Signal + High Action Sensitivity -> L1 | `decision/policy.py::decide` (Rule R10) | `verify_before_proceeding (L1)` | `source/tests/unit/test_policy.py` |
| **R0a** | Known Third-Party Processor without Payload Risk -> L1 | `decision/policy.py::decide` (Rule R0a) | `verify_before_proceeding (L1)` | `source/tests/unit/test_policy.py` |
| **R0b** | Dynamic QR / URL Shortener -> L1 | `decision/policy.py::decide` (Rule R0b) | `verify_before_proceeding (L1)` | `source/tests/unit/test_policy.py` |
| **R0c** | Weak Payload Evidence + Medium Action Sensitivity -> L1 | `decision/policy.py::decide` (Rule R0c) | `verify_before_proceeding (L1)` | `source/tests/unit/test_policy.py` |
| **R0d** | Unverified High-Sensitivity Action (Missing Org Context) -> L1 | `decision/policy.py::decide` (Rule R0d) | `verify_before_proceeding (L1)` | `source/tests/unit/test_policy.py` |
| **R0e** | Low OCR Confidence / No Text on Non-Trivial Action -> L1 | `decision/policy.py::decide` (Rule R0e) | `verify_before_proceeding (L1)` | `source/tests/unit/test_policy.py` |
| **R0f** | Combined Weak Payload + Weak Context Signals -> L1 | `decision/policy.py::decide` (Rule R0f) | `verify_before_proceeding (L1)` | `source/tests/unit/test_policy.py` |
| **R0** | Clean Payload & Consistent Context -> L0 | `decision/policy.py::decide` (Rule R0) | `low_risk (L0)` | `source/tests/unit/test_policy.py` |

## 5. Indicator Rule Registry (87 Unique Rule IDs across `source/rules/*_rules.yaml`)

| Rule ID | Rule File | Strength | Category | Title | Positive Test Suite | Negative Test Suite |
|---|---|---|---|---|---|---|
| `ACT-001` | `source/rules/action_rules.yaml` | `` | `action` | Action sensitivity | `source/tests/unit/test_policy.py` | `source/tests/unit/test_analyzers.py` |
| `COM-001` | `source/rules/comm_rules.yaml` | `` | `sensitive_request` | Request to disclose a credential or one-time code | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `COM-002` | `source/rules/comm_rules.yaml` | `` | `sensitive_request` | Request for payment or financial details | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `COM-003` | `source/rules/comm_rules.yaml` | `` | `sensitive_request` | Request for personal identity information | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `COM-004` | `source/rules/comm_rules.yaml` | `` | `social_engineering` | Urgency or pressure language | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `CON-001` | `source/rules/contact_rules.yaml` | `` | `identity_consistency` | Email domain unrelated to stated organisation | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_policy.py` |
| `CON-002` | `source/rules/contact_rules.yaml` | `` | `identity_consistency` | Website domain unrelated to stated organisation | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_policy.py` |
| `CON-003` | `source/rules/contact_rules.yaml` | `` | `identity_consistency` | Email and website domains differ | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_policy.py` |
| `CON-004` | `source/rules/contact_rules.yaml` | `` | `identity_consistency` | Free email provider used | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_policy.py` |
| `CON-005` | `source/rules/contact_rules.yaml` | `` | `structure` | Phone number format invalid | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_policy.py` |
| `CTX-001` | `source/rules/context_rules.yaml` | `` | `context_consistency` | Identity mismatch | `source/tests/unit/test_consistency.py` | `source/tests/unit/test_matching.py` |
| `CTX-002` | `source/rules/context_rules.yaml` | `` | `context_consistency` | Payment recipient does not match the displayed business | `source/tests/unit/test_consistency.py` | `source/tests/unit/test_matching.py` |
| `CTX-003` | `source/rules/context_rules.yaml` | `` | `context_consistency` | Destination domain does not correspond to the identified organisation | `source/tests/unit/test_consistency.py` | `source/tests/unit/test_matching.py` |
| `CTX-004` | `source/rules/context_rules.yaml` | `` | `context_consistency` | Contact destination does not correspond to the identified organisation | `source/tests/unit/test_consistency.py` | `source/tests/unit/test_matching.py` |
| `CTX-005` | `source/rules/context_rules.yaml` | `` | `context_consistency` | Action does not fit the stated purpose | `source/tests/unit/test_consistency.py` | `source/tests/unit/test_matching.py` |
| `CTX-006` | `source/rules/context_rules.yaml` | `` | `context_consistency` | Wi-Fi network name does not match the venue | `source/tests/unit/test_consistency.py` | `source/tests/unit/test_matching.py` |
| `CTX-007` | `source/rules/context_rules.yaml` | `` | `context_consistency` | Amount differs from displayed amount | `source/tests/unit/test_consistency.py` | `source/tests/unit/test_matching.py` |
| `CTX-008` | `source/rules/context_rules.yaml` | `` | `context_consistency` | Application target does not match the identified service | `source/tests/unit/test_consistency.py` | `source/tests/unit/test_matching.py` |
| `CTX-009` | `source/rules/context_rules.yaml` | `` | `context_consistency` | Payment payload where money is expected to be received | `source/tests/unit/test_consistency.py` | `source/tests/unit/test_matching.py` |
| `CTX-010` | `source/rules/context_rules.yaml` | `` | `context_consistency` | Message destination differs from the contact shown | `source/tests/unit/test_consistency.py` | `source/tests/unit/test_matching.py` |
| `CTX-011` | `source/rules/context_rules.yaml` | `` | `context_consistency` | Identity relationship ambiguous | `source/tests/unit/test_consistency.py` | `source/tests/unit/test_matching.py` |
| `CTX-012` | `source/rules/context_rules.yaml` | `` | `context_consistency` | Insufficient context | `source/tests/unit/test_consistency.py` | `source/tests/unit/test_matching.py` |
| `CTX-013` | `source/rules/context_rules.yaml` | `` | `context_consistency` | Network security does not fit the described network | `source/tests/unit/test_consistency.py` | `source/tests/unit/test_matching.py` |
| `CTX-014` | `source/rules/context_rules.yaml` | `` | `context_consistency` | Credentials for an internal network in a public context | `source/tests/unit/test_consistency.py` | `source/tests/unit/test_matching.py` |
| `DL-001` | `source/rules/deeplink_rules.yaml` | `` | `application` | Unverified custom URI scheme | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_policy.py` |
| `DL-002` | `source/rules/deeplink_rules.yaml` | `` | `operation` | Link requests a sensitive in-app operation | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_policy.py` |
| `DL-003` | `source/rules/deeplink_rules.yaml` | `` | `parameters` | Sensitive parameters in deep link | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_policy.py` |
| `DL-004` | `source/rules/deeplink_rules.yaml` | `` | `parameters` | Excessive parameters | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_policy.py` |
| `DL-005` | `source/rules/deeplink_rules.yaml` | `` | `operation` | Intent with browser fallback URL | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_policy.py` |
| `DL-006` | `source/rules/deeplink_rules.yaml` | `` | `parameters` | Authenticator secret embedded | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_policy.py` |
| `DL-007` | `source/rules/deeplink_rules.yaml` | `` | `application` | Known application target | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_policy.py` |
| `EML-001` | `source/rules/email_rules.yaml` | `` | `structure` | Multiple or hidden email recipients | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `EML-002` | `source/rules/email_rules.yaml` | `` | `identity_consistency` | Free email provider recipient | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `EML-003` | `source/rules/email_rules.yaml` | `` | `host` | Recipient domain resembles a known brand | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `EML-004` | `source/rules/email_rules.yaml` | `` | `structure` | Malformed email recipient | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `PAY-001` | `source/rules/payment_rules.yaml` | `` | `recipient` | Payment recipient identified | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `PAY-002` | `source/rules/payment_rules.yaml` | `` | `recipient` | Payee display name missing | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `PAY-003` | `source/rules/payment_rules.yaml` | `` | `amount` | Unusually large amount | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `PAY-004` | `source/rules/payment_rules.yaml` | `` | `amount` | Fixed amount encoded | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `PAY-005` | `source/rules/payment_rules.yaml` | `` | `destination` | Ancillary URL present | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `PAY-006` | `source/rules/payment_rules.yaml` | `` | `structure` | Unrecognised payment parameters | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `PAY-007` | `source/rules/payment_rules.yaml` | `` | `structure` | Recipient identifier format invalid | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `PAY-008` | `source/rules/payment_rules.yaml` | `` | `integrity` | Payment payload checksum invalid | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `PAY-010` | `source/rules/payment_rules.yaml` | `` | `amount` | Non-positive amount | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `PAY-011` | `source/rules/payment_rules.yaml` | `` | `amount` | Amount not fixed by the QR code | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `SMS-001` | `source/rules/sms_rules.yaml` | `` | `structure` | Malformed SMS destination | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `SMS-002` | `source/rules/sms_rules.yaml` | `` | `structure` | Multiple SMS recipients | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `SMS-003` | `source/rules/sms_rules.yaml` | `` | `structure` | Pre-filled message body | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `TXT-001` | `source/rules/text_rules.yaml` | `` | `structure` | Hidden or control characters present | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `TXT-002` | `source/rules/text_rules.yaml` | `` | `structure` | Embedded indicator found in text | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `TXT-003` | `source/rules/text_rules.yaml` | `` | `structure` | Oversized payload | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `TXT-004` | `source/rules/text_rules.yaml` | `` | `classification` | Payload not recognised as a supported action | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `TXT-005` | `source/rules/text_rules.yaml` | `` | `classification` | Call-initiation URI | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `TXT-006` | `source/rules/text_rules.yaml` | `` | `classification` | Payload could not be safely normalised | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `TI-001` | `source/rules/threat_intel_rules.yaml` | `` | `threat_intelligence` | External provider reports multiple malicious detections | `source/tests/unit/test_threat_intel.py` | `source/tests/security/test_offline_non_execution.py` |
| `TI-002` | `source/rules/threat_intel_rules.yaml` | `` | `threat_intelligence` | External provider report is suspicious or mixed | `source/tests/unit/test_threat_intel.py` | `source/tests/security/test_offline_non_execution.py` |
| `TI-003` | `source/rules/threat_intel_rules.yaml` | `` | `threat_intelligence` | Existing report shows no malicious detections | `source/tests/unit/test_threat_intel.py` | `source/tests/security/test_offline_non_execution.py` |
| `TI-004` | `source/rules/threat_intel_rules.yaml` | `` | `threat_intelligence` | No existing external report | `source/tests/unit/test_threat_intel.py` | `source/tests/security/test_offline_non_execution.py` |
| `TI-005` | `source/rules/threat_intel_rules.yaml` | `` | `threat_intelligence` | External corroboration unavailable | `source/tests/unit/test_threat_intel.py` | `source/tests/security/test_offline_non_execution.py` |
| `TI-006` | `source/rules/threat_intel_rules.yaml` | `` | `threat_intelligence` | External lookup not performed | `source/tests/unit/test_threat_intel.py` | `source/tests/security/test_offline_non_execution.py` |
| `TI-007` | `source/rules/threat_intel_rules.yaml` | `` | `threat_intelligence` | External provider rate limited | `source/tests/unit/test_threat_intel.py` | `source/tests/security/test_offline_non_execution.py` |
| `TI-008` | `source/rules/threat_intel_rules.yaml` | `` | `threat_intelligence` | External provider authentication failure | `source/tests/unit/test_threat_intel.py` | `source/tests/security/test_offline_non_execution.py` |
| `URL-001` | `source/rules/url_rules.yaml` | `` | `transport` | Unencrypted transport (HTTP) | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-002` | `source/rules/url_rules.yaml` | `` | `host` | Public IP address used as host | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-003` | `source/rules/url_rules.yaml` | `` | `host` | URL shortener or redirection service | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-004` | `source/rules/url_rules.yaml` | `` | `host` | Lookalike of a known brand domain | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-005` | `source/rules/url_rules.yaml` | `` | `host` | Brand name embedded in a different domain | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-006` | `source/rules/url_rules.yaml` | `` | `query` | Credential-like query parameter | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-007` | `source/rules/url_rules.yaml` | `` | `host` | Credentials embedded in URL | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-008` | `source/rules/url_rules.yaml` | `` | `host` | Internationalised (punycode) host | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-009` | `source/rules/url_rules.yaml` | `` | `host` | Mixed scripts in host label | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-010` | `source/rules/url_rules.yaml` | `` | `host` | Excessive subdomain depth | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-011` | `source/rules/url_rules.yaml` | `` | `path` | Path suggests login | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-012` | `source/rules/url_rules.yaml` | `` | `query` | Excessive or encoded parameters | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-013` | `source/rules/url_rules.yaml` | `` | `transport` | Dangerous or script URI scheme | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-014` | `source/rules/url_rules.yaml` | `` | `host` | Non-standard port | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-015` | `source/rules/url_rules.yaml` | `` | `transport` | Scheme missing | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-016` | `source/rules/url_rules.yaml` | `` | `query` | Embedded redirect parameter | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-017` | `source/rules/url_rules.yaml` | `` | `structure` | Very long URL | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-018` | `source/rules/url_rules.yaml` | `` | `host` | Private or special-purpose host | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-019` | `source/rules/url_rules.yaml` | `` | `host` | Obfuscated numeric IP host | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `URL-021` | `source/rules/url_rules.yaml` | `` | `transport` | Non-web URI scheme | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `WIFI-001` | `source/rules/wifi_rules.yaml` | `` | `network_security` | Open network (no authentication) | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `WIFI-002` | `source/rules/wifi_rules.yaml` | `` | `network_security` | Weak or legacy encryption | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `WIFI-003` | `source/rules/wifi_rules.yaml` | `` | `network_security` | Hidden network | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `WIFI-004` | `source/rules/wifi_rules.yaml` | `` | `credential_exposure` | Password embedded in QR payload | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
| `WIFI-005` | `source/rules/wifi_rules.yaml` | `` | `structure` | Malformed or unusual SSID | `source/tests/unit/test_analyzers.py` | `source/tests/unit/test_normalizer.py` |
