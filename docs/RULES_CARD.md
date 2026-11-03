# QRShield Rules & Decision Policy Card (`docs/RULES_CARD.md`)

This document summarizes the declarative security rule registry (`source/rules/*_rules.yaml`), reference registries (`source/rules/reference/*.yaml`), and ordinal decision policy (`source/qrshield_core/decision/policy.py`) in **QRShield `1.0.0`**.

For the complete machine-generated line-by-line mapping of every rule ID to its analyzer implementation and unit tests, see [`docs/SPEC_TRACE.md`](SPEC_TRACE.md).

---

## 1. Declarative Rule Files (`source/rules/*_rules.yaml`)

QRShield defines **`87` unique rule IDs** across **12 modular YAML files**:

| Rule File (`source/rules/`) | Rule ID Range / Count | Layer | Target Payload Families | Purpose |
| :--- | :--- | :---: | :--- | :--- |
| **`url_rules.yaml`** | `URL-001`..`URL-021` (`20` rules) | `payload` | `url` | Unencrypted HTTP login, public/private/obfuscated IP hosts, shorteners, brand lookalikes, embedded credentials, punycode/mixed-script homoglyphs, subdomain depth, query & `#fragment` open redirects, dangerous URI schemes. |
| **`context_rules.yaml`** | `CTX-001`..`CTX-014` (`14` rules) | `context` | All 8 families | Cross-modal mismatches across organization identity, payment recipient, destination domain, contact details, stated purpose, Wi-Fi SSID/security, displayed amount, app target, and insufficient context. |
| **`payment_rules.yaml`** | `PAY-001`..`PAY-011` (`10` rules) | `payload` | `payment` | Recipient identification, missing payee name, large amount thresholds, fixed vs open amount, ancillary URLs, unrecognized parameters, invalid VPA format, invalid EMVCo CRC checksum. |
| **`threat_intel_rules.yaml`** | `TI-001`..`TI-008` (`8` rules) | `threat_intel` | All families with URLs | External VirusTotal v3 multi-engine malicious hit (`TI-001`), suspicious/mixed report (`TI-002`), clean report (`TI-003`), no report (`TI-004`), disabled/unconfigured status (`TI-005`..`TI-008`). |
| **`deeplink_rules.yaml`** | `DL-001`..`DL-007` (`7` rules) | `payload` | `deep_link` | Unverified custom scheme, sensitive in-app operation (`grant_custody`, `linkdevice`, `export_seed`, etc.), sensitive parameters, excessive parameters, intent fallback URL, embedded `otpauth` secret, known app target. |
| **`text_rules.yaml`** | `TXT-001`..`TXT-006` (`6` rules) | `payload` | `plain_text` | Control characters, embedded URL/email/phone indicators, oversized payload, unrecognized action, call/USSD initiation (`TXT-005`), normalization fallback. |
| **`contact_rules.yaml`** | `CON-001`..`CON-005` (`5` rules) | `payload` | `contact` | Unrelated email/website domain vs vCard `ORG`, mismatched email and web domains, free email provider, invalid phone format. |
| **`wifi_rules.yaml`** | `WIFI-001`..`WIFI-005` (`5` rules) | `payload` | `wifi` | Open network (`nopass`), legacy `WEP` encryption, hidden SSID (`H:true`), embedded password exposure, malformed/unusual SSID. |
| **`comm_rules.yaml`** | `COM-001`..`COM-004` (`4` rules) | `payload` | `sms`, `email`, `contact`, `plain_text` | Outbound credential/OTP disclosure request (`COM-001`), financial/payment request (`COM-002`), personal identity request (`COM-003`), urgency/coercion language (`COM-004`). |
| **`email_rules.yaml`** | `EML-001`..`EML-004` (`4` rules) | `payload` | `email` | Multiple/hidden `cc`/`bcc` recipients, free email provider recipient, brand-lookalike recipient domain, malformed email address. |
| **`sms_rules.yaml`** | `SMS-001`..`SMS-003` (`3` rules) | `payload` | `sms` | Malformed/short-code SMS destination, multiple recipients, pre-filled message body. |
| **`action_rules.yaml`** | `ACT-001` (`1` rule) | `action` | All 8 families | Records calibrated action sensitivity (`low`, `medium`, `high`). |

---

## 2. Reference Data Registries (`source/rules/reference/`)

| File | Contents |
| :--- | :--- |
| **`brands.yaml`** | `26` curated production brand entries (official domains, UPI VPA handles, Wi-Fi SSID prefixes, and custom app schemes). |
| **`lists.yaml`** | `63` generic business descriptors, `20` legal corporate suffixes, `30` generic Wi-Fi tokens, `20` recognized third-party payment/booking/ticketing processors, `20` URL shorteners, `6` dynamic QR redirectors, `17` consumer email providers, and numeric thresholds (`INR: 10000`, `USD: 500`, `EUR: 500`, `GBP: 400`). |
| **`lexicon.yaml`** | Credential/OTP/PIN tokens, payment lure phrases, personal identity tokens, and urgency/coercion lexicons. |
| **`purposes.yaml`** | Purpose-to-payload compatibility matrix mapping stated signage intents (e.g., `menu`, `wifi`, `payment`, `contact`, `app_download`, `parking`, `support`) to expected vs incompatible payload types. |
| **`schemes.yaml`** | Known deep-link URI schemes (`upi`, `phonepe`, `gpay`, `paytmmp`, `whatsapp`, `tg`, `opentable`, `resy`, etc.), `42` sensitive operation tokens, and `45` sensitive query parameter tokens. |

---

## 3. Ordinal Decision Policy (`source/qrshield_core/decision/policy.py`)

The `decide()` function maps converged evidence across the 4 layers (`payload`, `context`, `action`, `threat_intel`) to a 4-level ordinal `AssessmentLevel` using **17 explicit rules**:
- **`L3` (`harmful_corroborated`)**: `R1` (confirmed external Threat Intelligence `TI-001`), `R2` (`STRONG` payload indicator corroborated by `STRONG` context mismatch).
- **`L2` (`high_concern`)**: `R2` (local uncorroborated variant when required), `R3` (`STRONG` payload indicator alone), `R4` (`STRONG` context mismatch on `MEDIUM`/`HIGH` sensitivity action), `R5` (`MEANINGFUL` payload + `MEANINGFUL` context mismatch), `R6` (`>= 2` `MEANINGFUL` payload indicators on a `HIGH` sensitivity action).
- **`L1` (`needs_verification`)**: `R6` (single `MEANINGFUL` payload indicator), `R7` (`STRONG`/`MEANINGFUL` context anomaly on low-sensitivity action), `R8` (suspicious/mixed Threat Intel `TI-002`), `R9` (multiple `WEAK` signals across independent families), `R10` (`WEAK` payload signal on `HIGH` sensitivity action), `R0a` (known third-party processor `CTX-011` without payload risk), `R0b` (URL shortener / dynamic QR `URL-003`), `R0c` (`WEAK` payload evidence on `MEDIUM` sensitivity action), `R0d` (unverified `HIGH` sensitivity action missing organization context), `R0e` (low OCR confidence or missing text on non-trivial action), `R0f` (combined `WEAK` payload + `WEAK` context signals).
- **`L0` (`no_material_concern`)**: `R0` (clean payload and consistent context, including context-verified open guest Wi-Fi at cafes/libraries/hotels).
