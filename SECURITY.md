# Security Policy (`SECURITY.md`)

## 1. Supported Versions

| Version | Supported | Notes |
| :--- | :---: | :--- |
| `1.0.x` | Yes | Current stable release (`qrshield-1.0.0`) |
| `< 1.0.0` | No | Pre-release development snapshots |

---

## 2. Reporting a Vulnerability

If you discover a security vulnerability in QRShield — especially any bypass of the **non-execution invariant**, an image parser / decompression-bomb vulnerability, an SSRF/CSRF/authentication bypass in the local FastAPI web server, or a severe false-negative evasion in the core analyzers — please report it responsibly:

1. **Do not open a public GitHub issue** for unpatched security vulnerabilities that could put users of the tool at risk.
2. Submit a private report via **GitHub Security Advisories** (`Security` tab $\rightarrow$ `Report a vulnerability`) or contact the maintainers listed in [`CITATION.cff`](CITATION.cff) with:
   - Affected component and file path (e.g., `source/qrshield_core/image/loader.py`, `source/app/main.py`).
   - Minimal proof-of-concept input (e.g., payload string, synthetic QR image, or HTTP request) and environment configuration.
   - Expected behavior vs. observed behavior and potential security impact.
3. We aim to acknowledge receipt within **72 hours**, provide an initial triage assessment within **7 days**, and release a verified patch with regression tests before public disclosure.

---

## 3. Core Security Invariants Enforced by QRShield

### 3.1 Strict Non-Execution Invariant
QRShield processes untrusted QR codes as passive data:
- **Zero Payload Execution**: Decoded URLs, Wi-Fi configurations, payment URIs, vCards, SMS/email templates, phone/USSD strings, and deep links are never opened, fetched, dialed, or passed to OS handlers.
- **Zero Unsolicited Network Calls**: Local analysis (`threat_intel_mode="off"`) makes zero outbound DNS or HTTP requests. External threat intelligence (`source/qrshield_core/threat_intel/service.py`) is strictly opt-in, applies only to `http://` and `https://` URLs, and transmits only the URL identifier to the configured VirusTotal v3 endpoint over HTTPS.
- **Zero Unsafe Code Execution or Deserialization**: Static AST scanning (`tools/run_static_security.py`) prohibits `eval()`, `exec()`, `os.system()`, `os.popen()`, `subprocess.*` (inside `qrshield_core/` and `app/`), `pickle.load()`, and `yaml.load()` without `SafeLoader`.

### 3.2 Input Bounds & Image Sanitization (`source/qrshield_core/image/loader.py`)
- Rejects uploads exceeding `MAX_IMAGE_SIZE_MB` (`10 MB` default), `MAX_IMAGE_PIXELS` (`40,000,000` pixels default), or `MAX_IMAGE_SIDE` (`4000 px` default) prior to full pixel allocation.
- Verifies image structure with Pillow, converts to RGB, and re-encodes a clean in-memory PNG to strip embedded EXIF/metadata payloads before passing pixel buffers to OpenCV or OCR engines.

### 3.3 Web Application & Container Hardening (`source/app/main.py`, `Dockerfile`, `docker-compose.yml`)
- **Loopback Binding by Default**: Binds to `127.0.0.1:8000` and rejects non-loopback peer connections unless `ALLOWED_HOSTS` explicitly includes a remote hostname **and** `QRSHIELD_ACCESS_TOKEN` is set to a secret of at least 32 characters (verified with constant-time `hmac.compare_digest`).
- **DNS-Rebinding & Cross-Origin Protection**: Enforces `TrustedHostMiddleware` and validates the `Origin` header on all `POST`, `PUT`, `PATCH`, and `DELETE` requests.
- **Path Traversal Prevention**: Strictly validates session/result/run IDs via regex (`ID_RE`, `RUN_ID_RE`) and `Path.resolve(strict=True).relative_to(...)` before serving any file from `artifacts/`.
- **Strict Response Headers**: Sets `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Permissions-Policy: camera=(), microphone=(), geolocation=()`.
- **Container Hardening**: Runs as non-root `USER qrshield` (`UID 10001`), mounts root filesystem `read_only: true`, drops all Linux capabilities (`cap_drop: ALL`), and sets `no-new-privileges: true`.

For additional architectural security details, see [`docs/SECURITY.md`](docs/SECURITY.md).
