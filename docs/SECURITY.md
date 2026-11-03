# Security Architecture & Threat Model (`docs/SECURITY.md`)

This document describes the security architecture, threat model, non-execution guarantees, input sanitization controls, and container hardening of **QRShield `1.0.0`**. For vulnerability reporting instructions, see the root [`SECURITY.md`](../SECURITY.md).

---

## 1. Threat Model

QRShield is an inspection tool designed to analyze **untrusted, potentially adversarial QR code images and payload strings**. We consider an adversary who crafts malicious QR codes or manipulated signage images to achieve one of two goals:
1. **End-User Deception (Quishing / Cross-Modal Tampering)**: Tricking a human user into visiting a credential phishing site, connecting to an Evil-Twin Wi-Fi network, sending money to an unauthorized UPI VPA or crypto wallet, dialing a USSD forwarding string, or transmitting an OTP/PIN via SMS or email.
2. **Analyzer Compromise (Attacking QRShield Itself)**: Supplying a malformed image (decompression bomb, corrupted header, EXIF payload), a pathological URI/regex input (ReDoS), a path-traversal filename, or a cross-origin request to compromise the machine or container running QRShield.

---

## 2. Non-Execution Invariant (`AC-4`)

QRShield's foundational security guarantee is that **inspecting a QR code never triggers the action encoded in the QR code**:

- **URLs & Deep Links**: Parsed strictly as strings via `urllib.parse.urlsplit` in `source/qrshield_core/normalizer/normalize.py`. Zero DNS resolution, socket connection, HTTP fetching, or headless browser rendering of decoded URLs occurs during local analysis.
- **Wi-Fi / Payment / Contact / SMS / Email / Phone**: Parsed syntactically; zero OS network, telephony, banking, or intent APIs exist anywhere in the codebase.
- **Continuous Verification**:
  - `source/tests/security/test_offline_non_execution.py` monkeypatches `socket.socket.connect`, `socket.create_connection`, `urllib.request.urlopen`, `http.client.HTTPConnection.connect`, `subprocess.Popen`, `os.system`, and `webbrowser.open` to raise `RuntimeError` during offline analysis across all 8 payload families.
  - `tools/run_static_security.py` performs an AST scan across all `60` Python files in `source/qrshield_core/` and `source/app/` to ensure zero calls to `eval()`, `exec()`, `os.system()`, `os.popen()`, `subprocess.*`, `pickle.load()`, or unsafe `yaml.load()`.

---

## 3. Image & Payload Sanitization Controls

- **Pre-Allocation Image Bounds (`source/qrshield_core/image/loader.py`)**:
  - Enforces `MAX_IMAGE_SIZE_MB = 10` (`10,485,760` bytes), `MAX_IMAGE_PIXELS = 40,000,000`, and `MAX_IMAGE_SIDE = 4000` before full pixel allocation, preventing decompression bombs (`Image.MAX_IMAGE_PIXELS` enforced).
  - Restricts image formats to `PNG`, `JPEG`, `WEBP`, `BMP`, and `GIF`.
  - Re-encodes validated RGB pixels into a fresh in-memory PNG buffer (`LoadedImage.png_bytes`), stripping all EXIF, XMP, ICC, and comment chunks before OpenCV or OCR engines touch the image.
- **Log Redaction (`source/qrshield_core/redaction.py`)**:
  - Automatically masks sensitive query parameters (`otp`, `pin`, `password`, `passcode`, `token`, `secret`, `key`, `cvv`, `auth`) and Wi-Fi passwords (`P:...;`) before writing application logs.
- **SSRF & Privacy Controls on Opt-In Threat Intelligence (`source/qrshield_core/threat_intel/service.py`)**:
  - External Threat Intelligence is **disabled** in all research/benchmark runs (`threat_intel_mode="off"`).
  - Even when enabled by the user (`threat_intel_mode="lookup"` or `"scan"`), URLs pointing to loopback, RFC1918 private networks, link-local addresses, or `.local`/`.internal` hosts are never sent to external providers.

---

## 4. Web Application & Container Hardening

- **Loopback-Only Default & Constant-Time Token Auth (`source/app/main.py`)**:
  - Rejects non-loopback peer connections (`403 Forbidden`) unless `ALLOWED_HOSTS` explicitly includes a remote hostname **and** `QRSHIELD_ACCESS_TOKEN` (`>= 32` chars) is validated via `hmac.compare_digest`.
- **DNS-Rebinding & CSRF Protection**:
  - Enforces Starlette `TrustedHostMiddleware` (`ALLOWED_HOSTS`) and checks that browser `Origin` headers match `Host` on all state-changing HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`).
- **Strict HTTP Security Headers**:
  - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
  - `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`.
- **Docker Container Hardening (`Dockerfile`, `docker-compose.yml`)**:
  - Non-root execution (`USER qrshield`, `UID/GID 10001:10001`), `read_only: true` root filesystem, `cap_drop: [ALL]`, `no-new-privileges: true`, `pids_limit: 256`, and loopback port binding (`127.0.0.1:8000:8000`).
