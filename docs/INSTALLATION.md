# Installation & Setup Guide (`docs/INSTALLATION.md`)

This guide covers installing and configuring **QRShield `1.0.0`** across local development environments, reproducible research setups, air-gapped machines, and hardened Docker containers.

---

## 1. System Requirements

### Supported Platforms & Python Versions
- **Operating Systems**: Linux (Ubuntu/Debian 22.04+ recommended), macOS 13+, or Windows 11 via WSL2.
- **Python**: `3.11` or `3.12` (tested continuously in CI via [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)).
- **Hardware**: Any modern x86_64 or ARM64 CPU with `>= 2 GB` RAM (`~55 ms` median per-image latency on CPU; no GPU required).

### System-Level Native Dependencies
QRShield uses **OpenCV** (`opencv-python-headless`) for multi-pass QR decoding and **Tesseract OCR** (`tesseract-ocr`) or **PaddleOCR** for local scene text extraction.

- **Ubuntu / Debian**:
  ```bash
  sudo apt-get update
  sudo apt-get install -y tesseract-ocr libgl1 libglib2.0-0 libgomp1
  ```
- **Fedora / RHEL**:
  ```bash
  sudo dnf install -y tesseract mesa-libGL glib2 libgomp
  ```
- **macOS (Homebrew)**:
  ```bash
  brew install tesseract
  ```

Verify that Tesseract is on your `PATH`:
```bash
tesseract --version
```

---

## 2. Python Environment Installation

### 2.1 Editable Development Installation (Recommended)
From the repository root:
```bash
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e ".[dev]"
```
This installs all core runtime dependencies (`fastapi`, `uvicorn`, `jinja2`, `python-multipart`, `pydantic`, `pyyaml`, `pillow`, `numpy`, `scipy`, `opencv-python-headless`, `pytesseract`) plus the development/verification suite (`pytest`, `coverage`, `mutmut`, `qrcode`, `httpx`, `ruff`, `python-docx`).

### 2.2 Optional Extras (PaddleOCR & ZXing-CPP)
To install optional deep-learning OCR (`paddleocr`) or the secondary `zxing-cpp` QR decoder:
```bash
pip install -e ".[dev,ocr,decoder]"
```
> **Note**: Install the optional `ocr` extra before using the default `OCR_PROVIDER=paddleocr`. For a lighter installation, set `OCR_PROVIDER=tesseract` and install the Tesseract executable. `OCR_PROVIDER=auto` tries PaddleOCR first, then Tesseract.

### 2.3 Hash-Locked Reproducible Installation (`requirements.lock`)
For strict cryptographic verification of every Python wheel (`AC-11`):
```bash
pip install --require-hashes -r requirements.lock
pip install --no-deps -e .
```

### 2.4 Air-Gapped / Offline Fallback Support
In restricted sandbox environments where `pytest` or `qrcode` wheels are not pre-installed on the host, [`source/sitecustomize.py`](../source/sitecustomize.py) automatically appends `tools/offline_fallback` to the end of `sys.path` (never shadowing host-installed packages).

---

## 3. Environment Configuration (`.env`)

Copy the root template [`.env.example`](../.env.example) to `source/.env` (or export variables directly in your shell):
```bash
cp .env.example source/.env
```
Key settings to verify for local use:
```ini
QRSHIELD_ENV=development
OCR_ENABLED=true
OCR_PROVIDER=paddleocr
THREAT_INTEL_ENABLED=false
LOAD_SYNTHETIC_REFERENCE=false
```

---

## 4. Hardened Docker & Docker Compose Setup

QRShield ships with a hardened root [`Dockerfile`](../Dockerfile) and [`docker-compose.yml`](../docker-compose.yml):
- Runs as unprivileged user `qrshield` (`UID 10001`).
- Enforces `read_only: true` root filesystem with an isolated `64M` `/tmp` tmpfs.
- Drops all Linux kernel capabilities (`cap_drop: ALL`) and sets `no-new-privileges: true`.
- Binds strictly to loopback (`127.0.0.1:8000:8000`).

Build and start the service:
```bash
docker compose up --build -d
curl -s http://127.0.0.1:8000/health
```
Expected response:
```json
{"status": "ok", "version": "1.0.0"}
```

---

## 5. Verifying Your Installation

Run the full verification gate from the repository root:
```bash
make verify
```
When all gates pass, you will see:
```text
==================================================================
QRShield 1.0.0: ALL VERIFICATION GATES PASSED (0)
==================================================================
```
