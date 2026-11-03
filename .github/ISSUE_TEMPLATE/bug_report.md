---
name: Bug Report
about: Report a bug in QRShield's decoder, OCR, analyzers, decision policy, Web UI, or CLI
title: "[BUG] "
labels: bug
assignees: ''
---

## Summary
A concise description of the bug and where it occurs (`qrshield_core`, `app`, `evaluation`, or `qrs_bench_ind`).

## Steps to Reproduce
1. Command or API endpoint invoked:
   ```bash
   # e.g., PYTHONPATH=source python3 -m evaluation --single-image ...
   ```
2. QR payload string or signage context attributes (sanitize any real personal data or secrets):
   - **Decoded Payload**: `...`
   - **Displayed Context (`organization`, `purpose`, `amount`, etc.)**: `...`

## Expected Behavior
What assessment level (`L0`–`L3`), indicator ID(s), or output did you expect?

## Actual Behavior
What assessment level, indicator ID(s), or error occurred instead?

## Environment
- **QRShield Version**: `1.0.0`
- **Python Version**: e.g., `3.11.14`
- **OS / Platform**: e.g., Ubuntu 22.04 / macOS / Docker
- **OCR Provider (`OCR_PROVIDER`)**: `tesseract` / `paddleocr` / `disabled`
