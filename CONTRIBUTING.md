# Contributing to QRShield

Thank you for your interest in contributing to **QRShield**! This document outlines the engineering invariants, workflow, coding conventions, and verification gates required for all contributions.

---

## 1. Non-Negotiable Engineering Invariants

Before writing code or modifying rules, please review the project's core invariants:

1. **Strict Non-Execution Invariant**:
   - QRShield must **never** open, fetch, resolve, join, pay, send, call, or launch any decoded QR payload during local analysis.
   - `source/qrshield_core/` and `source/app/` must never import or invoke `subprocess`, `os.system`, `webbrowser`, `eval`, `exec`, `pickle.load`, or raw network sockets on decoded payload strings.
2. **Explainable, Rule-Backed Verdicts**:
   - Every security finding (`EvidenceItem`) must map to a declared rule ID in `source/rules/*_rules.yaml` (`87` unique rule IDs across 12 YAML files) with an explicit `severity`, `family`, `observed_value`, `expected_value`, `explanation`, and `remediation`.
   - Every assessment level (`L0`–`L3`) must be produced by an explicit policy rule (`R0`–`R10`, `R0a`–`R0f`) in `source/qrshield_core/decision/policy.py`.
3. **Zero Benchmark Label Leakage**:
   - Never tune rules, thresholds, brand registries (`source/rules/reference/brands.yaml`), processor registries (`source/rules/reference/lists.yaml`), or lexicons (`source/rules/reference/lexicon.yaml`) using organizations (`N01`–`N40`) or templates (`T09`–`T28`) from the held-out `qrs_bench_ind/splits/test_locked/` split.
   - Any change to `source/qrshield_core/**/*.py` or `source/rules/**/*.yaml` after an engine freeze requires bumping the engine version, updating `docs/TUNING_DISCLOSURE.md`, and regenerating the freeze manifest (`qrs_bench_ind/evaluation_runs/engine_freeze_manifest.json`).
4. **Fixture Isolation**:
   - Synthetic test brands and reserved `.example` / `.test` fixtures belong strictly in `source/rules/test_fixtures/brands_synthetic.yaml` and must never be enabled by default (`LOAD_SYNTHETIC_REFERENCE=false`).

---

## 2. Development Setup

1. Clone the repository and create a Python `3.11+` virtual environment:
   ```bash
   git clone https://github.com/qrshield/qrshield.git
   cd qrshield
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -e ".[dev]"
   ```
2. Install system dependencies (`tesseract-ocr` and `libgl1`):
   ```bash
   # Ubuntu / Debian
   sudo apt-get update && sudo apt-get install -y tesseract-ocr libgl1
   ```
3. Run the test suite to confirm your environment is ready:
   ```bash
   PYTHONPATH=source python3 -m pytest source/tests -q
   ```

---

## 3. Adding or Updating a Security Rule

1. **Declare the rule** in the appropriate `source/rules/*_rules.yaml` file (e.g., `url_rules.yaml`, `payment_rules.yaml`, `context_rules.yaml`) with:
   - `id` (e.g., `URL-022`),
   - `title`, `category`, `layer`, `family`, `severity` (`info` | `weak` | `meaningful` | `strong`),
   - `applicability`, `rationale`, and `remediation`.
2. **Implement the detector** in the corresponding analyzer under `source/qrshield_core/analyzers/` (`url.py`, `wifi.py`, `payment.py`, `contact.py`, `messaging.py`, `deeplink.py`, `text.py`) or `source/qrshield_core/context/consistency.py` using `deps.reg.make(...)`.
3. **Add unit tests** in `source/tests/unit/` covering both positive triggers and benign near-miss (false-positive trap) inputs.
4. **Regenerate the specification traceability matrix**:
   ```bash
   python3 tools/generate_spec_trace.py
   ```
   Every rule in `source/rules/*_rules.yaml` must have `>= 1` code site and `>= 1` test reference (`0` orphan rules).

---

## 4. Pre-Submission Verification Checklist

Before submitting a pull request, run the complete verification gate from the repository root:

```bash
make verify
```

`make verify` must exit `0` and confirm:
- [x] `tools/verify_clean_tree.py`: Zero `__pycache__` directories, `.pyc` files, or leftover runtime scratch directories.
- [x] `tools/run_coverage.py`: All `pytest` tests pass, line coverage `>= 90.0%`, and subsystem branch coverage `>= 80.0%`.
- [x] `tools/run_mutation.py`: AST mutation kill score `>= 70.0%` on `decision/policy.py` and `matching/entity.py`.
- [x] `tools/check_label_provenance.py`: Benchmark provenance integrity passes.
- [x] `tools/generate_spec_trace.py`: `100%` rule-to-code-to-test traceability (`0` orphans).
- [x] `tools/run_static_security.py`: `0` critical or high static security / container hardening findings.
- [x] `tools/independent_validation.py`: Independent statistical recomputation, 208-case red-team gate, decoder cross-check, and freeze manifest checks pass.

---

## 5. Pull Request Process

1. Create a descriptive feature or bugfix branch (`git checkout -b fix/short-description` or `feat/short-description`).
2. Keep commits atomic and descriptive.
3. Update relevant documentation under `docs/` if behavior, CLI flags, API routes, or configuration options change.
4. Fill out the pull request template (`.github/pull_request_template.md`) and include the output of `make verify`.
