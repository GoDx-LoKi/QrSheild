# Developer Guide (`docs/DEVELOPMENT.md`)

This guide covers the developer workflow for testing, coverage measurement, AST mutation testing, fuzzing, static security scanning, authoring declarative security rules, and maintaining engine freeze manifests in **QRShield `1.0.0`**.

---

## 1. Repository Layout for Developers

- **`source/qrshield_core/`**: Core 7-stage analysis engine. Must remain pure domain logic with zero web or CLI dependencies.
- **`source/rules/`**:
  - `*_rules.yaml`: 12 declarative rule files defining `87` unique rule IDs.
  - `reference/`: Production reference data (`brands.yaml`, `lexicon.yaml`, `lists.yaml`, `purposes.yaml`, `schemes.yaml`).
  - `test_fixtures/`: Synthetic `.example` / `.test` brands (`brands_synthetic.yaml`) used only by unit tests when `load_synthetic_reference=True`.
- **`source/app/`**: FastAPI web application, Jinja2 templates, HTMX partials, and `/api/v1` JSON routes.
- **`source/evaluation/`**: Benchmark loader (`dataset_loader.py`), validator (`validator.py`), scorer (`scoring.py`), layer ablation study (`ablation.py`), OOD holdout suite (`holdout.py`), and CLI (`__main__.py`).
- **`source/tests/`**:
  - `unit/`: Fast unit tests for normalizers, analyzers, entity/domain matching, OCR/redaction, context consistency, decision policy, threat intel, and claim verification.
  - `integration/`: Full pipeline (`test_pipeline.py`) and FastAPI web/API (`test_web.py`) integration tests.
  - `security/`: Non-execution invariant (`test_offline_non_execution.py`), parser/web security (`test_security.py`), and hardening regressions (`test_hardening_regressions.py`).
  - `evaluation/`: Benchmark integrity, robustness linkage, human annotation ingestion, and `QRS-Bench-Ind` regression tests (`test_remediation_regressions.py`, `test_research_*.py`).
- **`tools/`**: Standalone verification, coverage, mutation, fuzzing, statistical recomputation, and annotation ingestion scripts.

---

## 2. Running Tests & Quality Gates

### 2.1 Fast Unit & Integration Test Suite (`pytest`)
```bash
PYTHONPATH=source python3 -m pytest source/tests -q
```
All `446` tests execute in ~25 seconds on CPU.

### 2.2 Line & AST-Branch Coverage Gate (`tools/run_coverage.py`)
Traces execution across `source/qrshield_core/` over all `446` tests and enforces `>= 90.0%` line coverage and `>= 80.0%` branch coverage on `analyzers/`, `context/`, and `decision/`:
```bash
python3 tools/run_coverage.py
```
Outputs `release/evidence/coverage_summary.json` (`93.19%` line coverage, `80.65%` branch coverage).

### 2.3 Custom AST Mutation Testing Gate (`tools/run_mutation.py`)
Generates `50` deterministic single-point AST mutants (`Compare` and `BoolOp` operators) across `source/qrshield_core/decision/policy.py` and `source/qrshield_core/matching/entity.py` and enforces a mutation kill score `>= 70.0%`:
```bash
python3 tools/run_mutation.py
```
Outputs `release/evidence/mutation_summary.json` (`90.00%` mutation score, `45 / 50` mutants killed).

### 2.4 Structure-Aware Fuzzer (`tools/run_fuzzer.py`)
Executes `100,000` deterministic fuzzed inputs (`75,000` normalizer/analyzer inputs, `20,000` OCR candidate extraction inputs, and `5,000` malformed/truncated image byte streams) and verifies `0` unhandled exceptions:
```bash
python3 tools/run_fuzzer.py
```
Outputs `release/evidence/fuzz_summary.json`.

### 2.5 Static Security & Container Hardening Gate (`tools/run_static_security.py`)
Scans `source/qrshield_core/` and `source/app/` via Python's `ast` module for forbidden calls (`eval`, `exec`, `os.system`, `os.popen`, `subprocess.*`, `pickle.load`, unsafe `yaml.load`) and audits `Dockerfile` and `docker-compose.yml` hardening:
```bash
python3 tools/run_static_security.py
```
Outputs `release/evidence/static_security_summary.json` (`0` critical/high findings).

### 2.6 Independent Zero-Shared-Code Validation (`tools/independent_validation.py`)
Runs with **zero Python imports** from `qrshield_core`, `evaluation`, or `app`:
1. Verifies `< 1e-6` agreement between `release/evidence/metrics_master.json` and independent `scipy.stats` + NumPy recomputations.
2. Evaluates `release/evidence/redteam_208_scenarios.jsonl` via black-box CLI subprocess (`python3 -m evaluation --batch-jsonl`) and enforces `>= 95%` attack recall, `>= 95%` benign specificity, and `>= 90%` per-category rates (`release/evidence/redteam_208_report.json`).
3. Cross-checks QRShield's own multi-pass decoder (`python3 -m evaluation --decode-images-dir`) against raw single-pass OpenCV, standalone multi-pass OpenCV, and ground truth across all `192` `test_locked` robustness images (`release/evidence/decoder_crosscheck.json`).
4. Verifies all `66` frozen engine SHA-256 hashes in `qrs_bench_ind/evaluation_runs/engine_freeze_manifest.json` (`release/evidence/cleanroom_repro_report.json`).
```bash
python3 tools/independent_validation.py
```

### 2.7 Full One-Command Verification Gate (`make verify`)
```bash
make verify
```

---

## 3. Freeze Manifest & Benchmark Hygiene Protocol

`qrs_bench_ind/evaluation_runs/engine_freeze_manifest.json` stores the SHA-256 digests of all `66` files in `source/qrshield_core/**/*.py` (`48` files) and `source/rules/**/*.yaml` (`18` files).

- During documentation, packaging, or tooling maintenance, **never modify files inside `source/qrshield_core/` or `source/rules/`** so the frozen engine binary/source state remains bit-for-bit identical to the evaluated `1.0.0` release.
- If you are developing a new engine version (e.g., `1.1.0`):
  1. Tune rules and thresholds strictly on `qrs_bench_ind/splits/dev/` and `qrs_bench_ind/splits/val/`.
  2. Document every rule/lexicon change in `docs/TUNING_DISCLOSURE.md`.
  3. Regenerate the traceability matrix via `python3 tools/generate_spec_trace.py`.
  4. Re-run `python3 build_and_evaluate_qrs_bench_ind.py --evaluate-only` and `python3 tools/compute_rigorous_stats.py` to record a new freeze manifest and evaluation report.
