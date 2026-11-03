# Reproducibility Guide (`docs/REPRODUCIBILITY.md`)

This document provides the exact commands, deterministic random seeds, environment pins, and verification scripts required to reproduce every benchmark figure, statistical test, and quality gate in **QRShield `1.0.0`** (`AC-1`–`AC-12`).

---

## 1. Reference Environment

- **Operating System**: Linux (`x86_64`, Debian/Ubuntu)
- **Python**: `3.11.14` (all wheels and SHA-256 hashes pinned in [`requirements.lock`](../requirements.lock))
- **Local OCR**: `tesseract 5.5.0` (`eng`, `osd`)
- **OpenCV**: `opencv-python-headless==4.11.0`
- **Deterministic Random Seeds**:
  - Benchmark generation (`build_and_evaluate_qrs_bench_ind.py`): `SEED = 20260417`
  - Cluster bootstrap 95% confidence intervals (`tools/compute_rigorous_stats.py`, `B = 2000` replicates): `seed = 20260419`
  - Structure-aware 100,000-input fuzzer (`tools/run_fuzzer.py`): `seed = 20261101`

---

## 2. One-Command Verification Gate (`make verify`)

From a clean checkout of the repository root, run:
```bash
make verify
```

`make verify` runs the following seven deterministic gates sequentially and exits `0` only if every check passes:

| Step | Command Executed | Evidence File Produced / Checked | Verified Metric / Outcome |
| :---: | :--- | :--- | :--- |
| **1** | `python3 tools/verify_clean_tree.py --clean` | Console JSON output | `0` `__pycache__` dirs, `0` `.pyc` files, `0` retired/scratch dirs, all root files present. |
| **2** | `python3 tools/run_coverage.py` | `release/evidence/coverage_summary.json` | **`446 passed, 0 failed`**; **`93.19%`** line coverage (`>= 90%`), **`80.65%`** branch coverage (`>= 80%`). |
| **3** | `python3 tools/run_mutation.py` | `release/evidence/mutation_summary.json` | **`90.00%`** AST mutation kill score (`45 / 50` mutants killed, `>= 70%`). |
| **4** | `python3 tools/check_label_provenance.py` | `release/evidence/provenance_audit.json` | All `1,080` records carry `"provenance": "author_assigned"`; zero fabricated rater claims. |
| **5** | `python3 tools/generate_spec_trace.py` | `docs/SPEC_TRACE.md` | `87 / 87` YAML rules and `17 / 17` decision policy rules traced (`0` orphans). |
| **6** | `python3 tools/run_static_security.py` | `release/evidence/static_security_summary.json` | `0` critical or high AST / Docker security findings across `60` source files. |
| **7** | `python3 tools/independent_validation.py` | `release/evidence/independent_stats_report.json`<br>`release/evidence/redteam_208_report.json`<br>`release/evidence/decoder_crosscheck.json`<br>`release/evidence/cleanroom_repro_report.json` | `< 1e-6` `scipy.stats` agreement; `208 / 208` red-team pass (`100%` recall & specificity); `99.48%` (`191 / 192`) QRShield multi-pass decode rate vs `69.27%` (`133 / 192`) raw OpenCV; `66 / 66` frozen engine SHA-256 hashes verified. |

---

## 3. Rebuilding & Re-Evaluating `QRS-Bench-Ind` From Scratch

To re-evaluate the frozen `1.0.0` engine on `qrs_bench_ind/` (or rebuild all `1,280` PNG images from scratch):

```bash
# Re-evaluate existing 1,280 PNG images against frozen QRShield 1.0.0 (~90 seconds on CPU)
python3 build_and_evaluate_qrs_bench_ind.py --evaluate-only

# Recompute cluster-aware bootstrap CIs, McNemar-Holm p-values, and PPV tables
python3 tools/compute_rigorous_stats.py

# Verify every numerical claim in the paper and reports against metrics_master.json
python3 tools/verify_claims.py
```

To regenerate all `1,280` PNG images and re-evaluate from scratch:
```bash
python3 build_and_evaluate_qrs_bench_ind.py
```

---

## 4. Verifying Artifact Checksums

Verify the SHA-256 checksums of key benchmark and evidence files:
```bash
sha256sum -c release/SHA256SUMS.txt
```
And verify all `1,280` rendered benchmark PNG images:
```bash
(cd qrs_bench_ind && sha256sum -c MANIFEST_SHA256.txt)
```
