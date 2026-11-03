# `QRS-Bench-Ind` — Multi-Scheme Contextual QR Security Benchmark

`QRS-Bench-Ind` is the canonical benchmark dataset for evaluating **QRShield `1.0.0`** across 8 QR payload families (`url`, `wifi`, `payment`, `contact`, `sms`, `email`, `deep_link`, `plain_text`).

## 1. Dataset Summary

- **Total Evaluation Units**: `1,080` (`annotations/consensus_ground_truth.jsonl`)
- **Total Rendered PNG Images**: `1,280` (`900x1180` PNGs, SHA-256 checksums in `MANIFEST_SHA256.txt`)
- **Disjoint Organizations**: `60` (`8` in `dev` `D01`–`D08`, `12` in `val` `V01`–`V12`, `40` unseen in `test_locked` `N01`–`N40`)
- **Disjoint Signage Layouts**: `28` (`4` in `dev` `T01`–`T04`, `4` in `val` `T05`–`T08`, `20` unseen in `test_locked` `T09`–`T28`)
- **Label Provenance**: `"author_assigned"` (blind dual-rater protocol and full-schema ingestion pipeline provided in `metadata/ANNOTATION_PROTOCOL.md` and `../tools/ingest_annotations.py`)

## 2. Directory Structure

- `MANIFEST_SHA256.txt`: SHA-256 digests for all `1,280` PNG images.
- `annotations/consensus_ground_truth.jsonl`: Full ground-truth records for all `1,080` evaluation units.
- `metadata/organizations_splits.yaml`: Disjoint organization profiles across `dev`, `val`, and `test_locked`.
- `metadata/taxonomy_and_codebook.yaml`: Stratum, template, script, and label taxonomy definitions.
- `metadata/ANNOTATION_PROTOCOL.md`: Blind dual-rater human annotation protocol and ingestion instructions.
- `metadata/threat_intel_snapshot.json`: Frozen offline Threat Intelligence lookup table for `SG5` corroborated campaign evaluation.
- `splits/{dev,val,test_locked}/`: Rendered PNG images organized by split and stratum (`core_scenes/`, `challenge_traps/`, `counterfactual_pairs/`, `robustness_variants/`).
- `evaluation_runs/`:
  - `engine_freeze_manifest.json`: SHA-256 hashes of all `66` frozen engine and rule files.
  - `per_unit_predictions.jsonl`: Per-unit predictions across all `1,080` units.
  - `benchmark_metrics_report.json`: Full stratified metrics, ablations, baselines, and timing distributions.
  - `QRS_Bench_Ind_Evaluation_Report.md`: Executive markdown report of locked-test results.
