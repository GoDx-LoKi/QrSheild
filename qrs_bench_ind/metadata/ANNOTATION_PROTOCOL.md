# Blind Dual-Rater Human Annotation Protocol (`qrs_bench_ind/metadata/ANNOTATION_PROTOCOL.md`)

This document specifies the protocol for conducting an external blind dual-rater human annotation study on **`QRS-Bench-Ind`** (`1,080` units / `1,280` images) using [`tools/ingest_annotations.py`](../../tools/ingest_annotations.py).

---

## 1. Provenance Policy (`AC-5`)

All shipped records in [`qrs_bench_ind/annotations/consensus_ground_truth.jsonl`](../annotations/consensus_ground_truth.jsonl) carry `"provenance": "author_assigned"`. Human inter-rater reliability metrics ($\kappa$, $\kappa_w$) are **only** reported when independent human raters complete the blind rating CSVs and their labels are ingested via `tools/ingest_annotations.py`.

---

## 2. Step-by-Step Blind Annotation Workflow

### Step 1: Export Blind Rating Tasks (`1,280` Image Rows)
Run from the repository root:
```bash
python3 tools/ingest_annotations.py \
  --export-blind-csv /tmp/blind_annotation_tasks.csv
```
This exports `1,280` rows covering:
- `880` single-image units (`core_scenes`, `challenge_traps`, `robustness_variants`), and
- `400` counterfactual image rows (`200` pairs $\times$ separate `__A` and `__B` tasks so raters assign independent `L0`–`L3` labels to both Image A and Image B, plus `directional_relation_vs_A` on the `__B` row).

All ground-truth fields (`consensus_ground_truth`, `accepted_ground_truth_set`, `expected_relation`) are stripped from the exported CSV.

### Step 2: Independent Rating by Rater 1, Rater 2, and Adjudicator
- **Rater 1** and **Rater 2** independently inspect each image (`rel_path`) and decoded payload preview (`payload_preview`), filling in:
  - `assigned_level_L0_to_L3`: one of `no_material_concern`, `needs_verification`, `high_concern`, or `harmful_corroborated`.
  - `directional_relation_vs_A` (required for `pair_side == "B"` rows): one of `Risk(B) > Risk(A)`, `Risk(B) == Risk(A)`, or `Risk(B) < Risk(A)`, which must be mathematically consistent with the rater's own `assigned_level_L0_to_L3` for Image A and Image B.
- **Adjudicator** resolves any unit where Rater 1 and Rater 2 disagree on either the ordinal level or the directional counterfactual relation.

### Step 3: Ingest Human Ratings & Compute Inter-Rater Reliability
```bash
python3 tools/ingest_annotations.py \
  --rater1 /path/to/rater1.csv \
  --rater2 /path/to/rater2.csv \
  --adjudicator /path/to/adjudicator.csv \
  --base-gt qrs_bench_ind/annotations/consensus_ground_truth.jsonl \
  --out-jsonl qrs_bench_ind/annotations/human_adjudicated_ground_truth.jsonl \
  --out-irr release/evidence/human_irr_report.json
```
The ingestion script:
1. Validates that every single-image unit and both sides (`A` and `B`) of every counterfactual pair have valid `L0`–`L3` labels and consistent `directional_relation_vs_A` annotations.
2. Preserves the full benchmark unit schema (`split`, `stratum`, `category`, `org_id`, `template_id`, `subtype`, `script`, `image_id`, `rel_path`, `accepted_ground_truth_set`, etc.) required by the benchmark evaluator.
3. Stamps `"provenance": "human"` and outputs unweighted and quadratic-weighted Cohen's $\kappa_w$ across single-image units, counterfactual Image A/B ratings, and directional relation judgments.

### Step 4: Evaluate QRShield Against Human-Adjudicated Ground Truth
```bash
python3 build_and_evaluate_qrs_bench_ind.py \
  --evaluate-only \
  --gt-jsonl qrs_bench_ind/annotations/human_adjudicated_ground_truth.jsonl
```
