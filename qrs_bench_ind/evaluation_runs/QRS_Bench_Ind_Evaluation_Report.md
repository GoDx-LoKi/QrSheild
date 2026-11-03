# QRS-Bench-Ind — Independent Benchmark Evaluation Report

- **Engine Version**: `QRShield 1.0.0` (frozen in `qrs_bench_ind/evaluation_runs/engine_freeze_manifest.json` prior to `test_locked` evaluation)
- **Dataset Size**: `1,080` evaluation units (`1,280` rendered PNG images across `dev`, `val`, and `test_locked`; `776` units / `928` images in `test_locked`)
- **Label Provenance**: `author_assigned` (`consensus_ground_truth.jsonl`; human inter-rater statistics are not reported)
- **Unseen Locked-Test Organizations**: `40` (`N01`–`N40`, zero overlap with `D01`–`D08`, `V01`–`V12`, or `brands.yaml`)
- **Unseen Locked-Test Visual Layouts**: `20` (`T09`–`T28`, out of `28` total layouts `T01`–`T28`)
- **Multi-Script Coverage**: English Latin (`latin_en`, `n=346`), bilingual Hindi Devanagari (`bilingual_devanagari`, `n=43`), and bilingual Japanese CJK (`bilingual_cjk`, `n=43`)

## 1. Headline Evaluation Results (`test_locked`)

| Metric (`test_locked`) | `QRShield 1.0.0` on `QRS-Bench-Ind` | Cluster-Aware 95% CI (Org / Template) |
| :--- | :---: | :---: |
| **Core Scenes (`n=320`) Exact Agreement** | **`100.00%`** (`320 / 320`) | `[1.0, 1.0]` / `[1.0, 1.0]` |
| **Core Scenes (`n=320`) Accepted-Set Agreement** | **`100.00%`** (`320 / 320`) | `[1.0, 1.0]` / `[1.0, 1.0]` |
| **Combined (`n=432`) Exact Agreement** | **`100.00%`** (`432 / 432`) | `[1.0, 1.0]` / `[1.0, 1.0]` |
| **Combined (`n=432`) Accepted-Set Agreement** | **`100.00%`** (`432 / 432`) | `[1.0, 1.0]` / `[1.0, 1.0]` |
| **Clean Benign (`SG1`, `n=112`) Any-Escalation FPR** | **`0.00%`** (`0 / 112`) | Specificity `100.00%` (Severe FPR `0.00%`) |
| **Challenge FP Traps (`n=56`) Over-Escalation** | **`0.00%`** (`0 / 56`) | True-Negative Resistance `100.00%` |
| **Challenge FN Traps (`n=56`) Evasion Rate** | **`0.00%`** (`0 / 56`) | Detection Recall `100.00%` |
| **Counterfactual Directional (`128` pairs)** | **`100.00%`** | `128 / 128` pairs |
| **Counterfactual Paraphrase (`24` pairs)** | **`100.00%`** | `24 / 24` pairs |
| **Non-Trivial Robustness (`R01`–`R11`, `176` imgs)** | **`99.43%`** (`175 / 176`) | All-12 (`R00`–`R11`): `99.48%` (`191 / 192`) |
