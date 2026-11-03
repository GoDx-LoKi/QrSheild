# Dataset Datasheet — `QRS-Bench-Ind` (`docs/DATASET_DATASHEET.md`)

Following Gebru et al. (*"Datasheets for Datasets"*), this document describes the motivation, composition, generation process, split hygiene, and label provenance of **`QRS-Bench-Ind`** ([`qrs_bench_ind/`](../qrs_bench_ind/)).

---

## 1. Motivation

- **Purpose**: Evaluate context-aware QR code security analyzers across 8 payload families (`url`, `wifi`, `payment`, `contact`, `sms`, `email`, `deep_link`, `plain_text`), adversarial false-positive/false-negative challenge traps, paired counterfactual signage perturbations, and physical/optical image degradations.
- **Zero-Leakage Generalization Goal**: Ensure that the held-out `test_locked` split tests genuine cross-modal context verification on unseen organizations (`N01`–`N40`) and unseen signage layouts (`T09`–`T28`) rather than memorization of a static brand allowlist.

---

## 2. Composition & Split Architecture

`QRS-Bench-Ind` comprises **`1,080` evaluation units** and **`1,280` rendered PNG images** (`900x1180` resolution, verified in [`qrs_bench_ind/MANIFEST_SHA256.txt`](../qrs_bench_ind/MANIFEST_SHA256.txt)):

| Split | Total Units | Total PNG Images | Organizations (`60` Disjoint) | Visual Templates (`28` Disjoint) | Core Scenes (`SG1`–`SG5`) | Challenge Traps (`FP` + `FN`) | Counterfactual Pairs (`CF1`–`CF6`) | Robustness Variants (`R00`–`R11`) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`dev`** | `148` | `172` | `8` (`D01`–`D08`) | `4` (`T01`–`T04`) | `80` | `20` (`10` FP + `10` FN) | `24` pairs (`48` imgs) | `24` (`2` seeds $\times 12$) |
| **`val`** | `156` | `180` | `12` (`V01`–`V12`) | `4` (`T05`–`T08`) | `80` | `28` (`14` FP + `14` FN) | `24` pairs (`48` imgs) | `24` (`2` seeds $\times 12$) |
| **`test_locked`** | `776` | `928` | `40` (`N01`–`N40`) | `20` (`T09`–`T28`) | `320` | `112` (`56` FP + `56` FN) | `152` pairs (`304` imgs) | `192` (`16` seeds $\times 12$) |
| **Total** | **`1,080`** | **`1,280`** | **`60` orgs** | **`28` layouts** | **`480`** | **`160`** (`80` FP + `80` FN) | **`200` pairs (`400` imgs)** | **`240` (`20` seeds $\times 12`)** |

### Strata Definitions
1. **Core Scenes (`480` units: `80` `dev`, `80` `val`, `320` `test_locked`)**: Balanced across all 8 payload families and 5 scenario groups:
   - `SG1_clean_benign`: Consistent signage and benign payload (`L0`).
   - `SG2_ambiguous_benign`: Legitimate third-party processor, URL shortener, or missing secondary context (`L1`).
   - `SG3_context_tamper_mismatch`: Benign-looking payload pasted onto mismatched organizational/amount/SSID signage (`L2`).
   - `SG4_intrinsic_payload_attack`: Phishing/credential lure, homoglyph, userinfo trick, USSD command, or token-stuffed VPA (`L2`).
   - `SG5_corroborated_campaign`: Intrinsic attack corroborated by strong context mismatch and/or Threat Intelligence (`L3`).
2. **Challenge Traps (`160` units: `80` FP traps + `80` FN traps)**:
   - **False-Positive (`FP`) Traps**: Legitimate parent/DBA footer disclosures, acronym domains, open cafe/library guest Wi-Fi, benign administrative password requests (*"send guest Wi-Fi password for room 4"*), and security education notices (*"Never share your OTP"*).
   - **False-Negative (`FN`) Traps**: `#redirect=` client-side fragment redirects, paraphrased 6-digit credential solicitation, token-stuffed VPA handles (`merchant.refund@okaxis`), and custom deep-link wallet custody grants.
3. **Counterfactual Pairs (`200` pairs / `400` images)**:
   - `160` directional pairs (`CF1`–`CF5`: organization swap, amount tamper, transport/redirect downgrade, VPA/SSID tamper, deep-link parameter injection) where `Risk(B) > Risk(A)`.
   - `40` paraphrase negative-control pairs (`CF6`) where visual layout and wording are paraphrased without changing security semantics (`Risk(B) == Risk(A)`).
4. **Factorial Robustness Suite (`240` images: `20` seeds $\times 12$ conditions `R00`–`R11`)**:
   - `R00_clean`, `R01_perspective_15deg`, `R02_perspective_25deg`, `R03_gaussian_blur`, `R04_uneven_shadow_glare`, `R05_low_contrast_fade`, `R06_jpeg_recompression_q25`, `R07_downscale_upscale`, `R08_sensor_noise`, `R09_partial_border_crop`, `R10_rot_plus_jpeg`, `R11_curved_surface_glare_blur`.

### Multi-Script Coverage
In `test_locked` (`n=432` single-image units), signage is rendered across three script regimes:
- `latin_en` (`n=346`),
- `bilingual_devanagari` (Hindi Devanagari + English, `n=43`), and
- `bilingual_cjk` (Japanese CJK + English, `n=43`).

---

## 3. Label Provenance & Human Annotation Workflow (`AC-5`, `DEF-011`)

- **Current Provenance**: Every record in [`qrs_bench_ind/annotations/consensus_ground_truth.jsonl`](../qrs_bench_ind/annotations/consensus_ground_truth.jsonl) carries `"provenance": "author_assigned"`, assigned deterministically from scenario construction templates in [`build_and_evaluate_qrs_bench_ind.py`](../build_and_evaluate_qrs_bench_ind.py).
- **Blind Human Annotation Workflow**:
  - [`qrs_bench_ind/metadata/ANNOTATION_PROTOCOL.md`](../qrs_bench_ind/metadata/ANNOTATION_PROTOCOL.md) defines the blind dual-rater rubric.
  - `python3 tools/ingest_annotations.py --export-blind-csv <path>` exports all `1,280` image rating tasks (including separate `A` and `B` tasks for all `200` counterfactual pairs) without ground-truth labels.
  - `python3 tools/ingest_annotations.py --rater1 ... --rater2 ... --adjudicator ...` validates directional counterfactual relations, computes unweighted and quadratic-weighted Cohen's $\kappa_w$, and outputs a complete, evaluator-compatible JSONL file (`--gt-jsonl` in `build_and_evaluate_qrs_bench_ind.py`).

---

## 4. Licensing & Ethical Considerations

- All `60` organizations (`D01`–`D08`, `V01`–`V12`, `N01`–`N40`), domains, VPAs, phone numbers, and street addresses in `QRS-Bench-Ind` are synthetic research entities created for defensive security evaluation.
- Released under the **MIT License** ([`LICENSE`](../LICENSE)).
