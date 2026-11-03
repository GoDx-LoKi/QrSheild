# QRS-Bench-Ind Blind Human Annotation Protocol & Rubric (`annotations_kit/ANNOTATION_PROTOCOL_RUBRIC.md`)

## 1. Purpose & Ground-Truth Provenance Policy
Per QRShield Release Requirement `AC-5` (`F-01`), benchmark annotations must carry an explicit machine-checked `provenance` field:
- `"provenance": "author_assigned"`: Assigned deterministically by the benchmark scenario specification at generation time. When provenance is `"author_assigned"`, no inter-rater $\kappa$ or human consensus claim may be reported.
- `"provenance": "human"`: Assigned by two independent human security analysts using the blind task worksheets (`annotations_kit/blind_tasks_v1_0.csv`, `1,280` image tasks covering all `880` single-image units and both Image `A` and Image `B` of all `200` counterfactual pairs) and ingested via `tools/ingest_annotations.py`.

## 2. Blinding Rules for Human Annotators
1. Annotators receive only:
   - The rendered composite scene image (`splits/<split>/.../*.png`).
   - The decoded raw QR payload string (displayed in a sandboxed text viewer without executing or resolving any link).
   - The offline threat-intelligence fixture lookup (`metadata/threat_intel_snapshot.json`) if evaluating the Threat-Intel stratum.
2. Annotators **never** see:
   - QRShield's output verdict, indicator IDs (`URL-*`, `CTX-*`, `PAY-*`, etc.), or rule trace (`R0`–`R10`).
   - The generator's `subtype` (`SG1`–`SG5`, `fp_trap`, `fn_trap`) or `author_assigned` label.
   - Each other's worksheets prior to submission.
3. For counterfactual pairs (`stratum == "counterfactual_pairs"`):
   - Each pair is exported as **two distinct task rows** (`<unit_id>__A` with `pair_side="A"` and `<unit_id>__B` with `pair_side="B"`).
   - Each human rater independently assigns an ordinal risk level (`assigned_level_L0_to_L3`) to **both** Image `A` and Image `B`, and records (or allows the ingestion tool to derive and cross-check) the directional relation (`directional_relation_vs_A` $\in$ `{"Risk(B) > Risk(A)", "Risk(B) == Risk(A)", "Risk(B) < Risk(A)"}`).

## 3. Four-Level Risk Rubric (`L0`–`L3`)
| Level String | Code | Operational Criterion |
|---|---|---|
| `no_material_concern` | `L0` | The QR payload's scheme, destination domain/handle, action, and parameters are consistent with the visible surrounding visual context, and no deceptive payload or context signal is present. |
| `needs_verification` | `L1` | The scene contains an ambiguity, opaque intermediary (URL shortener, dynamic QR redirector), third-party processor/affiliate relationship, unencrypted/open Wi-Fi disclosure, or unreadable/occluded context that warrants out-of-band user verification before proceeding, without overt deception. |
| `high_concern` | `L2` | The scene exhibits clear local evidence of deception or harmful intent: brand/domain impersonation (lookalike domain, unrelated domain under a trusted brand header), payee VPA substitution, purpose mismatch (e.g., "Scan for Menu" encoding a UPI payment or device-linking URI), credential/OTP/PIN harvesting request, or high-risk deep-link/payment parameter tampering. |
| `harmful_corroborated` | `L3` | The scene exhibits high-concern (`L2`) deception **and** the payload's host/domain is independently corroborated by the offline threat-intelligence snapshot (`malicious >= 2` or `malicious >= 1, suspicious >= 2`). |

## 4. Ingestion & Direct Evaluator Consumption Workflow
```bash
# 1. Export all 1,280 blind image tasks (including separate A and B rows for counterfactual pairs):
python3 tools/ingest_annotations.py --export-blind-tasks \
  qrs_bench_ind/annotations/consensus_ground_truth.jsonl \
  annotations_kit/blind_tasks_v1_0.csv

# 2. After human raters complete rater1.csv and rater2.csv (and optional adjudicator.csv),
#    ingest into a full-schema benchmark ground-truth JSONL:
python3 tools/ingest_annotations.py --ingest \
  --base-gt qrs_bench_ind/annotations/consensus_ground_truth.jsonl \
  --rater1 rater1.csv --rater2 rater2.csv --adjudicator adjudicator.csv \
  --out qrs_bench_ind/annotations/human_consensus_ground_truth.jsonl \
  --report release/evidence/human_irr_report.json

# 3. Directly evaluate QRShield against the ingested human-consensus ground-truth file:
python3 build_and_evaluate_qrs_bench_ind.py \
  --gt-jsonl qrs_bench_ind/annotations/human_consensus_ground_truth.jsonl

# 4. Run provenance gate:
python3 tools/check_label_provenance.py
```
