"""QRShield research evaluation engine.

Orchestrates the SAME QRShieldEngine used by the web application against an external
image-based research dataset (qrs_bench_ind/ placed beside the project).
No security logic is duplicated here — this package handles loading, orchestration,
scoring, persistence, and reporting only.
"""
from .dataset_loader import (
    PAYLOAD_TYPES,
    ResearchDataset,
    ResearchItem,
    discover_dataset_root,
    load_research_dataset,
)
from .failures import FailureCode, failure_record, is_evaluable
from .image_runner import RESEARCH_CONFIG, ItemResult, preflight_ocr, run_image
from .run_manager import (
    RunProgress,
    append_result,
    build_run_manifest,
    load_completed_ids,
    load_results_jsonl,
    make_run_id,
)
from .scoring import score_base, score_counterfactual, score_robustness
from .validator import ValidationResult, validate_dataset, validate_dataset_root

__all__ = [
    "PAYLOAD_TYPES",
    "discover_dataset_root",
    "load_research_dataset",
    "ResearchDataset",
    "ResearchItem",
    "FailureCode",
    "failure_record",
    "is_evaluable",
    "RESEARCH_CONFIG",
    "ItemResult",
    "preflight_ocr",
    "run_image",
    "RunProgress",
    "append_result",
    "build_run_manifest",
    "load_completed_ids",
    "load_results_jsonl",
    "make_run_id",
    "score_base",
    "score_counterfactual",
    "score_robustness",
    "ValidationResult",
    "validate_dataset",
    "validate_dataset_root",
]
