"""Failure taxonomy for research image processing.

Distinguishes \"system could not produce a prediction\" from \"system produced a
prediction that disagreed with ground truth\". Never collapse these two categories.
"""
from __future__ import annotations

from enum import Enum
from typing import Any


class FailureCode(str, Enum):
    SUCCESS = "SUCCESS"
    INPUT_ERROR = "INPUT_ERROR"
    IMAGE_LOAD_ERROR = "IMAGE_LOAD_ERROR"
    QR_DETECT_ERROR = "QR_DETECT_ERROR"
    QR_DECODE_ERROR = "QR_DECODE_ERROR"
    MULTIPLE_QR_AMBIGUOUS = "MULTIPLE_QR_AMBIGUOUS"
    OCR_INITIALIZATION_ERROR = "OCR_INITIALIZATION_ERROR"
    OCR_ERROR = "OCR_ERROR"
    OCR_NO_TEXT = "OCR_NO_TEXT"
    CONTEXT_EXTRACTION_PARTIAL = "CONTEXT_EXTRACTION_PARTIAL"
    PAYLOAD_PARSE_ERROR = "PAYLOAD_PARSE_ERROR"
    PAYLOAD_CLASSIFICATION_ERROR = "PAYLOAD_CLASSIFICATION_ERROR"
    SECURITY_ANALYSIS_ERROR = "SECURITY_ANALYSIS_ERROR"
    CONTEXT_ANALYSIS_ERROR = "CONTEXT_ANALYSIS_ERROR"
    DECISION_ERROR = "DECISION_ERROR"
    EVALUATION_ERROR = "EVALUATION_ERROR"
    TIMEOUT = "TIMEOUT"
    RUNTIME_ERROR = "RUNTIME_ERROR"


def is_evaluable(code: FailureCode) -> bool:
    """Return True if the item produced a usable prediction (even if wrong)."""
    return code is FailureCode.SUCCESS


def failure_record(item_id: str, suite: str, image_path: str, code: FailureCode,
                   stage: str, message: str, tb: str | None = None) -> dict[str, Any]:
    """Build a minimal result record for a failed item."""
    return {
        "item_id": item_id,
        "suite": suite,
        "image_path": image_path,
        "failure_code": code.value,
        "failure_stage": stage,
        "failure_message": message,
        "failure_traceback": tb,
        "evaluable": False,
        "prediction": None,
    }
