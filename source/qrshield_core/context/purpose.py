"""Purpose and context-type inference from free text, using the reference lexicon."""
from __future__ import annotations

import re
from typing import Any

from ..rules import ReferenceData


def infer_purpose(text: str, ref: ReferenceData) -> tuple[dict[str, Any] | None, str | None]:
    """Return (purpose entry, matched keyword). The longest matching keyword wins (ties: file order)."""
    low = (text or "").lower()
    best: tuple[int, dict[str, Any], str] | None = None
    for p in ref.purposes:
        for kw in p["keywords"]:
            if re.search(rf"(?<![a-z]){re.escape(kw.lower())}(?![a-z])", low):
                if best is None or len(kw) > best[0]:
                    best = (len(kw), p, kw)
    return (best[1], best[2]) if best else (None, None)


def infer_context_type(text: str, ref: ReferenceData) -> tuple[str | None, str | None]:
    low = (text or "").lower()
    for ctype, kws in ref.context_types.items():
        for kw in kws:
            if re.search(rf"(?<![a-z]){re.escape(kw)}(?![a-z])", low):
                return ctype, kw
    return None, None
