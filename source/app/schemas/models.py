"""Request schemas for the JSON API (inputs are validated and length-limited; they are still treated as untrusted)."""
from __future__ import annotations

import re
import pydantic
from pydantic import BaseModel, Field

_PYDANTIC_V2 = hasattr(BaseModel, "model_dump")
_ABLATION_RE = "^(payload_only|context_only|payload_context|payload_context_action|full)$"


class ContextIn(BaseModel):
    organization: str = Field("", max_length=200)
    context_type: str = Field("", max_length=60)
    purpose: str = Field("", max_length=300)
    amount: str = Field("", max_length=40)
    additional: str = Field("", max_length=1000)

    if not _PYDANTIC_V2:
        def model_dump(self) -> dict:
            return self.dict()


class AnalyzePayloadRequest(BaseModel):
    payload: str = Field(..., max_length=4000, description="Decoded QR payload (treated as data, never executed)")
    context: ContextIn = ContextIn()
    ablation: str = Field(
        "payload_context_action",
        **(dict(pattern=_ABLATION_RE) if _PYDANTIC_V2 else dict(regex=_ABLATION_RE)),
    )
    threat_intel: bool = Field(False, description="Opt in to an external report lookup (sends the URL to the provider)")
